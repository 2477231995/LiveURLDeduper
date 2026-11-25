"""核心逻辑单测：python -m unittest discover -s tests -v"""

from __future__ import annotations

import codecs
import json
import tempfile
import threading
import unittest
from pathlib import Path

import requests

from liveurldeduper.core import (
    ProbeResult,
    ScanConfig,
    StatusMatcher,
    Target,
    build_proxies,
    candidate_urls,
    dedupe_key,
    dedupe_urls,
    iter_lines,
    iter_targets,
    load_targets,
    parse_proxy,
    parse_target,
    sniff_encoding,
    probe_target,
    read_targets,
    results_to_urls,
    scan,
    write_csv,
    write_json,
    write_urls,
)


class FakeResponse:
    def __init__(self, status_code: int, headers: dict | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeHttp:
    """按 URL 返回预设结果：int -> 状态码，Exception -> 抛出，None -> 连接失败。"""

    def __init__(self, table: dict[str, object]) -> None:
        self.table = table
        self.calls: list[str] = []
        self.closed = False

    def get(self, url: str):
        self.calls.append(url)
        value = self.table.get(url)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise requests.ConnectionError("connection refused")
        if isinstance(value, int):
            return FakeResponse(value)
        return FakeResponse(*value)

    def close(self) -> None:
        self.closed = True


class ParseTargetTests(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(parse_target("a.com"), Target("a.com", None))
        self.assertEqual(parse_target("  A.COM.  "), Target("a.com", None))

    def test_host_with_port(self):
        self.assertEqual(parse_target("a.com:8443"), Target("a.com", 8443))

    def test_full_url(self):
        self.assertEqual(
            parse_target("HTTPS://User:Pass@A.com:8443/path?q=1#frag"),
            Target("a.com", 8443),
        )
        self.assertEqual(parse_target("http://a.com/x"), Target("a.com", None))

    def test_ipv6(self):
        self.assertEqual(parse_target("[::1]:8080"), Target("::1", 8080))
        self.assertEqual(Target("::1", 8080).hostport, "[::1]:8080")

    def test_rejects_junk(self):
        for line in ("", "   ", "# comment", "*.a.com", "a.com:99999", "a.com:abc", "a b.com"):
            self.assertIsNone(parse_target(line), msg=repr(line))

    def test_fast_path_edges(self):
        # 快路径（不碰 urlsplit）必须和慢路径给出完全一样的结果
        self.assertEqual(parse_target("a.com:80/x"), Target("a.com", 80))
        self.assertEqual(parse_target("[::1]:8080"), Target("::1", 8080))
        self.assertEqual(parse_target("a.com."), Target("a.com", None))
        self.assertIsNone(parse_target("a.com:0"))
        self.assertIsNone(parse_target("::1"))  # 裸 IPv6 不带方括号，老逻辑也不认
        self.assertIsNone(parse_target("a.com:8080:90"))

    def test_load_targets_dedupes_and_counts_skips(self):
        lines = ["a.com", "A.com", "b.com:443", "", "# note", "*.c.com", "a.com"]
        targets, skipped = load_targets(lines)
        self.assertEqual([t.host for t in targets], ["a.com", "b.com"])
        self.assertEqual(skipped, 1)

    def test_default_port_treated_as_absent(self):
        targets, _ = load_targets(["a.com", "a.com:443", "a.com:80", "a.com:8443"])
        self.assertEqual([t.hostport for t in targets], ["a.com", "a.com:8443"])

    def test_candidate_order(self):
        self.assertEqual(
            candidate_urls(Target("a.com")), ["https://a.com", "http://a.com"]
        )
        self.assertEqual(
            candidate_urls(Target("a.com", 80)), ["http://a.com:80", "https://a.com:80"]
        )
        self.assertEqual(
            candidate_urls(Target("a.com", 8443)),
            ["https://a.com:8443", "http://a.com:8443"],
        )


class StreamingTests(unittest.TestCase):
    def test_iter_targets_counter(self):
        lines = ["a.com", "A.com", "b.com:443", "", "# note", "*.c.com", "a.com"]
        counter: dict = {}
        targets = list(iter_targets(lines, counter))
        self.assertEqual([t.host for t in targets], ["a.com", "b.com"])
        self.assertEqual(counter["lines"], 7)
        self.assertEqual(counter["skipped"], 1)
        self.assertEqual(counter["duplicates"], 2)

    def test_read_targets_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "subs.txt"
            path.write_text(
                "\n".join(["a.com", "b.com:8443", "", "# x", "*.y.com", "a.com", ""]),
                encoding="utf-8",
            )
            counter: dict = {}
            targets = list(read_targets(path, counter))
            self.assertEqual([t.hostport for t in targets], ["a.com", "b.com:8443"])
            self.assertEqual(counter["skipped"], 1)
            self.assertEqual(counter["duplicates"], 1)
            # iter_lines 逐行产出，不会一次性把文件读成一个 list
            self.assertEqual(sum(1 for _ in iter_lines(path)), 6)

    def test_read_targets_utf16_with_bom(self):
        # 记事本存成“Unicode”就是这种：UTF-16 LE + BOM，以前整份文件被当成脏行
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "u16.txt"
            path.write_bytes("a.com\nb.com:8443\n".encode("utf-16"))
            counter: dict = {}
            targets = list(read_targets(path, counter))
            self.assertEqual([t.hostport for t in targets], ["a.com", "b.com:8443"])
            self.assertEqual(counter["encoding"], "utf-16")

    def test_read_targets_utf16_without_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "u16le.txt"
            path.write_bytes("a.com\nb.com\n".encode("utf-16-le"))
            counter: dict = {}
            targets = list(read_targets(path, counter))
            self.assertEqual([t.host for t in targets], ["a.com", "b.com"])
            self.assertEqual(counter["encoding"], "utf-16-le")

    def test_read_targets_utf8_bom_keeps_first_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.txt"
            path.write_bytes(codecs.BOM_UTF8 + b"a.com\nb.com\n")
            targets = list(read_targets(path))
            self.assertEqual([t.host for t in targets], ["a.com", "b.com"])

    def test_read_targets_gbk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gbk.txt"
            path.write_bytes("# 注释行\nA.COM\n".encode("gbk"))
            counter: dict = {}
            targets = list(read_targets(path, counter))
            self.assertEqual([t.host for t in targets], ["a.com"])
            self.assertEqual(counter["encoding"], "gb18030")

    def test_sniff_encoding_plain_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "utf8.txt"
            path.write_text("a.com\n", encoding="utf-8")
            self.assertEqual(sniff_encoding(path), "utf-8")

    def test_load_targets_matches_streaming(self):
        lines = ["a.com", "b.com:8443", "bad line", "a.com", "*.z.com"]
        targets, skipped = load_targets(lines)
        self.assertEqual([t.hostport for t in targets], ["a.com", "b.com:8443"])
        self.assertEqual(skipped, 2)  # "bad line" 和 "*.z.com" 都算脏行


class StatusMatcherTests(unittest.TestCase):
    def test_any(self):
        matcher = StatusMatcher("any")
        for code in (200, 301, 403, 500):
            self.assertTrue(matcher(code))
        self.assertFalse(matcher(None))

    def test_ranges(self):
        self.assertTrue(StatusMatcher("2xx")(204))
        self.assertFalse(StatusMatcher("2xx")(301))
        self.assertTrue(StatusMatcher("200-399")(302))
        self.assertTrue(StatusMatcher("200,301,403")(403))
        self.assertFalse(StatusMatcher("200,301")(403))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            StatusMatcher("abc")


class DedupeTests(unittest.TestCase):
    def test_prefer_https(self):
        self.assertEqual(
            dedupe_urls(["http://a.com", "https://a.com", "http://b.com"]),
            ["https://a.com", "http://b.com"],
        )

    def test_https_order_independent(self):
        self.assertEqual(dedupe_urls(["https://a.com", "http://a.com"]), ["https://a.com"])

    def test_explicit_default_port_merged(self):
        self.assertEqual(dedupe_urls(["https://a.com:443", "https://a.com"]), ["https://a.com"])
        self.assertEqual(dedupe_urls(["http://a.com:80"]), ["http://a.com"])

    def test_non_default_ports_kept(self):
        urls = ["https://a.com:8443", "https://a.com"]
        self.assertEqual(dedupe_urls(urls), ["https://a.com", "https://a.com:8443"])

    def test_case_insensitive(self):
        self.assertEqual(dedupe_urls(["https://A.COM", "https://a.com"]), ["https://a.com"])

    def test_key(self):
        self.assertEqual(dedupe_key("https://a.com:443"), ("a.com", None))
        self.assertEqual(dedupe_key("https://a.com:8443"), ("a.com", 8443))

    def test_results_to_urls_filters_dead(self):
        results = [
            ProbeResult(Target("a.com"), url="http://a.com", status=200, alive=True),
            ProbeResult(Target("a.com"), url="https://a.com", status=200, alive=True),
            ProbeResult(Target("b.com"), url="https://b.com", status=404, alive=False),
        ]
        self.assertEqual(results_to_urls(results), ["https://a.com"])


class ProbeTests(unittest.TestCase):
    def test_https_ok(self):
        http = FakeHttp({"https://a.com": 200})
        result = probe_target(Target("a.com"), http=http)
        self.assertTrue(result.alive)
        self.assertEqual(result.url, "https://a.com")
        self.assertEqual(result.status, 200)
        self.assertEqual(http.calls, ["https://a.com"])

    def test_falls_back_to_http(self):
        http = FakeHttp({"http://a.com": 200})
        result = probe_target(Target("a.com"), http=http)
        self.assertTrue(result.alive)
        self.assertEqual(result.url, "http://a.com")
        self.assertEqual(http.calls, ["https://a.com", "http://a.com"])

    def test_403_alive_by_default(self):
        http = FakeHttp({"https://a.com": 403})
        self.assertTrue(probe_target(Target("a.com"), http=http).alive)

    def test_403_not_alive_when_only_2xx(self):
        http = FakeHttp({"https://a.com": 403, "http://a.com": 403})
        config = ScanConfig(alive=StatusMatcher("2xx"))
        result = probe_target(Target("a.com"), config, http=http)
        self.assertFalse(result.alive)
        self.assertEqual(result.status, 403)
        self.assertIn("不在判定范围", result.error or "")

    def test_falls_back_to_http_when_status_misses(self):
        # https 上 404、http 上 200 的主机很常见，不能被判死
        http = FakeHttp({"https://a.com": 404, "http://a.com": 200})
        config = ScanConfig(alive=StatusMatcher("200-399"))
        result = probe_target(Target("a.com"), config, http=http)
        self.assertTrue(result.alive)
        self.assertEqual(result.url, "http://a.com")
        self.assertEqual(http.calls, ["https://a.com", "http://a.com"])

    def test_reports_first_response_when_nothing_matches(self):
        http = FakeHttp({"https://a.com": 404, "http://a.com": 500})
        config = ScanConfig(alive=StatusMatcher("200"))
        result = probe_target(Target("a.com"), config, http=http)
        self.assertFalse(result.alive)
        self.assertEqual(result.status, 404)  # 兜底报第一个响应
        self.assertEqual(result.url, "https://a.com")

    def test_retries(self):
        http = FakeHttp({"https://a.com": 200})
        config = ScanConfig(retries=1, retry_backoff=0)
        original = http.get
        attempts = {"n": 0}

        def flaky(url):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise requests.Timeout("timed out")
            return original(url)

        http.get = flaky  # type: ignore[method-assign]
        result = probe_target(Target("a.com"), config, http=http)
        self.assertTrue(result.alive)
        self.assertEqual(attempts["n"], 2)

    def test_tls_error_alive(self):
        http = FakeHttp({"https://a.com": requests.exceptions.SSLError("certificate verify failed")})
        self.assertFalse(probe_target(Target("a.com"), http=http).alive)

        http = FakeHttp({"https://a.com": requests.exceptions.SSLError("bad cert")})
        config = ScanConfig(tls_error_alive=True)
        result = probe_target(Target("a.com"), config, http=http)
        self.assertTrue(result.alive)
        self.assertEqual(result.url, "https://a.com")
        self.assertIn("TLS", result.note or "")

    def test_all_dead(self):
        http = FakeHttp({})
        result = probe_target(Target("a.com"), http=http)
        self.assertFalse(result.alive)
        self.assertIsNone(result.status)
        self.assertEqual(len(http.calls), 2)


class ScanTests(unittest.TestCase):
    def test_scan_counts_and_progress(self):
        table = {"https://a.com": 200, "https://b.com": 500, "http://c.com": 301}
        http = FakeHttp(table)
        targets = [Target("a.com"), Target("b.com"), Target("c.com")]
        seen: list[ProbeResult] = []
        progress: list[int] = []
        results, stats = scan(
            targets,
            ScanConfig(workers=3),
            http=http,
            on_result=seen.append,
            on_progress=lambda s: progress.append(s.done),
        )
        self.assertEqual(stats.total, 3)
        self.assertEqual(stats.done, 3)
        self.assertEqual(stats.alive, 3)
        self.assertEqual(len(results), 3)
        self.assertEqual(len(seen), 3)
        self.assertEqual(progress, sorted(progress))
        self.assertFalse(http.closed)  # 外部传入的 http 由调用方关闭

    def test_progress_is_a_snapshot(self):
        http = FakeHttp({"https://a.com": 200, "https://b.com": 404})
        snapshots: list = []
        results, stats = scan(
            [Target("a.com"), Target("b.com")],
            ScanConfig(workers=2),
            http=http,
            progress_interval=0,
            on_progress=snapshots.append,
        )
        self.assertEqual(stats.done, 2)
        # 每个进度都是独立对象，后台改 stats 不会污染已经发给 UI 的进度
        for snap in snapshots:
            self.assertIsNot(snap, stats)
        self.assertEqual([s.done for s in snapshots][-1], 2)

    def test_many_targets_all_collected(self):
        class Always200:
            def get(self, url):
                return FakeResponse(200)

            def close(self):
                pass

        http = Always200()
        targets = [Target(f"h{i}.example.com") for i in range(2000)]
        results, stats = scan(targets, ScanConfig(workers=32), http=http)
        self.assertEqual(len(results), 2000)
        self.assertEqual(stats.done, 2000)
        self.assertEqual(stats.alive, 2000)

    def test_cancel_skips_network(self):
        http = FakeHttp({"https://a.com": 200})
        cancel = threading.Event()
        cancel.set()
        results, stats = scan(
            [Target("a.com")], ScanConfig(workers=1), cancel=cancel, http=http
        )
        self.assertEqual(results, [])
        self.assertEqual(http.calls, [])
        self.assertTrue(stats.cancelled)


class ExportTests(unittest.TestCase):
    def test_write_urls_and_csv_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            self.assertEqual(write_urls(tmpdir / "out" / "live.txt", ["https://a.com"]), 1)
            self.assertEqual((tmpdir / "out" / "live.txt").read_text("utf-8"), "https://a.com\n")

            results = [
                ProbeResult(
                    Target("a.com"), url="https://a.com", status=200,
                    server="nginx", alive=True, elapsed=0.12,
                )
            ]
            stats = stats_for(results)
            self.assertEqual(write_csv(tmpdir / "r.csv", results), 1)
            csv_text = (tmpdir / "r.csv").read_text("utf-8-sig")
            self.assertIn("host,port,alive", csv_text)
            self.assertIn("a.com,,1,https://a.com,200,nginx", csv_text)

            self.assertEqual(write_json(tmpdir / "r.json", results, stats), 1)
            payload = json.loads((tmpdir / "r.json").read_text("utf-8"))
            self.assertEqual(payload["stats"]["alive"], 1)
            self.assertEqual(payload["results"][0]["url"], "https://a.com")


def stats_for(results):
    from liveurldeduper.core import ScanStats

    return ScanStats(total=len(results), done=len(results), alive=1, failed=0, elapsed=0.2)


class ProxyTests(unittest.TestCase):
    def test_build_proxies(self):
        self.assertEqual(
            build_proxies("http", "127.0.0.1", 8080),
            {"http": "http://127.0.0.1:8080"},
        )
        self.assertEqual(
            build_proxies("socks5", "127.0.0.1", "1080"),
            {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"},
        )
        self.assertEqual(build_proxies("http", "", 8080), {})

    def test_parse_proxy(self):
        self.assertEqual(
            parse_proxy("socks5://user:pw@127.0.0.1:1080"),
            {"http": "socks5://user:pw@127.0.0.1:1080",
             "https": "socks5://user:pw@127.0.0.1:1080"},
        )
        self.assertEqual(parse_proxy(""), {})
        with self.assertRaises(ValueError):
            parse_proxy("127.0.0.1")


if __name__ == "__main__":
    unittest.main()
