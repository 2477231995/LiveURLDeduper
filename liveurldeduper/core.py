"""LiveURLDeduper 核心逻辑：目标解析、存活探测、去重、导出。

设计原则：
- 不依赖 tkinter，可被 GUI / CLI / 其它脚本直接复用，也方便写单测。
- 探测策略全部显式可配（超时、重试、状态码判定、TLS、代理），没有魔法。
- 输出结果确定（URL 排序），方便 diff 和二次处理。
"""

from __future__ import annotations

import codecs
import csv
import json
import os
import queue
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

__all__ = [
    "DEFAULT_USER_AGENT",
    "HTTP_FIRST_PORTS",
    "ProbeHttp",
    "ProbeResult",
    "ScanConfig",
    "ScanStats",
    "StatusMatcher",
    "Target",
    "candidate_urls",
    "dedupe_urls",
    "iter_lines",
    "iter_targets",
    "load_targets",
    "parse_target",
    "read_targets",
    "sniff_encoding",
    "probe_target",
    "results_to_urls",
    "scan",
    "write_csv",
    "write_json",
    "write_urls",
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 这些端口上 http 更常见，先试 http 可以少一次 TLS 握手失败的开销
HTTP_FIRST_PORTS = frozenset({80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888})

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_RE = re.compile(r"^[a-zA-Z0-9._\-:]+$")


# --------------------------------------------------------------------------- #
# 目标解析
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Target:
    """一个待探测的目标（主机 + 可选显式端口）。"""

    host: str
    port: int | None = None

    @property
    def hostport(self) -> str:
        if ":" in self.host:  # IPv6
            return f"[{self.host}]:{self.port}" if self.port else f"[{self.host}]"
        return f"{self.host}:{self.port}" if self.port else self.host

    def __str__(self) -> str:  # pragma: no cover - 仅用于日志
        return self.hostport


_SLOW_PATH_CHARS = ("/", "?", "#", "@")


def parse_target(line: str) -> Target | None:
    """把一行脏数据解析成 Target；无法解析时返回 None。

    兼容：host、host:port、scheme://host[:port]/path?query#frag、user:pass@host、[::1]:8080
    拒绝：空行、注释、通配符/正则片段、非法端口。

    子域名文件 99% 的行是裸 `host` / `host:port`，所以先走一条不碰
    urlsplit 的快路径（urlsplit 一个主机名要 4µs，百万行就是 4 秒）。
    """
    raw = (line or "").strip()
    if not raw or raw.startswith("#") or "*" in raw:
        return None

    if not any(ch in raw for ch in _SLOW_PATH_CHARS) and not raw.startswith("["):
        host = raw
        port: int | None = None
        if ":" in raw:
            if raw.count(":") != 1:
                host = ""  # 多冒号：裸 IPv6 或脏数据，交给慢路径
            else:
                host, _, port_text = raw.rpartition(":")
                if not port_text.isdigit():
                    return None
                port = int(port_text)
                if not (1 <= port <= 65535):
                    return None
        if host:
            host = host.lower()
            if host.endswith("."):
                host = host.rstrip(".")
            if not host or len(host) > 253 or not _HOST_RE.match(host):
                return None
            return Target(host=host, port=port)

    raw = _SCHEME_RE.sub("", raw, count=1)
    raw = raw.split("#", 1)[0].split("?", 1)[0].split("/", 1)[0]
    if "@" in raw:  # user:pass@host
        raw = raw.rsplit("@", 1)[1]
    if not raw:
        return None

    try:
        parts = urlsplit("//" + raw)
        host = parts.hostname
        port = parts.port
    except ValueError:  # 端口非数字 / 越界 / IPv6 括号不匹配
        return None

    if not host:
        return None
    host = host.lower().rstrip(".")
    if not host or len(host) > 253 or not _HOST_RE.match(host):
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    return Target(host=host, port=port)


# BOM 优先级：长的在前，否则 UTF-32 LE 会被 UTF-16 LE 抢先匹配
_BOMS: tuple[tuple[bytes, str], ...] = (
    # 用 codecs 常量，避免手写转义写错；长的放前面，否则 UTF-32 LE 会被 UTF-16 LE 抢先匹配
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

_NUL = bytes(1)  # 单个 0x00 字节


def _utf8_ok(sample: bytes) -> bool:
    """用增量解码器判断——末尾被截断的半个字符不算错。"""
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        decoder.decode(sample, False)
        return True
    except UnicodeDecodeError:
        return False


def sniff_encoding(path: str | os.PathLike[str], sample_size: int = 65536) -> str:
    """猜文件编码。读反了整批目标都会变成脏行——记事本存成“Unicode”就是 UTF-16 LE。

    顺序：BOM > 大量 NUL（无 BOM 的 UTF-16）> 严格 UTF-8 > GB18030 > latin-1 兜底。
    """
    with open(path, "rb") as handle:
        sample = handle.read(sample_size)
    for bom, encoding in _BOMS:
        if sample.startswith(bom):
            return encoding
    if sample:
        nulls = sample.count(_NUL)
        if nulls > len(sample) // 4:
            even_nulls = sum(1 for i in range(0, len(sample) - 1, 2) if sample[i] == 0)
            odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
            return "utf-16-be" if even_nulls > odd_nulls else "utf-16-le"
    if _utf8_ok(sample):
        return "utf-8"
    for encoding in ("gb18030", "latin-1"):
        try:
            sample.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "utf-8"


def iter_lines(
    path: str | os.PathLike[str],
    encoding: str | None = None,
    chunk_lines: int = 32768,
) -> Iterator[str]:
    """按块读文件，逐行产出。百万行文件也不会一次性撑爆内存。

    `encoding` 留空时自动嗅探（UTF-8 / UTF-8-BOM / UTF-16 LE/BE / GBK / GB18030）。
    """
    if encoding is None:
        encoding = sniff_encoding(path)
    # utf-16/utf-32 的 BOM 由 codec 自己处理；这里统一用 errors="replace" 防半行损坏崩掉
    with open(path, "r", encoding=encoding, errors="replace", newline="") as handle:
        while True:
            block = handle.readlines(chunk_lines)
            if not block:
                return
            yield from block


def iter_targets(
    lines: Iterable[str], counter: dict | None = None
) -> Iterator[Target]:
    """流式解析并去重，边读边产出 Target。

    `counter` 传入 dict 时会被就地更新：
    `{"lines": 总行数, "skipped": 脏行数, "duplicates": 重复行数}`，
    调用方在迭代结束后读它即可，不需要把整个文件读进 list。

    80/443 这类默认端口视为“没写端口”，避免 a.com 与 a.com:443 重复探测。
    """
    seen: set[tuple[str, int | None]] = set()
    total = skipped = duplicates = 0
    for line in lines:
        total += 1
        target = parse_target(line)
        if target is None:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                skipped += 1
        else:
            key = (target.host, None if target.port in (80, 443) else target.port)
            if key in seen:
                duplicates += 1
            else:
                seen.add(key)
                if counter is not None and total % 4096 == 0:
                    counter.update(lines=total, skipped=skipped, duplicates=duplicates)
                yield target
    if counter is not None:
        counter.update(lines=total, skipped=skipped, duplicates=duplicates)


def read_targets(
    path: str | os.PathLike[str], counter: dict | None = None
) -> Iterator[Target]:
    """文件路径 -> Target 流（自动识别编码 + 流式解析）。"""
    encoding = sniff_encoding(path)
    if counter is not None:
        counter["encoding"] = encoding
    return iter_targets(iter_lines(path, encoding=encoding), counter)


def load_targets(lines: Iterable[str]) -> tuple[list[Target], int]:
    """解析并去重输入行，返回 (目标列表, 被跳过的脏行数)。

    保留了老接口给测试 / 小文件用；大文件请用 read_targets() 流式处理。
    """
    counter: dict = {}
    targets = list(iter_targets(lines, counter))
    return targets, int(counter.get("skipped", 0))


def candidate_urls(target: Target) -> list[str]:
    """按成功率给同主机的候选 URL 排序。"""
    schemes = ["https", "http"]
    if target.port in HTTP_FIRST_PORTS:
        schemes.reverse()
    return [f"{scheme}://{target.hostport}" for scheme in schemes]


# --------------------------------------------------------------------------- #
# 存活判定
# --------------------------------------------------------------------------- #
class StatusMatcher:
    """状态码匹配器，支持 "any"、"2xx"、"200-399"、"200,301,403" 等写法。"""

    def __init__(self, spec: str = "any") -> None:
        self.spec = (spec or "any").strip().lower()
        self._ranges: list[tuple[int, int]] = []
        if self.spec in ("", "any", "*"):
            self.spec = "any"
            self._ranges = [(100, 599)]
            return
        for chunk in re.split(r"[,\s]+", self.spec):
            if not chunk:
                continue
            if re.fullmatch(r"[1-5]xx", chunk):
                lo = int(chunk[0]) * 100
                self._ranges.append((lo, lo + 99))
            elif "-" in chunk:
                lo_s, _, hi_s = chunk.partition("-")
                if not (lo_s.isdigit() and hi_s.isdigit()):
                    raise ValueError(f"无法解析状态码范围: {chunk!r}")
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    lo, hi = hi, lo
                self._ranges.append((lo, hi))
            elif chunk.isdigit():
                code = int(chunk)
                self._ranges.append((code, code))
            else:
                raise ValueError(f"无法解析状态码: {chunk!r}")
        if not self._ranges:
            raise ValueError(f"状态码规则为空: {spec!r}")

    def __call__(self, status: int | None) -> bool:
        if status is None:
            return False
        return any(lo <= status <= hi for lo, hi in self._ranges)

    def __repr__(self) -> str:  # pragma: no cover
        return f"StatusMatcher({self.spec!r})"


ANY_STATUS = StatusMatcher("any")


# --------------------------------------------------------------------------- #
# 探测
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ScanConfig:
    workers: int = 50
    connect_timeout: float = 4.0
    read_timeout: float = 6.0
    retries: int = 0                    # 应用层重试次数（0 = 只打一次）
    verify_tls: bool = False            # 渗透场景默认不校验证书
    allow_redirects: bool = False
    alive: Callable[[int | None], bool] = ANY_STATUS
    tls_error_alive: bool = False       # TLS 握手失败但端口通，也算存活（自签名证书场景）
    user_agent: str = DEFAULT_USER_AGENT
    proxies: dict[str, str] = field(default_factory=dict)
    retry_backoff: float = 0.25

    def __post_init__(self) -> None:
        if self.workers < 1:
            raise ValueError("workers 必须 >= 1")
        if self.retries < 0:
            raise ValueError("retries 不能为负")


@dataclass
class ProbeResult:
    target: Target
    url: str | None = None
    status: int | None = None
    server: str | None = None
    location: str | None = None
    alive: bool = False
    elapsed: float = 0.0
    error: str | None = None
    note: str | None = None

    @property
    def host(self) -> str:
        return self.target.host

    @property
    def port(self) -> int | None:
        return self.target.port


class ProbeHttp:
    """按线程复用 requests.Session 的轻量客户端。

    - stream=True 只读响应头，避免把整页 body 拖下来（大流量目标差距明显）。
    - 每线程一个 Session：省掉每次请求新建连接池的开销，也让代理/证书只配一次。
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._lock = threading.Lock()
        if not config.verify_tls:
            urllib3.disable_warnings(InsecureRequestWarning)

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session
        session = requests.Session()
        session.verify = self.config.verify_tls
        session.headers.update(
            {
                "User-Agent": self.config.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )
        if self.config.proxies:
            session.proxies.update(self.config.proxies)
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        with self._lock:
            self._sessions.append(session)
        self._local.session = session
        return session

    def get(self, url: str) -> requests.Response:
        return self._session().get(
            url,
            timeout=(self.config.connect_timeout, self.config.read_timeout),
            allow_redirects=self.config.allow_redirects,
            stream=True,
        )

    def close(self) -> None:
        with self._lock:
            sessions, self._sessions = self._sessions, []
        for session in sessions:
            session.close()


def _short(exc: BaseException, limit: int = 100) -> str:
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    return f"{exc.__class__.__name__}: {text[:limit]}"


def probe_target(
    target: Target,
    config: ScanConfig | None = None,
    *,
    http: ProbeHttp | None = None,
    cancel: threading.Event | None = None,
) -> ProbeResult:
    """探测单个目标：https 优先，失败回退 http。

    命中存活判定立即返回；状态码不命中则继续试另一个协议（https 上 404/403
    但 http 上 200 的主机很多，直接返回会把它们漏掉），最后拿第一个响应兜底。
    """
    config = config or ScanConfig()
    http = http or ProbeHttp(config)
    started = time.perf_counter()
    errors: list[str] = []
    last_status: int | None = None
    tls_failed = False
    first_response: ProbeResult | None = None

    for url in candidate_urls(target):
        for attempt in range(config.retries + 1):
            if cancel is not None and cancel.is_set():
                return ProbeResult(
                    target=target,
                    elapsed=time.perf_counter() - started,
                    error="已取消",
                )
            try:
                response = http.get(url)
            except requests.exceptions.SSLError as exc:
                tls_failed = True
                errors.append(f"{url} -> {_short(exc)}")
                break
            except Exception as exc:  # 连接失败/超时/DNS 失败等
                errors.append(f"{url} -> {_short(exc)}")
                if attempt < config.retries:
                    time.sleep(config.retry_backoff * (attempt + 1))
                continue
            else:
                status = getattr(response, "status_code", None)
                headers = getattr(response, "headers", {}) or {}
                try:
                    location = headers.get("Location")
                    server = headers.get("Server")
                finally:
                    closer = getattr(response, "close", None)
                    if callable(closer):
                        closer()
                last_status = status
                alive = bool(config.alive(status))
                result = ProbeResult(
                    target=target,
                    url=url,
                    status=status,
                    server=server,
                    location=location,
                    alive=alive,
                    elapsed=time.perf_counter() - started,
                    error=None if alive else f"状态码 {status} 不在判定范围内",
                    note=None if alive else "状态码未命中",
                )
                if result.alive:
                    return result
                # 状态码没命中就记下来，继续试另一个协议：
                # 常见的是 https 上 404/403 但 http 上 200，直接 return 会漏掉这类主机。
                if first_response is None:
                    first_response = result
                break

    if first_response is not None:
        if errors:
            first_response.error = f"{first_response.error}; " + "; ".join(errors)
        return first_response

    if tls_failed and config.tls_error_alive:
        https_url = f"https://{target.hostport}"
        return ProbeResult(
            target=target,
            url=https_url,
            status=last_status,
            alive=True,
            elapsed=time.perf_counter() - started,
            error="; ".join(errors) or None,
            note="TLS 握手失败，按配置视为存活",
        )

    return ProbeResult(
        target=target,
        status=last_status,
        alive=False,
        elapsed=time.perf_counter() - started,
        error="; ".join(errors) or "无响应",
    )


# --------------------------------------------------------------------------- #
# 批量扫描
# --------------------------------------------------------------------------- #
@dataclass
class ScanStats:
    total: int = 0
    done: int = 0
    alive: int = 0
    failed: int = 0
    cancelled: bool = False
    elapsed: float = 0.0
    pending: int = 0      # 还在探测中的目标数（卡在“17/18”时看得到）
    abandoned: int = 0    # 到了硬截止时间被放弃的目标数

    @property
    def speed(self) -> float:  # 个/秒
        return self.done / self.elapsed if self.elapsed > 0 else 0.0

    def snapshot(self) -> "ScanStats":
        """给 UI 线程用的不可变快照，避免跨线程读到正在被改的对象。"""
        return ScanStats(
            total=self.total,
            done=self.done,
            alive=self.alive,
            failed=self.failed,
            cancelled=self.cancelled,
            elapsed=self.elapsed,
            pending=self.pending,
            abandoned=self.abandoned,
        )


class _DaemonPool:
    """固定大小的守护线程池。

    为什么不用 ThreadPoolExecutor：它的 worker 是非守护线程。requests 的 timeout
    管不住 DNS（getaddrinfo 没有超时参数），只要有一个域名解析卡住，这个 worker 就
    永远不返回——scan() 一直停在 "17/18"，进程退出还会被 atexit 里的 join 挂死。
    这里的线程是 daemon，配合 scan() 里的硬截止时间：超时就放弃那个目标，扫描照常
    收尾，卡住的线程也不会拖住窗口关闭。
    """

    def __init__(self, workers: int, name: str = "probe") -> None:
        self._queue: queue.Queue = queue.Queue()
        self._threads = [
            threading.Thread(target=self._loop, daemon=True, name=f"{name}-{i}")
            for i in range(max(1, int(workers)))
        ]
        for thread in self._threads:
            thread.start()

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                fn, args, kwargs, future = item
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    future.set_result(fn(*args, **kwargs))
                except BaseException as exc:  # noqa: BLE001 - 原样回传给收集线程
                    future.set_exception(exc)
            finally:
                self._queue.task_done()

    def submit(self, fn, *args, **kwargs) -> Future:
        future: Future = Future()
        self._queue.put((fn, args, kwargs, future))
        return future

    def shutdown(self) -> None:
        """只发停止信号，不 join：卡住的线程不允许拖住退出。"""
        for _ in self._threads:
            self._queue.put(None)


def default_hard_deadline(config: ScanConfig) -> float:
    """单个目标的硬截止时间：两个协议各一次 connect+read，再按重试放宽，留 5s 余量。"""
    return (config.connect_timeout + config.read_timeout) * (2 + config.retries) + 5.0


def scan(
    targets: Sequence[Target],
    config: ScanConfig | None = None,
    *,
    cancel: threading.Event | None = None,
    on_result: Callable[[ProbeResult], None] | None = None,
    on_progress: Callable[[ScanStats], None] | None = None,
    http: ProbeHttp | None = None,
    progress_interval: float = 0.2,
    pending_factor: int = 4,
    hard_deadline: float | None = None,
) -> tuple[list[ProbeResult], ScanStats]:
    """并发探测，返回 (全部结果, 统计)。on_result / on_progress 在收集线程回调。

    三条关键设计（分别对应内存爆掉、界面卡死、卡在最后一个目标这三类现场）：
    - 滑动窗口提交，最多 `workers * pending_factor` 个在途，10 万目标也只占十几 MB；
    - 每个目标有硬截止时间：requests 的 timeout 管不住 DNS，一个域名解析挂住就会
      让整批永远停在 17/18；到点直接放弃该目标并记一条失败，扫描继续收尾；
    - worker 是守护线程，被放弃的探测即使还卡着，也不会拖住进程退出。
    """
    config = config or ScanConfig()
    cancel = cancel or threading.Event()
    owns_http = http is None
    http = http or ProbeHttp(config)
    total = len(targets)
    stats = ScanStats(total=total)
    results: list[ProbeResult] = []
    started = time.perf_counter()
    pending_limit = max(int(config.workers * max(pending_factor, 1)), 64)
    if hard_deadline is None:
        hard_deadline = default_hard_deadline(config)
    last_progress = 0.0
    index = 0
    pending: set[Future] = set()
    started_at: dict[Future, float] = {}
    target_of: dict[Future, Target] = {}
    pool = _DaemonPool(config.workers, name="probe")

    def fill() -> None:
        nonlocal index
        while index < total and len(pending) < pending_limit:
            target = targets[index]
            future = pool.submit(probe_target, target, config, http=http, cancel=cancel)
            pending.add(future)
            started_at[future] = time.perf_counter()
            target_of[future] = target
            index += 1

    def record(result: ProbeResult) -> None:
        results.append(result)
        stats.done += 1
        stats.alive += int(result.alive)
        stats.failed += int(not result.alive)
        if on_result is not None:
            on_result(result)

    try:
        if not cancel.is_set():
            fill()
            while pending:
                done, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    started_at.pop(future, None)
                    target_of.pop(future, None)
                    try:
                        result = future.result()
                    except Exception as exc:  # 理论上 probe_target 不会抛，兜底
                        result = ProbeResult(
                            target=Target("?"), alive=False, error=_short(exc)
                        )
                    if result.error == "已取消":
                        continue
                    record(result)
                if cancel.is_set():
                    break

                # 硬截止：DNS 卡死 / 服务端不吐字节的，不能陪它无限等
                now = time.perf_counter()
                stalled = [
                    future
                    for future, submitted_at in started_at.items()
                    if now - submitted_at > hard_deadline
                ]
                for future in stalled:
                    began = started_at.pop(future, now)
                    pending.discard(future)
                    target = target_of.pop(future, Target("?"))
                    stats.abandoned += 1
                    record(
                        ProbeResult(
                            target=target,
                            alive=False,
                            elapsed=now - began,
                            error=(
                                f"超过 {hard_deadline:.0f}s 未返回"
                                f"（多为 DNS 解析/握手卡住），已放弃"
                            ),
                            note="abandoned",
                        )
                    )
                if stalled and cancel.is_set():
                    break

                fill()
                stats.pending = len(pending)
                if on_progress is not None:
                    now = time.perf_counter()
                    if now - last_progress >= progress_interval:
                        last_progress = now
                        stats.elapsed = now - started
                        on_progress(stats.snapshot())
    finally:
        pool.shutdown()
        if owns_http:
            http.close()

    stats.cancelled = cancel.is_set()
    stats.elapsed = time.perf_counter() - started
    stats.pending = len(pending)
    if on_progress is not None and not stats.cancelled:
        on_progress(stats.snapshot())
    return results, stats


# --------------------------------------------------------------------------- #
# 去重与导出
# --------------------------------------------------------------------------- #
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_url(url: str) -> str:
    """规范化 URL：小写 scheme/host、去掉尾部点、去掉默认端口。"""
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return raw.lower()
    if not host:
        return raw
    scheme = parts.scheme.lower() or "http"
    if port == _DEFAULT_PORTS.get(scheme):
        port = None
    hostport = f"[{host}]" if ":" in host else host
    if port:
        hostport += f":{port}"
    rest = ""
    if parts.path and parts.path != "/":
        rest += parts.path
    if parts.query:
        rest += "?" + parts.query
    if parts.fragment:
        rest += "#" + parts.fragment
    return f"{scheme}://{hostport}{rest}"


def dedupe_key(url: str) -> tuple[str, int | None]:
    """同一主机的 http/https 视为一组；显式默认端口（:443/:80）归一化掉。"""
    try:
        parts = urlsplit(_canonical_url(url))
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return (_canonical_url(url), None)
    return (host, port)


def _sort_key(url: str) -> tuple[str, int, int, str]:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port or 0
        scheme = 0 if parts.scheme == "https" else 1
    except ValueError:
        host, port, scheme = url.lower(), 0, 2
    return (host, port, scheme, url)


def dedupe_urls(urls: Iterable[str], *, prefer_https: bool = True) -> list[str]:
    """按主机去重，优先保留 https；输出规范、排序稳定。"""
    chosen: dict[tuple[str, int | None], str] = {}
    for url in urls:
        url = _canonical_url(url)
        if not url or url == "http://":
            continue
        key = dedupe_key(url)
        current = chosen.get(key)
        if current is None:
            chosen[key] = url
            continue
        if prefer_https and url.startswith("https://") and current.startswith("http://"):
            chosen[key] = url
    return sorted(chosen.values(), key=_sort_key)


def results_to_urls(
    results: Iterable[ProbeResult], *, prefer_https: bool = True
) -> list[str]:
    return dedupe_urls(
        (r.url for r in results if r.alive and r.url), prefer_https=prefer_https
    )


def write_urls(path: str | os.PathLike[str], urls: Iterable[str]) -> int:
    items = list(urls)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for url in items:
            handle.write(url + "\n")
    return len(items)


def write_csv(path: str | os.PathLike[str], results: Iterable[ProbeResult]) -> int:
    rows = list(results)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["host", "port", "alive", "url", "status", "server", "location", "elapsed", "error"]
        )
        for result in rows:
            writer.writerow(
                [
                    result.host,
                    result.port or "",
                    int(result.alive),
                    result.url or "",
                    result.status if result.status is not None else "",
                    result.server or "",
                    result.location or "",
                    f"{result.elapsed:.3f}",
                    result.error or "",
                ]
            )
    return len(rows)


def write_json(
    path: str | os.PathLike[str],
    results: Iterable[ProbeResult],
    stats: ScanStats | None = None,
) -> int:
    payload: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if stats is not None:
        payload["stats"] = {
            "total": stats.total,
            "done": stats.done,
            "alive": stats.alive,
            "failed": stats.failed,
            "cancelled": stats.cancelled,
            "elapsed": round(stats.elapsed, 3),
        }
    items = []
    for result in results:
        items.append(
            {
                "host": result.host,
                "port": result.port,
                "alive": result.alive,
                "url": result.url,
                "status": result.status,
                "server": result.server,
                "location": result.location,
                "elapsed": round(result.elapsed, 3),
                "error": result.error,
                "note": result.note,
            }
        )
    payload["results"] = items
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return len(items)


# --------------------------------------------------------------------------- #
# 代理
# --------------------------------------------------------------------------- #
def build_proxies(
    protocol: str, host: str, port: int | str, username: str = "", password: str = ""
) -> dict[str, str]:
    """构造 requests 的 proxies 字典；http/https 用对应协议，socks5 双写。"""
    protocol = (protocol or "http").strip().lower()
    host = (host or "").strip()
    if not host:
        return {}
    auth = f"{username}:{password}@" if username else ""
    if protocol in ("http", "https"):
        url = f"{protocol}://{auth}{host}:{int(port)}"
        return {protocol: url}
    if protocol in ("socks5", "socks5h", "socks4"):
        url = f"{protocol}://{auth}{host}:{int(port)}"
        return {"http": url, "https": url}
    raise ValueError(f"不支持的代理协议: {protocol}")


def parse_proxy(proxy: str) -> dict[str, str]:
    """把 "socks5://127.0.0.1:1080" 解析成 proxies 字典。"""
    proxy = (proxy or "").strip()
    if not proxy:
        return {}
    parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    if not parts.hostname or not parts.port:
        raise ValueError(f"代理格式应为 scheme://host:port，收到: {proxy!r}")
    protocol = (parts.scheme or "http").lower()
    return build_proxies(
        protocol, parts.hostname, parts.port, parts.username or "", parts.password or ""
    )
