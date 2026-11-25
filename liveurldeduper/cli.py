"""命令行入口：便于放进流水线 / 被 agent 调用。"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

from .core import (
    ProbeResult,
    ScanConfig,
    ScanStats,
    StatusMatcher,
    parse_proxy,
    read_targets,
    results_to_urls,
    scan,
    write_csv,
    write_json,
    write_urls,
)

_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="liveurldeduper",
        description="子域名存活检测 + URL 去重（默认启动 GUI，给 -i 则走命令行）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--input", help="子域名/URL 列表文件，每行一个")
    parser.add_argument("-o", "--output", help="存活 URL 输出文件（默认与输入同目录 live_urls.txt）")
    parser.add_argument("-t", "--threads", type=int, default=50, help="并发线程数")
    parser.add_argument("--connect-timeout", type=float, default=4.0, help="TCP/TLS 连接超时（秒）")
    parser.add_argument("--read-timeout", type=float, default=6.0, help="响应等待超时（秒）")
    parser.add_argument("--retries", type=int, default=0, help="失败重试次数")
    parser.add_argument(
        "--alive",
        default="any",
        help=(
            '存活判定：any / 2xx / "200-399" / "200-399,401,403"(SRC 推荐) / '
            '"200,301,302"(1.0 口径)；状态码不命中会自动再试另一个协议'
        ),
    )
    parser.add_argument("--proxy", help="代理，如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080")
    parser.add_argument("--verify-tls", action="store_true", help="校验 TLS 证书（默认不校验）")
    parser.add_argument("--follow-redirects", action="store_true", help="跟随 3xx 跳转")
    parser.add_argument(
        "--tls-error-alive",
        action="store_true",
        help="TLS 握手失败也视为存活（自签名证书场景）",
    )
    parser.add_argument("--csv", help="额外导出明细 CSV")
    parser.add_argument("--json", dest="json_path", help="额外导出 JSON（含统计信息）")
    parser.add_argument("-q", "--quiet", action="store_true", help="只输出最终汇总")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    return parser


def _build_config(args: argparse.Namespace) -> ScanConfig:
    try:
        matcher = StatusMatcher(args.alive)
    except ValueError as exc:
        raise SystemExit(f"错误：{exc}") from exc
    return ScanConfig(
        workers=args.threads,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        retries=args.retries,
        verify_tls=args.verify_tls,
        allow_redirects=args.follow_redirects,
        alive=matcher,
        tls_error_alive=args.tls_error_alive,
        proxies=parse_proxy(args.proxy or ""),
    )


def _ensure_console() -> None:
    """windowed 打包的 exe 从 cmd 调用时 stdout 为 None，这里attach 到父控制台。"""
    if sys.stdout is not None and sys.stderr is not None:
        return
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.AttachConsole(-1)  # ATTACH_PARENT_PROCESS
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)  # noqa: SIM115
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)  # noqa: SIM115
    except Exception:
        pass


def run_cli(args: argparse.Namespace) -> int:
    _ensure_console()
    input_path = Path(args.input).expanduser()
    if not input_path.is_file():
        raise SystemExit(f"错误：找不到输入文件 {input_path}")

    color = (not args.no_color) and sys.stdout.isatty()
    # 流式读，百万行的 subs.txt 也不会先被 splitlines() 复制成一个大 list
    counter: dict = {}
    targets = list(read_targets(input_path, counter))
    skipped = int(counter.get("skipped", 0))
    if not targets:
        print("错误：输入文件中没有可解析的目标", file=sys.stderr)
        return 2

    output_path = Path(args.output).expanduser() if args.output else input_path.parent / "live_urls.txt"
    config = _build_config(args)
    cancel = threading.Event()

    if not args.quiet:
        print(
            f"{_DIM}目标 {len(targets)} 个，跳过脏行 {skipped} 行，"
            f"编码 {counter.get('encoding', '?')}，"
            f"线程 {config.workers}，存活判定 {args.alive}{_RESET}"
        )

    last_report = 0.0
    stats_holder: list[ScanStats] = []

    def on_result(result: ProbeResult) -> None:
        if args.quiet:
            return
        if result.alive:
            status = result.status if result.status is not None else "-"
            print(
                f"{_color('存活', _GREEN, color)} {status:>4} "
                f"{result.url}{_DIM} ({result.elapsed:.2f}s){_RESET}"
            )
        elif result.status is not None:
            print(
                f"{_color('不命中', _RED, color)} {result.status:>4} {result.target}"
                f"{_DIM} ({result.error or ''}){_RESET}"
            )

    def on_progress(stats: ScanStats) -> None:
        nonlocal last_report
        if args.quiet:
            return
        now = time.monotonic()
        if now - last_report < 2.0:
            return
        last_report = now
        print(
            f"{_DIM}[进度 {stats.done}/{stats.total}] 存活 {stats.alive} "
            f"| {stats.speed:.1f} 个/秒 | {stats.elapsed:.0f}s{_RESET}",
            file=sys.stderr,
            flush=True,
        )

    try:
        results, stats = scan(
            targets, config, cancel=cancel, on_result=on_result, on_progress=on_progress
        )
    except KeyboardInterrupt:
        cancel.set()
        print("\n已中断", file=sys.stderr)
        return 130

    urls = results_to_urls(results)
    write_urls(output_path, urls)
    if args.csv:
        write_csv(args.csv, results)
    if args.json_path:
        write_json(args.json_path, results, stats)

    print(
        f"完成：共 {stats.total} 个目标，存活 {stats.alive} 个，"
        f"去重后 {len(urls)} 条，用时 {stats.elapsed:.1f}s"
    )
    print(f"结果已写入 {output_path}")
    if args.csv:
        print(f"明细 CSV: {args.csv}")
    if args.json_path:
        print(f"JSON: {args.json_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.input:
        from .gui import run_gui

        run_gui()
        return 0
    return run_cli(args)
