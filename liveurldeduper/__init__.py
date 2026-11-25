"""LiveURLDeduper —— 子域名存活检测与 URL 去重。"""

from .core import (  # noqa: F401
    DEFAULT_USER_AGENT,
    ProbeHttp,
    ProbeResult,
    ScanConfig,
    ScanStats,
    StatusMatcher,
    Target,
    build_proxies,
    candidate_urls,
    dedupe_key,
    dedupe_urls,
    load_targets,
    parse_proxy,
    parse_target,
    probe_target,
    results_to_urls,
    scan,
    write_csv,
    write_json,
    write_urls,
)

__version__ = "2.0.0"
