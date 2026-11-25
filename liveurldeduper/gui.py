"""Tkinter 图形界面。

线程模型：所有网络/IO 都在后台线程，后台线程只往 `queue.Queue` 写消息，
主线程用 `root.after` 定时消费。这样彻底避免了跨线程操作 Tk 控件导致的卡死/崩溃。
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .core import (
    ProbeResult,
    ScanConfig,
    ScanStats,
    StatusMatcher,
    Target,
    parse_proxy,
    read_targets,
    results_to_urls,
    scan,
    write_csv,
    write_urls,
)

AUTHOR = "by gucheNg"   # 只出现在窗口标题栏，正文里不重复
APP_TITLE = f"LiveURLDeduper · 子域名存活检测 / URL 去重 · {AUTHOR}"

# 存活判定预设：(写进配置的规则, 下拉框里给人看的说明)
ALIVE_PRESETS: tuple[tuple[str, str], ...] = (
    ("200", "只认 200（默认）"),
    ("200-399,401,403", "SRC 推荐：2xx/3xx + 401/403，排除 404 泛解析与 5xx"),
    ("any", "任何 HTTP 响应都算活（含 404/500），先摸清多少主机起服务"),
)
DEFAULT_ALIVE = ALIVE_PRESETS[0][0]
SETTINGS_VERSION = 4   # 4：老配置里的 alive 不再沿用，统一换成默认档 200
ALIVE_OPTIONS = [spec for spec, _hint in ALIVE_PRESETS]
ALIVE_HINTS = dict(ALIVE_PRESETS)
CONNECT_TIMEOUT = 4.0      # GUI 不再提供这两项，要调走 CLI
READ_TIMEOUT = 6.0
# 单个目标的硬截止：和 core.default_hard_deadline 一致（connect+read 跑两个协议 + 5s）
HARD_DEADLINE = (CONNECT_TIMEOUT + READ_TIMEOUT) * 2 + 5.0
MAX_LOG_LINES = 3000
LOG_TRIM_SLACK = 1000      # 超出上限这么多才批量裁一次，避免每行都删
MAX_TREE_ROWS = 8000       # 存活行进表上限
MAX_DEAD_ROWS = 2000       # 非存活行进表上限（别让 404 把存活行挤没了）
PUMP_INTERVAL_MS = 40      # 主线程多久消费一次消息队列
PUMP_BUDGET = 0.012        # 每次消费最多占用主线程 12ms，剩下的下一轮再说
ROW_FLUSH_TARGET = 0.010   # 每轮插表目标耗时，超过就减半、远低于就加倍（自适应）
LOG_FLUSH_TARGET = 0.006
ROW_BATCH_MIN, ROW_BATCH_MAX = 50, 2000
LOG_BATCH_MIN, LOG_BATCH_MAX = 50, 2000
LOG_BACKLOG_MAX = 10000    # 日志积压上限，超了就丢最老的（控件本身只留 3000 行）


# --------------------------------------------------------------------------- #
# 设置持久化
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "LiveURLDeduper"


def settings_path() -> Path:
    return config_dir() / "settings.json"


def load_settings() -> dict:
    try:
        return json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(data: dict) -> None:
    try:
        path = settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()  # type: ignore[attr-defined]
        except Exception:
            pass


def open_in_explorer(path: Path) -> None:
    folder = path if path.is_dir() else path.parent
    try:
        if sys.platform == "win32":
            os.startfile(str(folder))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 控件
# --------------------------------------------------------------------------- #
class LogView(ttk.Frame):
    """带行数上限的日志控件。

    两条关键优化（老版本每条日志要 ~10ms，500 条/轮直接把主线程焊死）：
    1. 一行一批地写太贵，改成整批 insert 一次；
    2. 到上限后不是每写一行就从头部删一行（那是 O(n) 拷贝），而是超出
       LOG_TRIM_SLACK 行才批量删一次。
    另外用户往上翻日志时不再强制 see(END) 把视图拽回底部。
    """

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.text = tk.Text(
            self, height=10, wrap=tk.WORD, state=tk.DISABLED,
            bg="#fbfbfb", relief=tk.FLAT, font=("Consolas", 9),
        )
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._lines = 0

    def _at_bottom(self) -> bool:
        try:
            return self.text.yview()[1] >= 0.999
        except tk.TclError:
            return True

    def append(self, message: str) -> None:
        self.append_many([message])

    def append_many(self, messages) -> None:
        if not messages:
            return
        if isinstance(messages, str):
            messages = [messages]
        stamp = time.strftime("%H:%M:%S")
        payload = "".join(f"[{stamp}] {m}\n" for m in messages)
        follow = self._at_bottom()
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, payload)
        self._lines += len(messages)
        if self._lines > MAX_LOG_LINES + LOG_TRIM_SLACK:
            excess = self._lines - MAX_LOG_LINES
            self.text.delete("1.0", f"{excess + 1}.0")
            self._lines = MAX_LOG_LINES
        if follow:
            self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def clear(self) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)
        self._lines = 0


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.settings = load_settings()
        self.queue: queue.Queue[tuple] = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None
        self.results: list[ProbeResult] = []
        self.stats: ScanStats | None = None
        self.output_path = tk.StringVar()
        # 主线程渲染状态：行数自己数，别去问 Treeview（get_children() 是 O(n)，
        # 老版本每插一行调一次，2 万行时光这一项就吃掉 34 秒）
        self._tree_rows = 0
        self._tree_truncated = False
        self._row_backlog: list[tuple] = []
        self._log_backlog: list[str] = []
        self._alive_rows = 0
        self._dead_rows = 0
        self._row_batch = 300     # 每轮插表行数，跑起来后按实测耗时自适应
        self._log_batch = 300
        self._last_progress_at = 0.0
        self._last_summary_at = 0.0
        self._input_entry: ttk.Entry | None = None
        # 界面上不放这个开关了，要开就改 settings.json 里的 "verbose_log": true
        self.verbose_log_var = tk.BooleanVar(value=False)
        self._verbose_log = False   # 缓存开关：每条结果读一次 Tk 变量太贵

        root.title(APP_TITLE)
        root.geometry(self.settings.get("geometry", "900x620"))
        root.minsize(780, 520)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        try:
            style.theme_use("vista" if sys.platform == "win32" else "clam")
        except tk.TclError:
            pass
        style.configure("TButton", font=("微软雅黑", 10))
        style.configure("TLabel", font=("微软雅黑", 10))
        style.configure("TCheckbutton", font=("微软雅黑", 10))
        style.configure("Header.TLabel", font=("微软雅黑", 15, "bold"))
        style.configure("Hint.TLabel", foreground="#777", font=("微软雅黑", 9))
        style.configure("Treeview", rowheight=24, font=("Consolas", 9))

        self._build_ui()
        self._load_state()
        self.root.after(100, self._pump)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(outer, text="子域名存活检测 / URL 去重", style="Header.TLabel").pack(
            anchor=tk.W, pady=(0, 10)
        )

        # 1) 文件：只有一个输入框
        files = ttk.Frame(outer)
        files.pack(fill=tk.X)
        files.columnconfigure(1, weight=1)
        ttk.Label(files, text="子域名文件").grid(row=0, column=0, sticky=tk.W)
        self.input_var = tk.StringVar()
        self._input_entry = ttk.Entry(files, textvariable=self.input_var)
        self._input_entry.grid(row=0, column=1, sticky=tk.EW, padx=8)
        ttk.Button(files, text="浏览…", command=self.select_input, width=8).grid(
            row=0, column=2
        )
        self.output_hint_var = tk.StringVar(value="输出：与输入文件同目录的 live_urls.txt")
        ttk.Label(files, textvariable=self.output_hint_var, style="Hint.TLabel").grid(
            row=1, column=1, columnspan=2, sticky=tk.W, padx=8, pady=(2, 0)
        )

        # 2) 参数：只留真正会改的三个，其余走默认值（要调就用 CLI）
        opts = ttk.Frame(outer)
        opts.pack(fill=tk.X, pady=(10, 0))
        opts.columnconfigure(1, weight=1)
        opts.columnconfigure(4, weight=1)

        ttk.Label(opts, text="线程").grid(row=0, column=0, sticky=tk.W)
        self.workers_var = tk.StringVar(value="50")
        ttk.Combobox(
            opts, textvariable=self.workers_var, width=5,
            values=["10", "30", "50", "100", "200", "300"],
        ).grid(row=0, column=1, sticky=tk.W, padx=(6, 16))

        ttk.Label(opts, text="存活判定").grid(row=0, column=2, sticky=tk.W)
        self.alive_var = tk.StringVar(value=DEFAULT_ALIVE)
        self.alive_combo = ttk.Combobox(
            opts,
            textvariable=self.alive_var,
            width=26,
            values=ALIVE_OPTIONS,
            state="readonly",  # 只能选预设，防止手打错规则把整批目标判死
        )
        self.alive_combo.grid(row=0, column=3, sticky=tk.W, padx=(6, 0))
        self.alive_combo.bind("<<ComboboxSelected>>", self._on_alive_changed)

        ttk.Label(opts, text="代理（可留空）").grid(
            row=1, column=0, sticky=tk.W, pady=(8, 0)
        )
        self.proxy_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.proxy_var).grid(
            row=1, column=1, columnspan=4, sticky=tk.EW, padx=(6, 0), pady=(8, 0)
        )

        self.alive_hint_var = tk.StringVar()
        ttk.Label(
            opts, textvariable=self.alive_hint_var, style="Hint.TLabel", wraplength=820,
        ).grid(row=2, column=0, columnspan=5, sticky=tk.W, pady=(6, 0))
        self._refresh_alive_hint()

        # 3) 按钮
        actions = ttk.Frame(outer)
        actions.pack(fill=tk.X, pady=10)
        self.start_btn = ttk.Button(actions, text="开始检测", command=self.start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(
            actions, text="停止", command=self._cancel_scan, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="复制存活 URL", command=self.copy_urls).pack(
            side=tk.LEFT, padx=(16, 0)
        )
        ttk.Button(actions, text="导出 CSV", command=self.export_csv).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(actions, text="打开目录", command=self.open_output_dir).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        # 4) 进度
        progress = ttk.Frame(outer)
        progress.pack(fill=tk.X)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            progress, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(fill=tk.X)
        self.status_var = tk.StringVar(value="就绪：选择子域名文件，或直接把文件拖进来")
        ttk.Label(progress, textvariable=self.status_var).pack(anchor=tk.W, pady=(4, 0))

        # 5) 结果 / 日志
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="结果")
        columns = ("host", "scheme", "status", "server", "url", "cost")
        self.tree = ttk.Treeview(
            results_frame, columns=columns, show="headings", selectmode="extended"
        )
        for key, label, width, anchor in (
            ("host", "主机", 180, tk.W),
            ("scheme", "协议", 52, tk.CENTER),
            ("status", "状态码", 60, tk.CENTER),
            ("server", "Server", 120, tk.W),
            ("url", "URL", 220, tk.W),
            ("cost", "耗时", 52, tk.E),
        ):
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor=anchor, stretch=key in ("url", "host"))
        self.tree.tag_configure("alive", foreground="#0a7d33")
        self.tree.tag_configure("denied", foreground="#b26a00")
        self.tree.tag_configure("dead", foreground="#999999")
        tree_scroll = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<Double-1>", lambda _e: self.copy_urls())
        self.tree.bind("<Control-c>", lambda _e: self.copy_urls())
        self.root.bind("<Escape>", self._cancel_scan)

        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="日志")
        self.log_view = LogView(log_frame)
        self.log_view.pack(fill=tk.BOTH, expand=True)

        self._install_dnd()

    def _refresh_alive_hint(self) -> None:
        spec = self.alive_var.get() or DEFAULT_ALIVE
        hint = ALIVE_HINTS.get(spec)
        if hint is None:
            hint = "自定义规则（CLI 传进来的），GUI 下拉框里没有这一档"
        self.alive_hint_var.set(f"{spec} → {hint}")

    def _on_alive_changed(self, _event=None) -> None:
        self._refresh_alive_hint()

    # ------------------------------------------------------------- drag&drop
    def _install_dnd(self) -> None:
        """可选：装了 tkinterdnd2 就支持把文件拖进窗口，没装就静默跳过。"""
        try:
            from tkinterdnd2 import DND_FILES
        except Exception:
            return
        try:
            targets = [self.root, self._input_entry]
            for widget in targets:
                if widget is None:
                    continue
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            pass

    def _on_drop(self, event) -> None:
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [str(event.data)]
        if not paths:
            return
        filename = paths[0].strip("{}")
        if not Path(filename).is_file():
            return
        self.input_var.set(filename)
        self.settings["last_dir"] = str(Path(filename).parent)
        self._refresh_output_hint()
        try:
            size_kb = Path(filename).stat().st_size / 1024
            self.status_var.set(f"已选择 {Path(filename).name}（{size_kb:.1f} KB），点“开始检测”")
        except OSError:
            self.status_var.set(f"已选择 {Path(filename).name}，点“开始检测”")

    # --------------------------------------------------------------- state
    def _load_state(self) -> None:
        s = self.settings
        self.input_var.set(s.get("input", ""))
        self._refresh_output_hint()
        self.workers_var.set(str(s.get("workers", 50)))
        saved_alive = s.get("alive") or DEFAULT_ALIVE
        if int(s.get("version", 0) or 0) < SETTINGS_VERSION:
            # 老版本存下的 any / 200 之类不沿用了，直接把新推荐档亮出来
            saved_alive = DEFAULT_ALIVE
        if saved_alive not in ALIVE_OPTIONS:  # CLI 写进去的自定义规则，保留但补进下拉框
            self.alive_combo.configure(values=[saved_alive, *ALIVE_OPTIONS])
        self.alive_var.set(saved_alive)
        self._refresh_alive_hint()
        # 兼容老版本的三个代理字段
        proxy = s.get("proxy", "")
        if not proxy and s.get("proxy_host"):
            proxy = f"{s.get('proxy_protocol', 'http')}://{s.get('proxy_host')}:{s.get('proxy_port', '')}"
        self.proxy_var.set(proxy)
        self.verbose_log_var.set(bool(s.get("verbose_log", False)))
        self._verbose_log = self.verbose_log_var.get()

    def _collect_state(self) -> dict:
        return {
            "version": SETTINGS_VERSION,
            "input": self.input_var.get().strip(),
            "workers": self.workers_var.get().strip(),
            "alive": self.alive_var.get().strip() or DEFAULT_ALIVE,
            "proxy": self.proxy_var.get().strip(),
            "verbose_log": self.verbose_log_var.get(),
            "last_dir": self.settings.get("last_dir", ""),
            "geometry": self.root.geometry(),
        }

    def on_close(self) -> None:
        save_settings(self._collect_state())
        if self.worker is not None and self.worker.is_alive():
            if not messagebox.askokcancel("仍在扫描", "扫描尚未结束，确定退出吗？"):
                return
            self.cancel.set()
        self.root.destroy()

    # ------------------------------------------------------------- helpers
    def log(self, message: str) -> None:
        self.log_view.append(message)

    def _set_running(self, running: bool) -> None:
        self.start_btn.configure(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.configure(state=tk.NORMAL if running else tk.DISABLED)

    def select_input(self) -> None:
        initial = self.settings.get("last_dir") or os.getcwd()
        filename = filedialog.askopenfilename(
            title="选择子域名文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=initial,
        )
        if not filename:
            return
        self.input_var.set(filename)
        self.settings["last_dir"] = str(Path(filename).parent)
        self._refresh_output_hint()
        try:
            size_kb = Path(filename).stat().st_size / 1024
            self.status_var.set(f"已选择 {Path(filename).name}（{size_kb:.1f} KB）")
        except OSError:
            self.status_var.set(f"已选择 {Path(filename).name}")

    def _default_output(self) -> Path | None:
        """输出固定为输入文件同目录的 live_urls.txt。"""
        input_file = self.input_var.get().strip()
        return Path(input_file).with_name("live_urls.txt") if input_file else None

    def _refresh_output_hint(self) -> None:
        target = self._default_output()
        self.output_path.set(str(target) if target else "")
        self.output_hint_var.set(
            f"输出：{target}" if target else "输出：与输入文件同目录的 live_urls.txt"
        )

    def _config(self) -> ScanConfig:
        """GUI 只暴露线程数 / 存活判定 / 代理，其余用默认值。"""
        workers = int(self.workers_var.get() or 50)
        return ScanConfig(
            workers=workers,
            connect_timeout=CONNECT_TIMEOUT,
            read_timeout=READ_TIMEOUT,
            alive=StatusMatcher(self.alive_var.get() or DEFAULT_ALIVE),
            proxies=parse_proxy(self.proxy_var.get().strip()),
        )

    # -------------------------------------------------------------- actions
    def start(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return
        input_file = self.input_var.get().strip().strip('"')
        if not input_file or not Path(input_file).is_file():
            messagebox.showerror("错误", "请选择有效的输入文件")
            return
        try:
            config = self._config()
        except ValueError as exc:
            messagebox.showerror("参数错误", str(exc))
            return

        output_file = str(self._default_output())
        verbose_log = self.verbose_log_var.get()
        self._verbose_log = verbose_log
        save_settings(self._collect_state())
        self._refresh_output_hint()
        self._reset_view()
        self._set_running(True)
        self.cancel.clear()
        self.notebook.select(0)
        self.log(
            f"读取文件：{input_file}（线程 {config.workers}，"
            f"存活判定 {self.alive_var.get() or DEFAULT_ALIVE}）"
        )
        self.status_var.set("读取文件…")
        # 读文件 + 解析 + 写结果全部在后台，主线程只负责画界面
        self.worker = threading.Thread(
            target=self._run_scan,
            args=(Path(input_file), output_file, config, verbose_log),
            daemon=True,
            name="scan",
        )
        self.worker.start()

    def _reset_view(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._tree_rows = 0
        self._tree_truncated = False
        self._row_backlog = []
        self._log_backlog = []
        self._alive_rows = 0
        self._dead_rows = 0
        self._row_batch = 300
        self._log_batch = 300
        self.results = []
        self.stats = None
        self.log_view.clear()
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=100)
        self.progress_var.set(0)
        self._last_progress_at = 0.0
        self._last_summary_at = 0.0

    def _run_scan(
        self,
        input_path: Path,
        output_file: str,
        config: ScanConfig,
        verbose_log: bool,
    ) -> None:
        """后台线程：流式读 → 探测 → 写文件，只往 queue 扔消息。"""
        counter: dict = {}
        targets: list[Target] = []
        try:
            for index, target in enumerate(read_targets(input_path, counter), 1):
                targets.append(target)
                if index % 50000 == 0:
                    self.queue.put(("reading", index, dict(counter)))
                if self.cancel.is_set():
                    break

            if not targets:
                self.queue.put(("empty", dict(counter)))
                return

            self.queue.put(("targets", len(targets), dict(counter)))
            results, stats = scan(
                targets,
                config,
                cancel=self.cancel,
                on_result=lambda r: self.queue.put(("result", r)),
                on_progress=lambda s: self.queue.put(("progress", s)),
            )
            urls = results_to_urls(results)
            write_urls(output_file, urls)
            self.queue.put(("done", (results, stats, output_file, len(urls))))
        except Exception as exc:  # 后台异常必须回传，不然界面会一直卡在扫描中
            self.queue.put(("error", f"{exc.__class__.__name__}: {exc}"))

    def _cancel_scan(self, _event=None) -> None:
        """没有停止按钮了，改由 Esc / 关闭窗口触发。"""
        if self.worker is not None and self.worker.is_alive() and not self.cancel.is_set():
            self.cancel.set()
            self.status_var.set("正在停止（等待在途请求返回）…")
            self.log("已请求停止，等待在途请求收尾…")

    def open_output_dir(self) -> None:
        target = self.output_path.get().strip()
        if target:
            open_in_explorer(Path(target))
        elif self.input_var.get().strip():
            open_in_explorer(Path(self.input_var.get().strip()))

    def export_csv(self) -> None:
        if not self.results:
            messagebox.showinfo("提示", "还没有结果")
            return
        base = self._default_output() or Path("live_urls")
        default = str(base.with_suffix(".csv"))
        filename = filedialog.asksaveasfilename(
            title="导出明细 CSV", defaultextension=".csv", initialfile=Path(default).name
        )
        if not filename:
            return
        rows = self.results
        self.log(f"正在导出 CSV（{len(rows)} 行）…")

        def worker() -> None:
            try:
                count = write_csv(filename, rows)
                self.queue.put(("csv", True, f"已导出 {count} 行：{filename}"))
            except OSError as exc:
                self.queue.put(("csv", False, f"导出失败：{exc}"))

        threading.Thread(target=worker, daemon=True, name="csv").start()

    def copy_urls(self) -> None:
        selection = self.tree.selection()
        if selection:
            urls = [self.tree.set(item, "url") for item in selection]
        else:
            urls = results_to_urls(self.results)
        urls = [u for u in urls if u]
        if not urls:
            messagebox.showinfo("提示", "没有可复制的 URL")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(urls))
        self.log(f"已复制 {len(urls)} 条 URL 到剪贴板")

    # ---------------------------------------------------------------- pump
    def _pump(self) -> None:
        try:
            self._pump_tick()
            self.root.after(PUMP_INTERVAL_MS, self._pump)
        except tk.TclError:
            return  # 窗口已经关了，别再往事件循环里塞回调

    def _pump_tick(self) -> None:
        """主线程消费队列。每次最多占用 12ms，保证拖动窗口/点击不卡。"""
        deadline = time.perf_counter() + PUMP_BUDGET
        latest_progress: ScanStats | None = None
        finished = False

        while True:
            try:
                message = self.queue.get_nowait()
            except queue.Empty:
                break
            kind = message[0]
            if kind == "result":
                self._stage_result(message[1])
            elif kind == "progress":
                latest_progress = message[1]
            elif kind == "done":
                self._flush(force=True)
                finished = True
                self._finish(*message[1])
                break
            elif kind == "error":
                self._flush(force=True)
                finished = True
                self._fail(message[1])
                break
            elif kind == "targets":
                self._on_targets(message[1], message[2])
            elif kind == "reading":
                self.status_var.set(f"读取文件… 已解析 {message[1]} 个目标")
            elif kind == "empty":
                self._on_empty(message[1])
                finished = True
                break
            elif kind == "csv":
                ok, text = message[1], message[2]
                self.log(text)
                (messagebox.showinfo if ok else messagebox.showerror)(
                    "导出成功" if ok else "导出失败", text
                )
            if time.perf_counter() >= deadline:
                break

        self._flush()
        # 同一批次里已经结束时，不能用滞后的进度覆盖最终状态
        if latest_progress is not None and not finished:
            self._apply_progress(latest_progress)

    def _flush(self, force: bool = False) -> None:
        """把暂存的结果/日志批量落到控件上，每轮限量自适应，剩下的下一轮继续。

        为什么要自适应：扫描时几十个探测线程在抢 GIL，主线程每调一次 Tk 的
        代价会被放大一个数量级（实测 0.008ms -> 0.15ms/行）。固定批量要么在
        空闲时太保守，要么在有负载时一轮就顶住几百毫秒，所以按实测耗时调。
        """
        backlog = self._row_backlog
        if backlog:
            take = len(backlog) if force else min(len(backlog), self._row_batch)
            started = time.perf_counter()
            for values, tag in backlog[:take]:
                self.tree.insert("", tk.END, values=values, tags=(tag,))
            del backlog[:take]
            if not force and take >= self._row_batch:
                spent = time.perf_counter() - started
                if spent > ROW_FLUSH_TARGET:
                    self._row_batch = max(ROW_BATCH_MIN, self._row_batch // 2)
                elif spent < ROW_FLUSH_TARGET / 3:
                    self._row_batch = min(ROW_BATCH_MAX, self._row_batch * 2)

        logs = self._log_backlog
        if logs:
            take = len(logs) if force else min(len(logs), self._log_batch)
            started = time.perf_counter()
            self.log_view.append_many(logs[:take])
            del logs[:take]
            if not force and take >= self._log_batch:
                spent = time.perf_counter() - started
                if spent > LOG_FLUSH_TARGET:
                    self._log_batch = max(LOG_BATCH_MIN, self._log_batch // 2)
                elif spent < LOG_FLUSH_TARGET / 3:
                    self._log_batch = min(LOG_BATCH_MAX, self._log_batch * 2)

    def _log(self, line: str) -> None:
        fringe = self._log_backlog
        fringe.append(line)
        if len(fringe) > LOG_BACKLOG_MAX:
            del fringe[: len(fringe) - LOG_BACKLOG_MAX]

    def _stage_result(self, result: ProbeResult) -> None:
        """只做最便宜的取值和拼接，真正的控件操作留到 _flush。"""
        alive = result.alive
        status = "-" if result.status is None else str(result.status)
        # 纯超时/DNS 失败的行不塞进表格（几万行会卡），但会保留在 CSV / 日志里。
        # 存活行和非存活行分开限额，避免一堆 404 把存活的挤出去。
        room = False
        if alive:
            room = self._alive_rows < MAX_TREE_ROWS
        elif result.status is not None:
            room = self._dead_rows < MAX_DEAD_ROWS
        if room:
            scheme = (result.url or "").split("://", 1)[0] if result.url else ""
            tag = "alive" if alive else ("denied" if result.status else "dead")
            self._row_backlog.append(
                (
                    (
                        result.target.hostport,
                        scheme,
                        status,
                        (result.server or "")[:40],
                        result.url or "",
                        f"{result.elapsed:.2f}s",
                    ),
                    tag,
                )
            )
            self._tree_rows += 1
            if alive:
                self._alive_rows += 1
                if self._alive_rows == MAX_TREE_ROWS:
                    self._log(f"存活行已达 {MAX_TREE_ROWS} 条上限，CSV 里是全量")
            else:
                self._dead_rows += 1
                if self._dead_rows == MAX_DEAD_ROWS:
                    self._log(f"非存活行已达 {MAX_DEAD_ROWS} 条上限，CSV 里是全量")

        if alive:
            self._log(f"存活 {status} {result.url} ({result.elapsed:.2f}s)")
        elif result.note == "abandoned":
            # 这一条看得见，才能解释为什么“17/18”突然结束了
            self._log(f"放弃 {result.target}（{result.error or ''}）")
        elif self._verbose_log:
            if result.status is not None:
                self._log(f"不命中 {status} {result.target}（{result.error or ''}）")
            elif not self.cancel.is_set():
                self._log(f"无响应 {result.target}（{result.error or ''}）")

    def _on_targets(self, total: int, counter: dict) -> None:
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=max(total, 1))
        self.progress_var.set(0)
        self.status_var.set(f"探测中 0/{total}…（Esc 可停止）")
        self.log(
            f"目标 {total} 个（读入 {counter.get('lines', 0)} 行，"
            f"编码 {counter.get('encoding', '?')}，"
            f"跳过脏行 {counter.get('skipped', 0)}，"
            f"重复 {counter.get('duplicates', 0)}），开始探测…"
        )

    def _on_empty(self, counter: dict) -> None:
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self._set_running(False)
        self.worker = None
        self.status_var.set("输入文件里没有可解析的目标")
        lines = counter.get("lines", 0)
        encoding = counter.get("encoding", "?")
        self.log(
            f"没有可解析的目标（读入 {lines} 行，编码 {encoding}，"
            f"跳过脏行 {counter.get('skipped', 0)}）"
        )
        message = chr(10).join(
            [
                f"读入 {lines} 行，编码按 {encoding} 解码，跳过脏行 {counter.get('skipped', 0)}。",
                "",
                "每行应该是：a.example.com 或 a.example.com:8443。",
                "如果所有行都被判脏，多半是编码或内容不对；读入 0 行说明文件不是文本列表。",
            ]
        )
        messagebox.showwarning("没有可解析的目标", message)

    def _apply_progress(self, stats: ScanStats) -> None:
        now = time.monotonic()
        if stats.done < stats.total and now - self._last_progress_at < 0.1:
            return
        self._last_progress_at = now
        if self.stats is None or stats.done >= self.stats.done:
            self.stats = stats
        self.progress_var.set(stats.done)
        percent = (stats.done / stats.total * 100) if stats.total else 0
        status = (
            f"{stats.done}/{stats.total}（{percent:.1f}%）｜存活 {stats.alive}"
            f"｜{stats.speed:.1f} 个/秒｜已用时 {stats.elapsed:.0f}s"
        )
        if stats.pending:
            status += f"｜在途 {stats.pending}"
            if stats.done + stats.pending >= stats.total:
                status += f"（收尾中，卡住的最多等 {HARD_DEADLINE:.0f}s 自动放弃）"
        self.status_var.set(status)
        if self._verbose_log:
            return
        if now - self._last_summary_at >= 2.0:
            self._last_summary_at = now
            self.log(
                f"进度 {stats.done}/{stats.total}｜存活 {stats.alive}｜"
                f"{stats.speed:.0f} 个/秒｜{stats.elapsed:.0f}s"
            )

    def _finish(
        self,
        results: list[ProbeResult],
        stats: ScanStats,
        output_file: str,
        url_count: int,
    ) -> None:
        self.results = results
        self.stats = stats
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=max(stats.total, 1))
        self._set_running(False)
        self.progress_var.set(stats.done)
        self.status_var.set(
            f"{'已停止' if stats.cancelled else '完成'}："
            f"目标 {stats.total}，存活 {stats.alive}，去重后 {url_count} 条"
        )
        self.log(
            f"{'扫描已停止' if stats.cancelled else '扫描完成'}："
            f"探测 {stats.done}/{stats.total}，存活 {stats.alive}，"
            f"去重后 {url_count} 条，用时 {stats.elapsed:.1f}s"
        )
        self.log(f"结果已写入 {output_file}")
        if stats.abandoned:
            self.log(
                f"有 {stats.abandoned} 个目标超过 {HARD_DEADLINE:.0f}s 未返回（多为 DNS 解析卡住），"
                f"已放弃并记为失败；要救它们就提高超时或用 --retries 重跑"
            )
        if not stats.cancelled:
            messagebox.showinfo(
                "完成",
                f"目标：{stats.total}\n"
                f"存活：{stats.alive}\n"
                f"去重后：{url_count}\n"
                f"用时：{stats.elapsed:.1f}s\n\n"
                f"结果文件：{output_file}",
            )
        self.worker = None

    def _fail(self, message: str) -> None:
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self._set_running(False)
        self.status_var.set("出错了")
        self.log(f"错误：{message}")
        self.worker = None
        messagebox.showerror("错误", message)


def run_gui() -> None:
    enable_dpi_awareness()
    try:  # 装了 tkinterdnd2 就能把文件直接拖进窗口
        from tkinterdnd2 import TkinterDnD

        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    # 高 DPI 屏幕上 Tk 默认按 96 DPI 缩放，这里按真实 DPI 修正，避免字体糊/过小
    try:
        root.tk.call("tk", "scaling", root.winfo_fpixels("1i") / 72.0)
    except tk.TclError:
        pass
    App(root)
    root.mainloop()
