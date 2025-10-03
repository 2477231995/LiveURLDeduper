import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3

# 忽略 https 证书警告
urllib3.disable_warnings()

class SubdomainProcessorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Author: gucheNg,Github: https://github.com/2477231995")
        self.root.geometry("700x600")
        self.root.resizable(True, True)

        # 样式设置
        self.style = ttk.Style()
        self.style.configure("TButton", font=("微软雅黑", 10))
        self.style.configure("TLabel", font=("微软雅黑", 10))
        self.style.configure("Header.TLabel", font=("微软雅黑", 14, "bold"))

        # 主框架
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题
        ttk.Label(
            self.main_frame,
            text="子域名存活检测、URL去重工具",
            style="Header.TLabel"
        ).pack(pady=(0, 20))

        # 1. 输入文件选择
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self.input_frame, text="选择子域名文件:").pack(side=tk.LEFT, padx=(0, 10))
        self.input_path_var = tk.StringVar()
        ttk.Entry(
            self.input_frame,
            textvariable=self.input_path_var,
            width=60
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(
            self.input_frame,
            text="浏览...",
            command=self.select_input_file
        ).pack(side=tk.RIGHT)

        # 2. 检测线程数
        self.thread_frame = ttk.Frame(self.main_frame)
        self.thread_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(self.thread_frame, text="检测线程数:").pack(side=tk.LEFT, padx=(0, 10))
        self.thread_count_var = tk.IntVar(value=30)
        ttk.Combobox(
            self.thread_frame,
            textvariable=self.thread_count_var,
            values=[10, 30, 50, 100],
            width=5,
            state="readonly"
        ).pack(side=tk.LEFT)
        ttk.Label(
            self.thread_frame,
            text="(线程越多越快，可能被目标限制)"
        ).pack(side=tk.LEFT, padx=(5, 0))

        # 3. 代理设置
        self.proxy_frame = ttk.LabelFrame(self.main_frame, text="代理设置(不设置也行)", padding="10")
        self.proxy_frame.pack(fill=tk.X, pady=(0, 20))

        # 3.1 代理协议
        ttk.Label(self.proxy_frame, text="代理协议:").pack(side=tk.LEFT, padx=(0, 10))
        self.proxy_protocol_var = tk.StringVar(value="http")
        ttk.Combobox(
            self.proxy_frame,
            textvariable=self.proxy_protocol_var,
            values=["http", "https", "socks5"],
            width=8,
            state="readonly"
        ).pack(side=tk.LEFT, padx=(0, 20))

        # 3.2 代理IP
        ttk.Label(self.proxy_frame, text="代理IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.proxy_ip_var = tk.StringVar()
        ttk.Entry(
            self.proxy_frame,
            textvariable=self.proxy_ip_var,
            width=15
        ).pack(side=tk.LEFT, padx=(0, 10))

        # 3.3 代理端口
        ttk.Label(self.proxy_frame, text="端口:").pack(side=tk.LEFT, padx=(0, 5))
        self.proxy_port_var = tk.StringVar()
        ttk.Entry(
            self.proxy_frame,
            textvariable=self.proxy_port_var,
            width=6
        ).pack(side=tk.LEFT, padx=(0, 20))

        # 3.4 测试代理按钮
        self.test_proxy_btn = ttk.Button(
            self.proxy_frame,
            text="测试代理",
            command=self.test_proxy
        )
        self.test_proxy_btn.pack(side=tk.LEFT)

        # 4. 开始处理按钮
        self.process_btn = ttk.Button(
            self.main_frame,
            text="开始处理",
            command=self.start_processing
        )
        self.process_btn.pack(pady=(0, 20))

        # 5. 进度条
        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, expand=True)

        # 6. 状态标签
        self.status_var = tk.StringVar(value="就绪：请选择输入文件")
        ttk.Label(
            self.main_frame,
            textvariable=self.status_var
        ).pack(anchor=tk.W, pady=(0, 10))

        # 7. 日志区域
        ttk.Label(self.main_frame, text="处理日志:").pack(anchor=tk.W, pady=(10, 5))
        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            self.log_frame,
            height=10,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bg="#f8f8f8"
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(
            self.log_frame,
            command=self.log_text.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        # 8. 底部提示
        ttk.Label(
            self.main_frame,
            text="提示: 检测完成后自动去重，结果保存为 live_urls.txt",
            foreground="gray",
            font=("微软雅黑", 9)
        ).pack(side=tk.BOTTOM, pady=10)

    def select_input_file(self):
        """选择输入文件"""
        filename = filedialog.askopenfilename(
            title="选择子域名输入文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=os.getcwd()
        )
        if filename:
            self.input_path_var.set(filename)
            self.status_var.set(f"就绪：已选文件 - {os.path.basename(filename)}")

    def test_proxy(self):
        """测试代理"""
        protocol = self.proxy_protocol_var.get()
        ip = self.proxy_ip_var.get().strip()
        port = self.proxy_port_var.get().strip()

        if not ip or not port:
            messagebox.showwarning("提示", "请输入代理IP和端口！")
            return
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字！")
            return

        proxy = None
        if protocol in ["http", "https"]:
            proxy = {protocol: f"{protocol}://{ip}:{port}"}
        elif protocol == "socks5":
            proxy = {"http": f"socks5://{ip}:{port}", "https": f"socks5://{ip}:{port}"}
        self.log(f"开始测试代理：{proxy}")

        try:
            response = requests.get("https://www.baidu.com", proxies=proxy, timeout=8, verify=False)
            if response.status_code == 200:
                messagebox.showinfo("成功", "代理测试通过！可访问百度")
            else:
                messagebox.showwarning("警告", "代理测试失败")
        except Exception as e:
            self.log(f"代理错误：{e}")
            messagebox.showwarning("警告", f"代理不可用：{e}")

    def log(self, message):
        """添加带时间戳的日志"""
        self.log_text.config(state=tk.NORMAL)
        import time
        current_time = time.strftime("%H:%M:%S", time.localtime())
        self.log_text.insert(tk.END, f"[{current_time}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_progress(self, value):
        self.progress_var.set(min(value, 100))
        self.root.update_idletasks()

    def update_status(self, status):
        self.status_var.set(status)
        self.root.update_idletasks()

    def check_subdomain(self, subdomain, proxy=None):
        """检测子域名存活，返回带协议 URL"""
        headers = {"User-Agent": "Mozilla/5.0"}
        test_urls = [f"https://{subdomain}", f"http://{subdomain}"]
        for url in test_urls:
            try:
                response = requests.get(
                    url,
                    proxies=proxy,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                    verify=False
                )
                if response.status_code in [200, 301, 302]:
                    return url
            except:
                continue
        return None

    def normalize_url(self, url):
        """解析 URL 并返回三元组：协议、主机、端口"""
        parsed = urlparse(url.strip())
        scheme = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        return scheme, host, port

    def deduplicate_urls(self, urls):
        """URL 去重，https 优先"""
        http_entries = {}
        for url in urls:
            scheme, host, port = self.normalize_url(url)
            key = (host, port)
            if scheme == "https":
                http_entries[key] = url
            elif key not in http_entries:
                http_entries[key] = url
        return list(http_entries.values())

    def process_subdomains(self):
        """核心处理逻辑"""
        input_file = self.input_path_var.get().strip()

        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("错误", "请选择有效输入文件！")
            self.process_btn.config(state=tk.NORMAL)
            return

        input_dir = os.path.dirname(input_file)
        output_file = os.path.join(input_dir, "live_urls.txt")

        proxy = None
        ip = self.proxy_ip_var.get().strip()
        port = self.proxy_port_var.get().strip()
        if ip and port:
            try:
                protocol = self.proxy_protocol_var.get()
                if protocol in ["http", "https"]:
                    proxy = {protocol: f"{protocol}://{ip}:{int(port)}"}
                elif protocol == "socks5":
                    proxy = {"http": f"socks5://{ip}:{int(port)}", "https": f"socks5://{ip}:{int(port)}"}
            except ValueError:
                messagebox.showerror("错误", "端口必须是数字！")
                self.process_btn.config(state=tk.NORMAL)
                return

        try:
            self.update_status("读取子域名...")
            self.update_progress(10)
            with open(input_file, 'r', encoding='utf-8') as f:
                subdomains = list(set([line.strip() for line in f if line.strip()]))

            total = len(subdomains)
            if total == 0:
                messagebox.showwarning("提示", "输入文件无有效子域名！")
                self.process_btn.config(state=tk.NORMAL)
                return
            self.log(f"读取到 {total} 个唯一子域名")

            self.update_status("检测存活状态...")
            self.update_progress(20)
            surviving_urls = []
            thread_count = self.thread_count_var.get()

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {executor.submit(self.check_subdomain, s, proxy): s for s in subdomains}
                completed = 0
                for future in as_completed(futures):
                    url = future.result()
                    completed += 1
                    self.update_progress(20 + 60 * (completed / total))
                    if url:
                        surviving_urls.append(url)
                        self.log(f"存活：{url}")
                    else:
                        self.log(f"不存活：{futures[future]}")

            self.update_status("去重并保存结果...")
            self.update_progress(90)
            deduped_urls = self.deduplicate_urls(surviving_urls)
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in sorted(deduped_urls):
                    f.write(url + '\n')

            self.update_progress(100)
            self.update_status("处理完成！")
            self.log(f"处理结束：{len(deduped_urls)} 个有效 URL")
            self.log(f"结果保存到：{output_file}")

            messagebox.showinfo(
                "处理完成",
                f"✅ 检测 {total} 个子域名\n"
                f"✅ 存活 {len(surviving_urls)} 个\n"
                f"✅ 去重后 {len(deduped_urls)} 个\n"
                f"✅ 结果文件：{os.path.basename(output_file)}\n"
                f"✅ 路径：{output_file}"
            )

        except Exception as e:
            self.log(f"处理过程中出错：{e}")
            messagebox.showerror("错误", f"处理过程中出错：{e}")
            self.process_btn.config(state=tk.NORMAL)

    def start_processing(self):
        self.process_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.process_subdomains, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainProcessorApp(root)
    root.mainloop()
