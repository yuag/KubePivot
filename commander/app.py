"""K8s Commander 主窗口。"""
import base64
import datetime
import json
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import time
import traceback
import tkinter as tk
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, scrolledtext, ttk

from commander.ai_fetcher import AIModelFetcher
from commander.ai_providers import AI_PROVIDERS, AI_SYSTEM_PROMPT
from commander.commands import COMMANDS, COMMAND_GROUPS, CATEGORY_INDEX
from commander.config import (
    ACCENT, APP_ROOT, APP_VERSION, BG, BG2, BG3, BORDER, CARD, CONFIG_DIR, CONFIG_PATH,
    DATA_DIR, LOG_PATH, REPORTS_DIR, SA_CA_PATH, SA_NS_PATH, SA_TOKEN_PATH,
    CYAN, DANGER, GREEN, HOVER, SUCCESS, TEXT, TEXT2, WARN, logger,
    ensure_data_dirs, migrate_legacy_config,
)
from commander.env_analyzer import EnvVarAnalyzer
from commander.env_detector import EnvironmentDetector
from commander import proxy_audit
from commander import socks_proxy
from commander.rbac_auditor import RBACAuditor, format_report_markdown, format_report_text
from commander.rbac_graph import build_attack_graph_svg
from commander import pod_shell

class K8sCommander(tk.Tk):
    def __init__(self):
        ensure_data_dirs()
        migrate_legacy_config()
        super().__init__()
        self.title(f"KubePivot  {APP_VERSION} — 容器渗透测试工具")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self.report_callback_exception = self._tk_callback_exception

        self.mode_var = tk.StringVar(value="curl")
        self.apiserver_var = tk.StringVar(value="https://kubernetes.default.svc:443")
        self.token_var = tk.StringVar()
        self.ns_var = tk.StringVar(value="default")
        self.cacert_var = tk.StringVar(value="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        self.skip_tls_var = tk.BooleanVar(value=False)
        self.role_name_var = tk.StringVar(value="my-role")
        self.configmap_var = tk.StringVar(value="kube-root-ca.crt")
        self.node_ip_var = tk.StringVar(value="127.0.0.1")
        self.pod_var = tk.StringVar(value="my-pod")
        self.container_var = tk.StringVar(value="")
        self.secret_var = tk.StringVar(value="my-secret")
        self.service_var = tk.StringVar(value="my-service")
        self.deployment_var = tk.StringVar(value="my-deployment")
        self.node_var = tk.StringVar(value="my-node")
        self.local_port_var = tk.StringVar(value="8080")
        self.remote_port_var = tk.StringVar(value="80")

        self.group_var = tk.StringVar(value="K8s")
        self.category_var = tk.StringVar()
        self.search_var = tk.StringVar()

        self.current_selected_cmd = None
        self._cmd_list_data = []
        self._debounce_id = None
        self._env_debounce_id = None
        self._executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="k8scmd")
        self._busy = False
        self._ai_busy = False
        self._last_ai_raw_data = ""

        self.ai_provider_var = tk.StringVar(value="DeepSeek")
        self.ai_api_key_var = tk.StringVar(value="")
        self.ai_base_url_var = tk.StringVar(value=AI_PROVIDERS["DeepSeek"]["base_url"])
        self.ai_model_var = tk.StringVar(value=AI_PROVIDERS["DeepSeek"]["model"])
        self.ai_format_var = tk.StringVar(value="openai")
        self.ai_auto_save_var = tk.BooleanVar(value=False)
        self._ai_models_cache = {}
        self._ai_models_fetch_gen = 0
        self._rbac_busy = False
        self._last_rbac_result = None
        self._last_rbac_report = ""
        self._pod_shell_entries = []
        self._pod_shell_busy = False

        self.proxy_enabled_var = tk.BooleanVar(value=False)
        self.proxy_host_var = tk.StringVar(value="127.0.0.1")
        self.proxy_port_var = tk.StringVar(value="1080")
        self.proxy_user_var = tk.StringVar(value="")
        self.proxy_pass_var = tk.StringVar(value="")
        self.proxy_test_url_var = tk.StringVar(value="")

        self._init_styles()
        self._build_ui()
        self.token_var.trace_add("write", lambda *_: self._update_token_panel())
        self._load_config()
        self._update_token_panel()
        self._update_status_bar(f"数据目录: {DATA_DIR}")

        for var in [self.apiserver_var, self.token_var, self.ns_var, self.cacert_var,
                    self.role_name_var, self.configmap_var, self.node_ip_var, self.pod_var,
                    self.container_var, self.secret_var, self.service_var, self.deployment_var,
                    self.node_var, self.local_port_var, self.remote_port_var]:
            var.trace_add("write", lambda *_: self._update_cmd_preview())
        self.skip_tls_var.trace_add("write", lambda *_: self._update_cmd_preview())
        self.mode_var.trace_add("write", lambda *_: self._on_mode_change())

    def _init_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, bordercolor=BORDER)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=TEXT2, padding=[12, 6])
        style.map("TNotebook.Tab", background=[("selected", BG3)], foreground=[("selected", ACCENT)])
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TLabelframe", background=BG, foreground=TEXT2, bordercolor=BORDER, padding=8)
        style.configure("TLabelframe.Label", background=BG, foreground=ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("TRadiobutton", background=BG, foreground=TEXT)
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.configure("TEntry", fieldbackground=BG3, foreground=TEXT, insertcolor=TEXT, bordercolor=BORDER)
        style.map("TEntry", fieldbackground=[("readonly", BG3), ("disabled", BG2)], foreground=[("readonly", TEXT)])
        style.configure("TButton", background=BG3, foreground=TEXT, padding=5)
        style.map("TButton", background=[("active", HOVER)])
        style.configure("Treeview", background=BG2, foreground=TEXT, fieldbackground=BG2, bordercolor=BORDER)
        style.configure("Treeview.Heading", background=BG3, foreground=TEXT2)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])
        style.configure(
            "Sidebar.TCombobox",
            fieldbackground=BG3,
            background=BG3,
            foreground=TEXT,
            arrowcolor=TEXT,
            bordercolor=BORDER,
            lightcolor=BG3,
            darkcolor=BORDER,
            insertcolor=TEXT,
        )
        style.map(
            "Sidebar.TCombobox",
            fieldbackground=[("readonly", BG3), ("disabled", BG2)],
            foreground=[("readonly", TEXT), ("disabled", TEXT2)],
            selectbackground=[("readonly", BG3)],
            selectforeground=[("readonly", TEXT)],
            background=[("readonly", BG3), ("active", HOVER)],
            arrowcolor=[("readonly", TEXT), ("disabled", TEXT2)],
        )
        # 下拉列表（弹出层）颜色
        self.option_add("*TCombobox*Listbox.background", BG2)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    @staticmethod
    def _fix_readonly_combobox(cb):
        """Windows 下 readonly Combobox 内部 Entry 需单独设色，否则白字白底看不见。"""
        def apply():
            try:
                cb.configure(style="Sidebar.TCombobox")
            except tk.TclError:
                pass
            for child in cb.winfo_children():
                if child.winfo_class() == "Entry":
                    child.configure(
                        background=BG3,
                        foreground=TEXT,
                        readonlybackground=BG3,
                        disabledbackground=BG3,
                        disabledforeground=TEXT,
                        insertbackground=TEXT,
                    )
        cb.after_idle(apply)
        cb.bind("<Map>", lambda _e: apply(), add="+")

    @staticmethod
    def _dark_entry(parent, textvariable, **kwargs):
        defaults = dict(
            bg=BG3, fg=TEXT, insertbackground=TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        defaults.update(kwargs)
        return tk.Entry(parent, textvariable=textvariable, **defaults)

    @staticmethod
    def _dark_scrolled_text(parent, **kwargs):
        defaults = dict(
            bg=BG2, fg=TEXT, insertbackground=TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
            font=("Consolas", 9),
        )
        defaults.update(kwargs)
        box = scrolledtext.ScrolledText(parent, **defaults)
        try:
            box.vbar.configure(bg=BG3, troughcolor=BG, activebackground=ACCENT, highlightthickness=0)
        except tk.TclError:
            pass
        return box

    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_env = tk.Frame(self.notebook, bg=BG)
        self.tab_cmd = tk.Frame(self.notebook, bg=BG)
        self.tab_resources = tk.Frame(self.notebook, bg=BG)
        self.tab_pod_shell = tk.Frame(self.notebook, bg=BG)
        self.tab_ai = tk.Frame(self.notebook, bg=BG)
        self.tab_proxy = tk.Frame(self.notebook, bg=BG)
        self.tab_rbac = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_env, text="  环境识别  ")
        self.notebook.add(self.tab_cmd, text="  基础 命令  ")
        self.notebook.add(self.tab_resources, text="  资源浏览  ")
        self.notebook.add(self.tab_pod_shell, text="  Pod 终端  ")
        self.notebook.add(self.tab_rbac, text="  RBAC 审计  ")
        self.notebook.add(self.tab_ai, text="  AI 安全专家  ")
        self.notebook.add(self.tab_proxy, text="  SOCKS5 代理  ")

        self._build_env_tab()
        self._build_cmd_tab()
        self._build_resource_tab()
        self._build_pod_shell_tab()
        self._build_rbac_tab()
        self._build_ai_tab()
        self._build_proxy_tab()
        self._build_statusbar()
        self._init_command_nav()
        self.notebook.bind("<<NotebookTabChanged>>", self._on_notebook_tab_changed)

        self.protocol("WM_DELETE_WINDOW", self._save_config_and_exit)

    def _build_statusbar(self):
        self.status_bar = tk.Frame(self, bg=BG3, height=24)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_mode = tk.Label(self.status_bar, text="[模式: curl]", bg=BG3, fg=GREEN, font=("Segoe UI", 9))
        self.status_mode.pack(side=tk.LEFT, padx=10)
        self.status_info = tk.Label(self.status_bar, text="就绪", bg=BG3, fg=TEXT2, font=("Segoe UI", 9))
        self.status_info.pack(side=tk.LEFT, padx=10)

    def _build_env_tab(self):
        paned = tk.PanedWindow(self.tab_env, orient=tk.HORIZONTAL, bg=BORDER, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = tk.Frame(paned, bg=BG, width=420)
        left.pack_propagate(False)
        tk.Label(left, text="粘贴环境变量 (KEY=value)", bg=BG, fg=TEXT2, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 4))
        self.env_text = scrolledtext.ScrolledText(left, bg=BG2, fg=TEXT, insertbackground=TEXT, font=("Consolas", 9), height=20)
        self.env_text.pack(fill=tk.BOTH, expand=True)
        self.env_text.bind("<<Paste>>", lambda e: self.after(100, self._schedule_env_analyze_confirm))
        self.env_text.bind("<Control-v>", lambda e: self.after(100, self._schedule_env_analyze_confirm))
        self.env_text.bind("<Control-V>", lambda e: self.after(100, self._schedule_env_analyze_confirm))
        # 不在 KeyRelease 时自动分析，避免覆盖「确认跳转」逻辑

        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill=tk.X, pady=6)
        ttk.Button(btn_row, text="识别环境", command=self._analyze_env_with_confirm).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="清空", command=self._clear_env).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="本机 env", command=self._load_local_env).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="K8s探测", command=self._probe_k8s_env).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="经 SOCKS 探测", command=self._run_proxy_audit).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="一键体检", command=self._run_full_audit).pack(side=tk.LEFT, padx=2)
        paned.add(left)

        right = tk.Frame(paned, bg=BG)
        self.verdict_card = tk.Frame(right, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        self.verdict_card.pack(fill=tk.X, pady=(0, 8), padx=4, ipady=8)
        tk.Label(self.verdict_card, text="环境判定", bg=CARD, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor=tk.W, padx=12, pady=(8, 0))
        self.verdict_lbl = tk.Label(self.verdict_card, text="等待输入…", bg=CARD, fg=ACCENT, font=("Segoe UI", 14, "bold"))
        self.verdict_lbl.pack(anchor=tk.W, padx=12, pady=8)

        self.nav_confirm_card = tk.Frame(right, bg=CARD, highlightbackground=ACCENT, highlightthickness=1)
        self.nav_confirm_lbl = tk.Label(
            self.nav_confirm_card, text="", bg=CARD, fg=TEXT, font=("Segoe UI", 10), justify=tk.LEFT, wraplength=520
        )
        self.nav_confirm_lbl.pack(anchor=tk.W, padx=12, pady=(10, 4))
        nav_btn_row = tk.Frame(self.nav_confirm_card, bg=CARD)
        nav_btn_row.pack(anchor=tk.W, padx=12, pady=(0, 10))
        self.nav_confirm_yes = ttk.Button(nav_btn_row, text="是，跳转", command=self._nav_confirm_yes)
        self.nav_confirm_yes.pack(side=tk.LEFT, padx=(0, 6))
        self.nav_confirm_no = ttk.Button(nav_btn_row, text="否，留在此页", command=self._nav_confirm_no)
        self.nav_confirm_no.pack(side=tk.LEFT)
        self._pending_nav = None

        tk.Label(right, text="详细报告", bg=BG, fg=TEXT2, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=4)
        self.env_report = scrolledtext.ScrolledText(right, bg=BG2, fg=TEXT, font=("Consolas", 9), height=22)
        self.env_report.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.env_report.tag_configure("sensitive", foreground=DANGER)
        self.env_report.tag_configure("cloud", foreground=CYAN)
        self.env_report.tag_configure("k8s", foreground=GREEN)
        self.env_report.tag_configure("warn", foreground=WARN)
        paned.add(right)

    def _build_resource_tab(self):
        bar = tk.Frame(self.tab_resources, bg=BG2)
        bar.pack(fill=tk.X)
        tk.Label(bar, text="Namespace → Pod → Container", bg=BG2, fg=TEXT2,
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=12, pady=8)
        ttk.Button(bar, text="刷新", command=self._refresh_resource_tree).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="填入 Pod 参数", command=self._apply_tree_selection).pack(side=tk.LEFT, padx=4)
        tk.Label(bar, text="双击 Pod 自动填充", bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=12)

        frame = tk.Frame(self.tab_resources, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.res_tree = ttk.Treeview(frame, columns=("type",), show="tree headings")
        self.res_tree.heading("#0", text="名称", anchor=tk.W)
        self.res_tree.heading("type", text="类型")
        self.res_tree.column("#0", width=360, minwidth=200)
        self.res_tree.column("type", width=100, anchor=tk.CENTER)
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.res_tree.yview)
        self.res_tree.configure(yscrollcommand=yscroll.set)
        self.res_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.res_tree.bind("<Double-1>", self._on_tree_double_click)
        self._res_tree_meta = {}

    def _build_pod_shell_tab(self):
        root = tk.PanedWindow(self.tab_pod_shell, orient=tk.HORIZONTAL, bg=BORDER, sashwidth=4)
        root.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = tk.Frame(root, bg=BG, width=420)
        left.pack_propagate(False)

        info = tk.Frame(left, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        info.pack(fill=tk.X, pady=(0, 6))
        info_inner = tk.Frame(info, bg=CARD)
        info_inner.pack(fill=tk.X, padx=10, pady=8)
        tk.Label(info_inner, text="目标 Pod", bg=CARD, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.pod_shell_target_lbl = tk.Label(
            info_inner, text="未选择", bg=CARD, fg=ACCENT, font=("Consolas", 10), wraplength=380, justify=tk.LEFT,
        )
        self.pod_shell_target_lbl.pack(anchor=tk.W, pady=(2, 6))
        ttk.Button(info_inner, text="从基础命令同步", command=self._pod_shell_sync_target).pack(anchor=tk.W, pady=2)
        tk.Label(
            info_inner,
            text="提示：资源浏览双击 Pod 也会自动跳转至此页",
            bg=CARD, fg=TEXT2, font=("Segoe UI", 8),
        ).pack(anchor=tk.W, pady=(4, 0))

        path_bar = tk.Frame(left, bg=BG)
        path_bar.pack(fill=tk.X, pady=4)
        tk.Label(path_bar, text="路径", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.pod_shell_path_var = tk.StringVar(value="/")
        tk.Entry(path_bar, textvariable=self.pod_shell_path_var, bg=BG3, fg=TEXT, width=28,
                 insertbackground=TEXT, relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        ttk.Button(path_bar, text="刷新", command=self._pod_shell_refresh_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(path_bar, text="上级", command=self._pod_shell_go_up).pack(side=tk.LEFT, padx=2)

        file_frame = tk.Frame(left, bg=BG)
        file_frame.pack(fill=tk.BOTH, expand=True)
        self.pod_shell_file_list = tk.Listbox(
            file_frame, bg=BG2, fg=TEXT, selectbackground=ACCENT, selectforeground="#fff",
            font=("Consolas", 9), activestyle="none", highlightthickness=0, bd=0,
        )
        file_scroll = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.pod_shell_file_list.yview)
        self.pod_shell_file_list.configure(yscrollcommand=file_scroll.set)
        self.pod_shell_file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.pod_shell_file_list.bind("<Double-1>", self._pod_shell_on_file_double)
        self.pod_shell_file_list.bind("<Return>", self._pod_shell_on_file_double)

        file_btn = tk.Frame(left, bg=BG)
        file_btn.pack(fill=tk.X, pady=6)
        ttk.Button(file_btn, text="查看文件", command=self._pod_shell_view_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_btn, text="下载到本机", command=self._pod_shell_download).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_btn, text="进入目录", command=self._pod_shell_enter_dir).pack(side=tk.LEFT, padx=2)

        root.add(left)

        right = tk.Frame(root, bg=BG)
        term_bar = tk.Frame(right, bg=BG2)
        term_bar.pack(fill=tk.X)
        tk.Label(term_bar, text="命令执行（非交互，不会卡住）", bg=BG2, fg=TEXT2,
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=8, pady=8)
        ttk.Button(term_bar, text="▶ 外部终端打开", command=self._pod_shell_open_external).pack(side=tk.RIGHT, padx=8)

        cmd_row = tk.Frame(right, bg=BG)
        cmd_row.pack(fill=tk.X, pady=4)
        tk.Label(cmd_row, text=">", bg=BG, fg=GREEN, font=("Consolas", 11, "bold")).pack(side=tk.LEFT, padx=(4, 0))
        self.pod_shell_cmd_var = tk.StringVar(value="ls -la /")
        cmd_entry = tk.Entry(cmd_row, textvariable=self.pod_shell_cmd_var, bg=BG3, fg=TEXT,
                             insertbackground=TEXT, relief=tk.FLAT, font=("Consolas", 10))
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        cmd_entry.bind("<Return>", lambda e: self._pod_shell_run_command())
        ttk.Button(cmd_row, text="执行", command=self._pod_shell_run_command).pack(side=tk.RIGHT, padx=4)

        tk.Label(right, text="输出 / 文件内容", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor=tk.W, padx=4)
        self.pod_shell_output = scrolledtext.ScrolledText(
            right, bg=BG2, fg=TEXT, font=("Consolas", 9), height=24, insertbackground=TEXT,
        )
        self.pod_shell_output.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.pod_shell_output.tag_configure("success", foreground=SUCCESS)
        self.pod_shell_output.tag_configure("danger", foreground=DANGER)
        self.pod_shell_output.tag_configure("accent", foreground=CYAN)
        root.add(right)

    def _on_notebook_tab_changed(self, _event=None):
        try:
            if self.notebook.select() == str(self.tab_pod_shell):
                self._pod_shell_sync_target()
        except tk.TclError:
            pass

    def _pod_shell_sync_target(self):
        ns = self.ns_var.get().strip() or "default"
        pod = self.pod_var.get().strip()
        container = self.container_var.get().strip()
        if container:
            text = f"{ns}/{pod}  (container: {container})"
        else:
            text = f"{ns}/{pod}" if pod else "未选择 Pod（请在基础命令填写，或资源浏览双击 Pod）"
        self.pod_shell_target_lbl.configure(text=text)

    def _pod_shell_get_target(self):
        ns = self.ns_var.get().strip() or "default"
        pod = self.pod_var.get().strip()
        container = self.container_var.get().strip() or None
        if not pod or pod == "my-pod":
            messagebox.showwarning(
                "Pod 终端",
                "请先指定 Pod：\n\n"
                "1. 资源浏览 → 刷新 → 双击 Pod\n"
                "2. 或在基础命令页把 Pod 改为真实名称（如 hacker-container）",
            )
            return None, None, None
        return ns, pod, container

    def _pod_shell_set_busy(self, busy, msg=None):
        self._pod_shell_busy = busy
        if msg:
            self._update_status_bar(msg, WARN if busy else TEXT2)

    def _pod_shell_append(self, text, tag=None):
        if tag:
            self.pod_shell_output.insert(tk.END, text, tag)
        else:
            self.pod_shell_output.insert(tk.END, text)
        self.pod_shell_output.see(tk.END)

    def _pod_shell_refresh_files(self):
        if self._pod_shell_busy:
            return
        target = self._pod_shell_get_target()
        if not target[0]:
            return
        ns, pod, container = target
        path = self.pod_shell_path_var.get().strip() or "/"
        self._pod_shell_set_busy(True, f"列出 {path} …")
        self._executor.submit(self._pod_shell_refresh_files_worker, ns, pod, container, path)

    def _pod_shell_refresh_files_worker(self, ns, pod, container, path):
        code, entries, err = pod_shell.list_dir(ns, pod, path, container)
        self.after(0, lambda: self._pod_shell_show_files(code, entries, err, path))

    def _pod_shell_show_files(self, code, entries, err, path):
        self.pod_shell_file_list.delete(0, tk.END)
        self._pod_shell_entries = entries
        if code != 0 and not entries:
            self._pod_shell_append(f"\n[-] 无法列出 {path}: {err}\n", "danger")
            self._pod_shell_set_busy(False, "列出目录失败")
            return
        for ent in entries:
            prefix = "[DIR] " if ent["kind"] == "dir" else "      "
            self.pod_shell_file_list.insert(tk.END, f"{prefix}{ent['name']}")
        self._pod_shell_append(f"\n[+] {path} — {len(entries)} 项\n", "success")
        self._pod_shell_set_busy(False, f"已刷新 {path}")

    def _pod_shell_selected_entry(self):
        sel = self.pod_shell_file_list.curselection()
        if not sel:
            messagebox.showinfo("Pod 终端", "请先在左侧列表选择文件或目录")
            return None
        idx = sel[0]
        if idx >= len(self._pod_shell_entries):
            return None
        return self._pod_shell_entries[idx]

    def _pod_shell_on_file_double(self, _event=None):
        ent = self._pod_shell_selected_entry()
        if not ent:
            return
        if ent["kind"] == "dir":
            self.pod_shell_path_var.set(ent["path"])
            self._pod_shell_refresh_files()
        else:
            self._pod_shell_view_file()

    def _pod_shell_go_up(self):
        cur = self.pod_shell_path_var.get().strip() or "/"
        self.pod_shell_path_var.set(pod_shell.parent_pod_path(cur))
        self._pod_shell_refresh_files()

    def _pod_shell_enter_dir(self):
        ent = self._pod_shell_selected_entry()
        if not ent:
            return
        if ent["kind"] != "dir":
            messagebox.showinfo("Pod 终端", "所选条目不是目录")
            return
        self.pod_shell_path_var.set(ent["path"])
        self._pod_shell_refresh_files()

    def _pod_shell_view_file(self):
        if self._pod_shell_busy:
            return
        target = self._pod_shell_get_target()
        if not target[0]:
            return
        ent = self._pod_shell_selected_entry()
        remote = ent["path"] if ent else self.pod_shell_path_var.get().strip()
        if ent and ent["kind"] == "dir":
            messagebox.showinfo("Pod 终端", "请选择文件，或双击目录进入")
            return
        ns, pod, container = target
        self._pod_shell_set_busy(True, "读取文件…")
        self._executor.submit(self._pod_shell_view_file_worker, ns, pod, container, remote)

    def _pod_shell_view_file_worker(self, ns, pod, container, remote):
        code, body, err = pod_shell.read_file(ns, pod, remote, container)
        self.after(0, lambda: self._pod_shell_show_file_content(remote, code, body, err))

    def _pod_shell_show_file_content(self, remote, code, body, err):
        self.pod_shell_output.delete("1.0", tk.END)
        if code != 0:
            self._pod_shell_append(f"[-] 读取失败 {remote}\n{err}\n", "danger")
        else:
            self._pod_shell_append(f"── {remote} ──\n", "accent")
            self._pod_shell_append(body if body.endswith("\n") else body + "\n")
        self._pod_shell_set_busy(False, "就绪")

    def _pod_shell_download(self):
        if self._pod_shell_busy:
            return
        target = self._pod_shell_get_target()
        if not target[0]:
            return
        ent = self._pod_shell_selected_entry()
        if not ent:
            messagebox.showinfo("Pod 终端", "请先选择要下载的文件或目录")
            return
        ns, pod, container = target
        remote = ent["path"]
        default_name = ent["name"]
        local = filedialog.asksaveasfilename(
            title="保存到本机",
            initialfile=default_name,
            defaultextension="",
        )
        if not local:
            return
        self._pod_shell_set_busy(True, "下载中…")
        self._executor.submit(self._pod_shell_download_worker, ns, pod, container, remote, local)

    def _pod_shell_download_worker(self, ns, pod, container, remote, local):
        code, msg, err = pod_shell.cp_from_pod(ns, pod, remote, local, container)
        self.after(0, lambda: self._pod_shell_download_done(remote, local, code, msg, err))

    def _pod_shell_download_done(self, remote, local, code, msg, err):
        if code == 0:
            self._pod_shell_append(f"\n[+] 已下载 {remote} → {local}\n", "success")
            self._update_status_bar(f"已下载到 {local}", SUCCESS)
        else:
            detail = err or msg or f"exit {code}"
            self._pod_shell_append(f"\n[-] 下载失败: {detail}\n", "danger")
            messagebox.showerror("下载失败", detail)
        self._pod_shell_set_busy(False)

    def _pod_shell_run_command(self):
        if self._pod_shell_busy:
            return
        target = self._pod_shell_get_target()
        if not target[0]:
            return
        cmd = self.pod_shell_cmd_var.get().strip()
        if not cmd:
            return
        ns, pod, container = target
        self._pod_shell_set_busy(True, "执行中…")
        self._executor.submit(self._pod_shell_run_command_worker, ns, pod, container, cmd)

    def _pod_shell_run_command_worker(self, ns, pod, container, cmd):
        code, out, err = pod_shell.exec_in_pod(ns, pod, cmd, container)
        self.after(0, lambda: self._pod_shell_show_command_result(cmd, code, out, err))

    def _pod_shell_show_command_result(self, cmd, code, out, err):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._pod_shell_append(f"\n[{ts}] $ {cmd}\n", "accent")
        if out:
            self._pod_shell_append(out if out.endswith("\n") else out + "\n")
        if err:
            self._pod_shell_append(err if err.endswith("\n") else err + "\n", "danger")
        if code != 0 and not out and not err:
            self._pod_shell_append(f"exit code {code}\n", "danger")
        self._pod_shell_set_busy(False, "就绪")

    def _pod_shell_open_external(self):
        target = self._pod_shell_get_target()
        if not target[0]:
            return
        ns, pod, container = target
        ok, msg = pod_shell.open_external_shell(ns, pod, container)
        if ok:
            self._update_status_bar(msg, SUCCESS)
            messagebox.showinfo(
                "外部终端",
                f"{msg}\n\n"
                f"Pod: {ns}/{pod}\n\n"
                "在新窗口中使用 /bin/sh 交互操作。\n"
                "若未弹出窗口，请在本机终端手动执行：\n"
                f"kubectl exec -it {pod} -n {ns} -- /bin/sh",
            )
        else:
            messagebox.showerror("外部终端", msg)

    def _build_rbac_tab(self):
        root = tk.PanedWindow(self.tab_rbac, orient=tk.HORIZONTAL, bg=BORDER, sashwidth=4)
        root.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = tk.Frame(root, bg=BG, width=300)
        left.pack_propagate(False)
        tk.Label(left, text="RBAC 权限评估", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0, 8))
        tk.Label(
            left,
            text="使用「基础命令」页的 API Server、Token、Namespace。\n"
                 "经 SOCKS5 时自动走代理（与 K8s API 一致）。",
            bg=BG, fg=TEXT2, font=("Segoe UI", 9), justify=tk.LEFT, wraplength=280,
        ).pack(anchor=tk.W, pady=(0, 12))

        info_card = tk.Frame(left, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        info_card.pack(fill=tk.X, pady=(0, 10))
        info_inner = tk.Frame(info_card, bg=CARD)
        info_inner.pack(fill=tk.X, padx=12, pady=10)
        tk.Label(info_inner, text="当前连接", bg=CARD, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.rbac_conn_lbl = tk.Label(
            info_inner, text="API / Token 未配置", bg=CARD, fg=TEXT,
            font=("Consolas", 8), justify=tk.LEFT, wraplength=260, anchor=tk.W,
        )
        self.rbac_conn_lbl.pack(fill=tk.X, pady=(4, 0))

        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill=tk.X, pady=4)
        ttk.Button(btn_row, text="刷新连接信息", command=self._rbac_refresh_conn_info).pack(fill=tk.X, pady=2)
        ttk.Button(btn_row, text="加载 SA", command=self._load_sa_token).pack(fill=tk.X, pady=2)
        self.rbac_run_btn = ttk.Button(btn_row, text="▶ 执行 RBAC 审计", command=self._run_rbac_audit)
        self.rbac_run_btn.pack(fill=tk.X, pady=2)

        tk.Label(left, text="进度", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(12, 4))
        self.rbac_progress = ttk.Progressbar(left, mode="determinate", maximum=100)
        self.rbac_progress.pack(fill=tk.X)
        self.rbac_progress_lbl = tk.Label(left, text="就绪", bg=BG, fg=TEXT2, font=("Segoe UI", 9))
        self.rbac_progress_lbl.pack(anchor=tk.W, pady=(4, 12))

        export_row = tk.Frame(left, bg=BG)
        export_row.pack(fill=tk.X, pady=4)
        ttk.Button(export_row, text="导出 Markdown", command=self._export_rbac_report).pack(fill=tk.X, pady=2)
        ttk.Button(export_row, text="复制报告", command=self._copy_rbac_report).pack(fill=tk.X, pady=2)
        ttk.Button(export_row, text="送去 AI 分析", command=self._send_rbac_to_ai).pack(fill=tk.X, pady=2)

        tk.Label(
            left,
            text="检测约 30+ 项权限 + 5 条提权链规则",
            bg=BG, fg=TEXT2, font=("Segoe UI", 8), wraplength=280, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(8, 0))

        root.add(left)

        right = tk.Frame(root, bg=BG)
        self.rbac_risk_lbl = tk.Label(
            right, text="风险评分: 未开始", bg=CARD, fg=ACCENT,
            font=("Segoe UI", 14, "bold"), anchor=tk.W, padx=12, pady=10,
        )
        self.rbac_risk_lbl.pack(fill=tk.X, padx=4, pady=(0, 8))

        right_paned = tk.PanedWindow(right, orient=tk.VERTICAL, bg=BORDER, sashwidth=3)
        right_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        perm_frame = tk.Frame(right_paned, bg=BG)
        tk.Label(perm_frame, text="权限清单", bg=BG, fg=TEXT2,
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=4)
        self.rbac_perm_txt = self._dark_scrolled_text(perm_frame, height=12)
        self.rbac_perm_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.rbac_perm_txt.tag_configure("critical", foreground=DANGER)
        self.rbac_perm_txt.tag_configure("high", foreground=WARN)
        self.rbac_perm_txt.tag_configure("medium", foreground=CYAN)
        self.rbac_perm_txt.tag_configure("low", foreground=SUCCESS)
        right_paned.add(perm_frame)

        chain_frame = tk.Frame(right_paned, bg=BG)
        tk.Label(chain_frame, text="提权链与 PoC", bg=BG, fg=TEXT2,
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=4)
        self.rbac_chain_txt = self._dark_scrolled_text(chain_frame, height=14)
        self.rbac_chain_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.rbac_chain_txt.tag_configure("poc", foreground=GREEN)
        right_paned.add(chain_frame)

        root.add(right)
        self.after(200, self._rbac_refresh_conn_info)

    def _rbac_refresh_conn_info(self):
        if not hasattr(self, "rbac_conn_lbl"):
            return
        api = self.apiserver_var.get().strip() or "(未填 API Server)"
        ns = self.ns_var.get().strip() or "default"
        token = self.token_var.get().strip()
        tok_hint = f"Token: {len(token)} 字符" if token else "Token: 未设置"
        proxy = socks_proxy.describe_status() if socks_proxy.is_enabled() else "代理: 未启用"
        tls = "跳过 TLS" if self.skip_tls_var.get() else "验证 TLS"
        self.rbac_conn_lbl.configure(
            text=f"API: {api}\nNS: {ns}\n{tok_hint}\n{proxy} | {tls}",
        )

    def _run_rbac_audit(self):
        if self._rbac_busy:
            return
        self._sync_proxy_from_ui()
        api = self.apiserver_var.get().strip()
        token = self.token_var.get().strip()
        if not api or not token:
            messagebox.showwarning(
                "RBAC 审计",
                "请先在「基础命令」页填写 API Server 与 Bearer Token。\n\n"
                "经 SOCKS 时请使用内网 IP（勿用 kubernetes.default.svc）。",
                parent=self,
            )
            return
        if "kubernetes.default" in api and socks_proxy.is_enabled():
            if not messagebox.askyesno(
                "RBAC 审计",
                "当前 API 为 kubernetes.default.svc，经 SOCKS 隧道可能无法解析。\n"
                "是否仍继续？（建议改为集群内网 IP）",
                parent=self,
            ):
                return
        self._rbac_busy = True
        self.rbac_run_btn.configure(state=tk.DISABLED)
        self.rbac_progress["value"] = 0
        self.rbac_progress_lbl.configure(text="审计进行中…", fg=WARN)
        self._update_status_bar("RBAC 审计进行中…", WARN)
        self.rbac_perm_txt.delete("1.0", tk.END)
        self.rbac_chain_txt.delete("1.0", tk.END)
        self._executor.submit(self._run_rbac_audit_worker)

    def _run_rbac_audit_worker(self):
        def progress(msg, current, total):
            pct = int(current / max(total, 1) * 100)
            self.after(0, lambda: self._rbac_progress_update(msg, pct))

        try:
            ca = self.cacert_var.get().strip()
            ca_ok = bool(ca and os.path.isfile(ca))
            skip_tls = self.skip_tls_var.get() or not ca_ok
            auditor = RBACAuditor(
                self.apiserver_var.get(),
                self.token_var.get(),
                self.ns_var.get(),
                skip_tls=skip_tls,
            )
            result = auditor.audit(progress)
            report = format_report_text(result)
            self.after(0, lambda: self._rbac_display_result(result, report))
        except Exception as e:
            err = str(e)
            self.after(0, lambda: self._rbac_audit_failed(err))

    def _rbac_progress_update(self, msg, pct):
        self.rbac_progress["value"] = pct
        self.rbac_progress_lbl.configure(text=msg[:80])

    def _rbac_display_result(self, result, report):
        self._last_rbac_result = result
        self._last_rbac_report = report
        overall = result["overall_risk"]
        self.rbac_risk_lbl.configure(
            text=f"{overall['emoji']} 总体风险: {overall['label']} — {overall['summary']}",
            fg=DANGER if overall["level"] in ("critical", "high") else WARN if overall["level"] == "medium" else SUCCESS,
        )
        self.rbac_perm_txt.delete("1.0", tk.END)
        allowed = result["allowed_permissions"]
        if allowed:
            for p in sorted(allowed, key=lambda x: (x["level"], x["key"])):
                line = f"✅ [{p['level']}] {p['verb']} {p['resource']}  @ {p['scope']}\n"
                self.rbac_perm_txt.insert(tk.END, line, p["level"])
        else:
            self.rbac_perm_txt.insert(tk.END, "（未检测到 allowed 权限项）\n")

        rs = result.get("rules_summary") or {}
        if rs.get("lines"):
            self.rbac_perm_txt.insert(tk.END, "\n── RulesReview ──\n")
            for ln in rs["lines"][:8]:
                self.rbac_perm_txt.insert(tk.END, f"  • {ln}\n")

        self.rbac_chain_txt.delete("1.0", tk.END)
        chains = result["escalation_chains"]
        if chains:
            for i, c in enumerate(chains, 1):
                self.rbac_chain_txt.insert(tk.END, f"【链 {i}】{c['name']}  风险:{c['risk']}\n")
                self.rbac_chain_txt.insert(tk.END, f"  需要: {', '.join(c['requires'])}\n")
                for step in c["steps"]:
                    self.rbac_chain_txt.insert(tk.END, f"  • {step}\n")
                self.rbac_chain_txt.insert(tk.END, "  PoC:\n", "poc")
                self.rbac_chain_txt.insert(tk.END, c["poc"] + "\n\n", "poc")
        else:
            self.rbac_chain_txt.insert(tk.END, "未匹配到预定义提权链。\n")

        recs = result.get("recommendations") or []
        if recs:
            self.rbac_chain_txt.insert(tk.END, "\n── 修复建议 ──\n")
            for r in recs:
                self.rbac_chain_txt.insert(tk.END, f"  • {r}\n")

        self._append_log(f"\n[{datetime.datetime.now():%H:%M:%S}] RBAC 审计完成\n", "accent")
        self._append_log(report + "\n", None)
        self._rbac_finish(f"RBAC 完成: {overall['label']}", SUCCESS)

    def _rbac_audit_failed(self, err):
        self.rbac_risk_lbl.configure(text=f"审计失败: {err[:120]}", fg=DANGER)
        self.rbac_chain_txt.delete("1.0", tk.END)
        self.rbac_chain_txt.insert(tk.END, err)
        self._append_log(f"\n[-] RBAC 审计失败: {err}\n", "danger")
        self._rbac_finish("RBAC 审计失败", DANGER)

    def _rbac_finish(self, status_msg, color):
        self._rbac_busy = False
        self.rbac_run_btn.configure(state=tk.NORMAL)
        self.rbac_progress["value"] = 100
        self.rbac_progress_lbl.configure(text="完成", fg=color)
        self._update_status_bar(status_msg, color)
        self._rbac_refresh_conn_info()

    def _export_rbac_report(self):
        if not self._last_rbac_result:
            messagebox.showinfo("RBAC", "请先执行 RBAC 审计", parent=self)
            return
        ensure_data_dirs()
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default = os.path.join(REPORTS_DIR, f"rbac_audit_{stamp}.md")
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".md",
            initialfile=os.path.basename(default),
            initialdir=REPORTS_DIR,
            filetypes=[("Markdown", "*.md"), ("All", "*.*")],
        )
        if path:
            base = os.path.splitext(os.path.basename(path))[0]
            svg_name = f"{base}_attack_graph.svg"
            svg_path = os.path.join(os.path.dirname(path), svg_name)
            md = format_report_markdown(self._last_rbac_result)
            try:
                with open(svg_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(build_attack_graph_svg(self._last_rbac_result))
                md = format_report_markdown(self._last_rbac_result, graph_image=svg_name)
            except OSError as e:
                messagebox.showwarning("攻击图", f"SVG 保存失败，报告仅含 Mermaid：{e}", parent=self)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(md)
            msg = f"RBAC 报告已保存: {path}"
            if os.path.isfile(svg_path):
                msg += f" + {svg_name}"
            self._update_status_bar(msg, SUCCESS)

    def _copy_rbac_report(self):
        text = self._last_rbac_report
        if not text:
            messagebox.showinfo("RBAC", "暂无报告可复制", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._update_status_bar("RBAC 报告已复制")

    def _send_rbac_to_ai(self):
        if not self._last_rbac_report:
            messagebox.showinfo("RBAC", "请先执行 RBAC 审计", parent=self)
            return
        self.notebook.select(self.tab_ai)
        self.ai_input_text.delete("1.0", tk.END)
        self.ai_input_text.insert("1.0", self._last_rbac_report)
        self.start_ai_audit_thread()

    def _build_ai_tab(self):
        root = tk.Frame(self.tab_ai, bg=BG)
        root.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        cfg = tk.Frame(root, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        cfg.pack(fill=tk.X, pady=(0, 8))
        cfg_inner = tk.Frame(cfg, bg=CARD)
        cfg_inner.pack(fill=tk.X, padx=10, pady=8)

        row1 = tk.Frame(cfg_inner, bg=CARD)
        row1.pack(fill=tk.X, pady=2)
        tk.Label(row1, text="厂商", bg=CARD, fg=TEXT2, width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.ai_provider_cb = ttk.Combobox(
            row1, textvariable=self.ai_provider_var, values=list(AI_PROVIDERS.keys()),
            state="readonly", width=22, style="Sidebar.TCombobox",
        )
        self.ai_provider_cb.pack(side=tk.LEFT, padx=4)
        self.ai_provider_cb.bind("<<ComboboxSelected>>", self._on_ai_provider_change)
        self._fix_readonly_combobox(self.ai_provider_cb)

        tk.Label(row1, text="API Key", bg=CARD, fg=TEXT2).pack(side=tk.LEFT, padx=(12, 4))
        self._dark_entry(row1, self.ai_api_key_var, show="*", width=30).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text="(本地 Ollama 可留空)", bg=CARD, fg=TEXT2, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        row2 = tk.Frame(cfg_inner, bg=CARD)
        row2.pack(fill=tk.X, pady=4)
        tk.Label(row2, text="Base URL", bg=CARD, fg=TEXT2, width=8, anchor=tk.W).pack(side=tk.LEFT)
        self._dark_entry(row2, self.ai_base_url_var, width=54).pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)

        row3 = tk.Frame(cfg_inner, bg=CARD)
        row3.pack(fill=tk.X, pady=2)
        tk.Label(row3, text="Model", bg=CARD, fg=TEXT2, width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.ai_model_cb = ttk.Combobox(
            row3, textvariable=self.ai_model_var, width=36, style="Sidebar.TCombobox",
        )
        self.ai_model_cb.pack(side=tk.LEFT, padx=4)
        ttk.Button(row3, text="刷新模型", command=self._on_refresh_ai_models_click).pack(side=tk.LEFT, padx=4)
        self.ai_models_status_lbl = tk.Label(row3, text="", bg=CARD, fg=TEXT2, font=("Segoe UI", 8))
        self.ai_models_status_lbl.pack(side=tk.LEFT, padx=4)
        self._fix_readonly_combobox(self.ai_model_cb)
        self._refresh_ai_model_choices()

        paned = tk.PanedWindow(root, orient=tk.HORIZONTAL, bg=BG, sashwidth=6, sashrelief=tk.FLAT,
                               bd=0, opaqueresize=True)
        paned.pack(fill=tk.BOTH, expand=True, pady=4)

        left_wrap = tk.Frame(paned, bg=BG)
        tk.Label(left_wrap, text="粘贴 /pods、/nodes、RBAC 或集群原始数据 (JSON/YAML/TXT)",
                 bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 4))
        left_box = tk.Frame(left_wrap, bg=BORDER, padx=1, pady=1)
        left_box.pack(fill=tk.BOTH, expand=True)
        self.ai_input_text = self._dark_scrolled_text(left_box, height=24)
        self.ai_input_text.pack(fill=tk.BOTH, expand=True)
        paned.add(left_wrap, minsize=360)

        right_wrap = tk.Frame(paned, bg=BG)
        tk.Label(right_wrap, text="AI 安全审计报告", bg=BG, fg=ACCENT, font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 4)
        )
        right_box = tk.Frame(right_wrap, bg=BORDER, padx=1, pady=1)
        right_box.pack(fill=tk.BOTH, expand=True)
        self.ai_output_text = self._dark_scrolled_text(right_box, height=24, fg=TEXT)
        self.ai_output_text.pack(fill=tk.BOTH, expand=True)
        self.ai_output_text.tag_configure("head", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.ai_output_text.tag_configure("warn", foreground=WARN)
        self.ai_output_text.tag_configure("danger", foreground=DANGER)
        self.ai_output_text.tag_configure("ok", foreground=SUCCESS)
        paned.add(right_wrap, minsize=400)

        btn_row = tk.Frame(root, bg=BG)
        btn_row.pack(fill=tk.X, pady=6)
        ttk.Button(btn_row, text="清空输入", command=lambda: self.ai_input_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="清空报告", command=lambda: self.ai_output_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="复制报告", command=self._copy_ai_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="保存本次", command=self._save_ai_session_manual).pack(side=tk.LEFT, padx=2)
        self.ai_autosave_btn = ttk.Button(btn_row, text="💾 自动保存: 关", command=self._toggle_ai_autosave)
        self.ai_autosave_btn.pack(side=tk.LEFT, padx=6)
        self.ai_save_dir_lbl = tk.Label(
            btn_row, text=f"保存目录: {DATA_DIR}", bg=BG, fg=TEXT2, font=("Segoe UI", 8),
        )
        self.ai_save_dir_lbl.pack(side=tk.LEFT, padx=4)
        self.ai_analyze_btn = ttk.Button(btn_row, text="🚀 AI 分析", command=self.start_ai_audit_thread)
        self.ai_analyze_btn.pack(side=tk.RIGHT, padx=4)
        self._sync_ai_autosave_btn()

    def _build_proxy_tab(self):
        root = tk.Frame(self.tab_proxy, bg=BG)
        root.pack(fill=tk.BOTH, expand=True, padx=24, pady=16)

        tk.Label(
            root, text="SOCKS5 代理", bg=BG, fg=ACCENT,
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor=tk.W)
        tk.Label(
            root,
            text="配置后，程序内 curl / K8s API / AI 请求自动经 SOCKS5 隧道；可用「经 SOCKS 一键探测」测试隧道内环境。",
            bg=BG, fg=TEXT2, font=("Segoe UI", 9), wraplength=720, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 12))

        card = tk.Frame(root, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.X, pady=(0, 12))
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill=tk.X, padx=20, pady=16)

        ttk.Checkbutton(inner, text="启用 SOCKS5 代理", variable=self.proxy_enabled_var).grid(
            row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 10),
        )

        tk.Label(inner, text="代理地址", bg=CARD, fg=TEXT2, width=10, anchor=tk.W).grid(
            row=1, column=0, sticky=tk.W, pady=4,
        )
        tk.Entry(inner, textvariable=self.proxy_host_var, bg=BG3, fg=TEXT, width=28,
                 relief=tk.FLAT, insertbackground=TEXT).grid(row=1, column=1, sticky=tk.W, padx=(0, 16), pady=4)

        tk.Label(inner, text="端口", bg=CARD, fg=TEXT2, width=6, anchor=tk.W).grid(
            row=1, column=2, sticky=tk.W, pady=4,
        )
        tk.Entry(inner, textvariable=self.proxy_port_var, bg=BG3, fg=TEXT, width=10,
                 relief=tk.FLAT, insertbackground=TEXT).grid(row=1, column=3, sticky=tk.W, pady=4)

        tk.Label(inner, text="用户名", bg=CARD, fg=TEXT2, width=10, anchor=tk.W).grid(
            row=2, column=0, sticky=tk.W, pady=4,
        )
        tk.Entry(inner, textvariable=self.proxy_user_var, bg=BG3, fg=TEXT, width=28,
                 relief=tk.FLAT, insertbackground=TEXT).grid(row=2, column=1, sticky=tk.W, padx=(0, 16), pady=4)

        tk.Label(inner, text="密码", bg=CARD, fg=TEXT2, width=6, anchor=tk.W).grid(
            row=2, column=2, sticky=tk.W, pady=4,
        )
        tk.Entry(inner, textvariable=self.proxy_pass_var, bg=BG3, fg=TEXT, width=10,
                 show="*", relief=tk.FLAT, insertbackground=TEXT).grid(row=2, column=3, sticky=tk.W, pady=4)

        tk.Label(inner, text="探测 URL(可选)", bg=CARD, fg=TEXT2, width=10, anchor=tk.W).grid(
            row=3, column=0, sticky=tk.W, pady=4,
        )
        tk.Entry(inner, textvariable=self.proxy_test_url_var, bg=BG3, fg=TEXT, width=48,
                 relief=tk.FLAT, insertbackground=TEXT).grid(
            row=3, column=1, columnspan=3, sticky=tk.W, pady=4,
        )
        tk.Label(
            inner,
            text="留空则经隧道访问 ifconfig.me；内网 webshell 无外网时 CONNECT 成功即算通过",
            bg=CARD, fg=TEXT2, font=("Segoe UI", 8), wraplength=620, justify=tk.LEFT, anchor=tk.W,
        ).grid(row=4, column=0, columnspan=4, sticky=tk.W)

        btn_row = tk.Frame(inner, bg=CARD)
        btn_row.grid(row=5, column=0, columnspan=4, sticky=tk.W, pady=(12, 0))
        ttk.Button(btn_row, text="应用代理", command=self._on_apply_socks_proxy).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="检测 SOCKS", command=self._on_test_socks_proxy).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_row, text="经 SOCKS 一键探测", command=self._run_proxy_audit).pack(side=tk.LEFT, padx=8)

        self.proxy_status_lbl = tk.Label(
            inner, text=socks_proxy.describe_status(), bg=CARD, fg=TEXT2,
            font=("Segoe UI", 9), wraplength=640, justify=tk.LEFT, anchor=tk.W,
        )
        self.proxy_status_lbl.grid(row=6, column=0, columnspan=4, sticky=tk.W, pady=(12, 0))

        if not socks_proxy.pysocks_available():
            tk.Label(
                root, text="⚠ 未安装 PySocks，代理无法生效。请运行: pip install PySocks",
                bg=BG, fg=WARN, font=("Segoe UI", 9), wraplength=720, justify=tk.LEFT,
            ).pack(anchor=tk.W, pady=(0, 8))

        info = tk.Frame(root, bg=BG2, highlightbackground=BORDER, highlightthickness=1)
        info.pack(fill=tk.X)
        info_inner = tk.Frame(info, bg=BG2)
        info_inner.pack(fill=tk.X, padx=16, pady=12)
        tk.Label(info_inner, text="说明", bg=BG2, fg=ACCENT, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        for line in (
            "• 使用 socks5h，DNS 经代理解析",
            "• 检测 SOCKS：①端口 ②握手 ③隧道连通，三步全过=连接成功",
            "• 默认经隧道访问 ifconfig.me；内网环境 CONNECT 成功即可用",
            "• 填「探测 URL」可验证内网目标（K8s API、169.254.169.254 等）",
            "• GKE Pod 内 metadata 无法经 SOCKS 二次访问，需在容器内直接 curl 或粘贴 env",
        ):
            tk.Label(info_inner, text=line, bg=BG2, fg=TEXT2, font=("Segoe UI", 9),
                     anchor=tk.W, justify=tk.LEFT).pack(anchor=tk.W, pady=1)

    def _sync_proxy_from_ui(self):
        socks_proxy.apply_config(
            self.proxy_enabled_var.get(),
            self.proxy_host_var.get(),
            self.proxy_port_var.get(),
            self.proxy_user_var.get(),
            self.proxy_pass_var.get(),
        )

    def _on_apply_socks_proxy(self):
        host = self.proxy_host_var.get().strip()
        port = self.proxy_port_var.get().strip()
        if self.proxy_enabled_var.get():
            if not host or not port:
                messagebox.showwarning("SOCKS5", "请填写代理地址和端口", parent=self)
                return
            if not port.isdigit():
                messagebox.showwarning("SOCKS5", "端口必须是数字", parent=self)
                return
            if not socks_proxy.pysocks_available():
                messagebox.showwarning(
                    "SOCKS5",
                    "未安装 PySocks，代理无法生效。\n\n请在命令行运行:\n  pip install PySocks",
                    parent=self,
                )
        self._sync_proxy_from_ui()
        self._persist_config()
        status = socks_proxy.describe_status()
        self.proxy_status_lbl.configure(
            text=status, fg=SUCCESS if socks_proxy.is_enabled() else TEXT2,
        )
        self._update_status_bar(f"代理已应用: {status}", SUCCESS if socks_proxy.is_enabled() else None)
        if socks_proxy.is_enabled():
            messagebox.showinfo(
                "SOCKS5",
                f"已启用代理\n{status}\n\n"
                "点击「检测 SOCKS」确认握手即可，扫描请手动 curl。",
                parent=self,
            )

    def _on_test_socks_proxy(self):
        self._sync_proxy_from_ui()
        if not socks_proxy.is_enabled():
            messagebox.showinfo("SOCKS5", "请先勾选「启用 SOCKS5」并填写地址端口", parent=self)
            return
        self.proxy_status_lbl.configure(text="检测 SOCKS…", fg=WARN)
        self._update_status_bar("正在检测 SOCKS5…", WARN)

        def worker():
            custom = self.proxy_test_url_var.get().strip()
            urls = [custom] if custom else None
            ok, msg = socks_proxy.test_connection(urls)
            def done():
                if ok:
                    status = "✓ SOCKS5 连接成功"
                    fg = SUCCESS
                else:
                    status = "✗ SOCKS5 连接失败"
                    fg = DANGER
                self.proxy_status_lbl.configure(text=status, fg=fg)
                self._update_status_bar(status, fg)
                title = "SOCKS5 连接成功" if ok else "SOCKS5 连接失败"
                if ok:
                    messagebox.showinfo(title, msg, parent=self)
                else:
                    messagebox.showwarning(title, msg, parent=self)
            self.after(0, done)

        self._executor.submit(worker)

    def _proxy_test_urls(self):
        custom = self.proxy_test_url_var.get().strip()
        return [custom] if custom else []

    def _refresh_ai_model_choices(self):
        provider = self.ai_provider_var.get()
        models = self._ai_models_cache.get(provider)
        if not models:
            preset = AI_PROVIDERS.get(provider, {})
            models = AIModelFetcher._fallback(preset)
        self.ai_model_cb["values"] = models
        current = self.ai_model_var.get().strip()
        if models and current not in models:
            preset = AI_PROVIDERS.get(provider, {})
            pick = preset.get("model") or models[0]
            if pick in models:
                self.ai_model_var.set(pick)
            elif current:
                pass
            else:
                self.ai_model_var.set(models[0])

    def _on_ai_provider_change(self, event=None):
        name = self.ai_provider_var.get()
        preset = AI_PROVIDERS.get(name)
        if not preset or name == "自定义":
            self._refresh_ai_model_choices()
            if hasattr(self, "ai_models_status_lbl"):
                self.ai_models_status_lbl.configure(text="")
            return
        self.ai_base_url_var.set(preset.get("base_url", ""))
        self.ai_model_var.set(preset.get("model", ""))
        self.ai_format_var.set(preset.get("format", "openai"))
        self._schedule_ai_models_fetch(force=True)

    def _tk_callback_exception(self, exc, val, tb):
        msg = "".join(traceback.format_exception(exc, val, tb))
        logger.error("界面回调异常:\n%s", msg)
        try:
            messagebox.showerror(
                "程序错误",
                f"操作失败，请把以下信息发给开发者：\n\n{val}\n\n日志: {LOG_PATH}",
                parent=self,
            )
        except tk.TclError:
            pass

    def _on_refresh_ai_models_click(self):
        """用户点击刷新模型：强制重新拉取并给出可见反馈。"""
        try:
            if hasattr(self, "ai_models_status_lbl"):
                self.ai_models_status_lbl.configure(text="正在刷新…", fg=WARN)
            self._update_status_bar("正在刷新模型列表…", WARN)
            self.update_idletasks()

            provider = self.ai_provider_var.get()
            preset = AI_PROVIDERS.get(provider, {})
            if preset.get("models_api") == "none":
                self.ai_models_status_lbl.configure(text="自定义模式，请手动输入模型名", fg=TEXT2)
                self._update_status_bar("自定义模式无需刷新模型列表")
                return
            api_key = self.ai_api_key_var.get().strip()
            if AIModelFetcher._needs_api_key(preset) and not api_key:
                static = AIModelFetcher._fallback(preset)
                self._ai_models_cache[provider] = static
                self._refresh_ai_model_choices()
                n = len(static)
                self.ai_models_status_lbl.configure(
                    text=f"静态列表 {n} 个（请先填写 API Key）", fg=WARN,
                )
                self._update_status_bar("刷新模型：请先填写 API Key", WARN)
                messagebox.showinfo(
                    "刷新模型",
                    f"厂商「{provider}」需要 API Key 才能在线拉取模型列表。\n\n"
                    f"已加载静态备选列表 {n} 个，填写 Key 后再次点击刷新。\n\n"
                    "注意：配置保存在程序目录下的 data 文件夹，整包拷贝即可带走 API Key：\n"
                    f"{CONFIG_PATH}",
                    parent=self,
                )
                return
            if api_key:
                self._persist_config()
            self._ai_models_cache.pop(provider, None)
            self._schedule_ai_models_fetch(force=True, show_error_dialog=True)
        except Exception as e:
            logger.error("刷新模型按钮异常: %s", e, exc_info=True)
            if hasattr(self, "ai_models_status_lbl"):
                self.ai_models_status_lbl.configure(text=f"刷新失败: {e}", fg=DANGER)
            self._update_status_bar(f"刷新模型失败: {e}", DANGER)
            messagebox.showerror("刷新模型失败", str(e), parent=self)

    def _schedule_ai_models_fetch(self, force=False, show_error_dialog=False):
        provider = self.ai_provider_var.get()
        preset = AI_PROVIDERS.get(provider, {})
        if preset.get("models_api") == "none":
            self._ai_models_cache[provider] = []
            self._refresh_ai_model_choices()
            if hasattr(self, "ai_models_status_lbl"):
                self.ai_models_status_lbl.configure(text="自定义模式，请手动输入模型名")
            return
        api_key = self.ai_api_key_var.get().strip()
        static = AIModelFetcher._fallback(preset)
        if AIModelFetcher._needs_api_key(preset) and not api_key:
            self._ai_models_cache[provider] = static
            self._refresh_ai_model_choices()
            if hasattr(self, "ai_models_status_lbl"):
                n = len(static)
                self.ai_models_status_lbl.configure(
                    text=f"静态列表 {n} 个（填写 API Key 后点 ↻ 刷新）", fg=TEXT2,
                )
            return
        if not force and provider in self._ai_models_cache:
            self._refresh_ai_model_choices()
            return
        if force:
            self._ai_models_cache.pop(provider, None)
        self._ai_models_fetch_gen += 1
        gen = self._ai_models_fetch_gen
        if hasattr(self, "ai_models_status_lbl"):
            self.ai_models_status_lbl.configure(text="正在获取模型列表…", fg=WARN)
        self._update_status_bar(f"正在获取 {provider} 模型列表…")
        base_url = self.ai_base_url_var.get().strip()
        self._executor.submit(
            self._fetch_ai_models_worker, provider, base_url, api_key, gen, show_error_dialog,
        )

    def _fetch_ai_models_worker(self, provider, base_url, api_key, gen, show_error_dialog=False):
        preset = AI_PROVIDERS.get(provider, {})
        models, used_fallback, fetch_err = AIModelFetcher.fetch(provider, base_url, api_key, preset)
        err = None
        if used_fallback:
            if AIModelFetcher._needs_api_key(preset) and not api_key:
                err = "static_no_key"
            else:
                err = "static_fallback"

        def apply():
            if gen != self._ai_models_fetch_gen:
                return
            self._ai_models_cache[provider] = models
            self._refresh_ai_model_choices()
            if hasattr(self, "ai_models_status_lbl"):
                if err == "static_no_key":
                    self.ai_models_status_lbl.configure(
                        text=f"静态列表 {len(models)} 个（填写 API Key 后点 ↻ 刷新）", fg=TEXT2,
                    )
                elif err == "static_fallback":
                    short = (fetch_err or "网络或 SSL 错误")[:55]
                    self.ai_models_status_lbl.configure(
                        text=f"失败: {short}…（已用静态 {len(models)} 个）", fg=WARN,
                    )
                elif models:
                    self.ai_models_status_lbl.configure(
                        text=f"已在线加载 {len(models)} 个模型", fg=SUCCESS,
                    )
                else:
                    self.ai_models_status_lbl.configure(text="未获取到模型", fg=TEXT2)
            if err == "static_fallback":
                self._update_status_bar(f"{provider} 在线获取失败，已用静态列表", WARN)
                if show_error_dialog:
                    proxy_hint = ""
                    if socks_proxy.is_enabled():
                        proxy_hint = f"\n当前 SOCKS5: {socks_proxy.describe_status()}\n"
                    messagebox.showwarning(
                        "刷新模型失败",
                        f"厂商：{provider}\n"
                        f"Base URL：{base_url or preset.get('base_url', '')}\n\n"
                        f"原因：{fetch_err or '网络或 SSL 错误'}\n"
                        f"{proxy_hint}\n"
                        f"已改用静态列表 {len(models)} 个，仍可手动选择模型。\n\n"
                        "常见排查：\n"
                        "1. 确认 API Key 已填写（保存在 data/config.json）\n"
                        "2. 公司网络/防火墙是否拦截 api.xxx.com\n"
                        "3. 若用 Ollama，需在本机安装并启动服务\n"
                        f"4. 详细日志：{LOG_PATH}",
                        parent=self,
                    )
            elif err == "static_no_key":
                self._update_status_bar("就绪")
            elif models:
                self._update_status_bar(f"{provider} 模型列表已更新 ({len(models)} 个)")

        self.after(0, apply)

    @staticmethod
    def _normalize_ai_chat_url(base_url):
        base = (base_url or "").strip().rstrip("/")
        if not base:
            return ""
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/messages"):
            return base.rsplit("/messages", 1)[0] + "/messages"
        if base.endswith("/v1"):
            return base + "/chat/completions"
        if "/v1/" in base or base.endswith("/v1beta/openai"):
            return base + "/chat/completions"
        return base + "/v1/chat/completions"

    @staticmethod
    def _normalize_anthropic_url(base_url):
        base = (base_url or "").strip().rstrip("/")
        if not base:
            return ""
        if base.endswith("/messages"):
            return base
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"

    def start_ai_audit_thread(self):
        raw_data = self.ai_input_text.get("1.0", tk.END).strip()
        if not raw_data:
            messagebox.showwarning("AI 分析", "请粘贴需要分析的集群数据！", parent=self)
            return
        provider = self.ai_provider_var.get()
        api_key = self.ai_api_key_var.get().strip()
        if provider != "Ollama (本地)" and not api_key:
            messagebox.showwarning("AI 分析", "请先配置 API Key！", parent=self)
            return
        if self._ai_busy:
            return
        self._last_ai_raw_data = raw_data
        self._ai_busy = True
        self.ai_analyze_btn.configure(state=tk.DISABLED)
        self.ai_output_text.delete("1.0", tk.END)
        self.ai_output_text.insert(tk.END, "[*] 正在同步上下文并分析中，请稍候…\n")
        self._update_status_bar("AI 分析中…")
        self._executor.submit(self._run_ai_audit, raw_data)

    def _run_ai_audit(self, data):
        api_key = self.ai_api_key_var.get().strip()
        model = self.ai_model_var.get().strip()
        base_url = self.ai_base_url_var.get().strip()
        fmt = self.ai_format_var.get() or "openai"
        provider = self.ai_provider_var.get()
        preset = AI_PROVIDERS.get(provider, {})
        if preset.get("format"):
            fmt = preset["format"]
        if "anthropic.com" in base_url.lower():
            fmt = "anthropic"

        if len(data) > 120000:
            data = data[:120000] + "\n\n…(内容过长，已截断至 120KB 发送给 AI)"

        user_content = f"这是我采集到的集群/云环境数据，请帮我全盘安全审计：\n\n{data}"

        try:
            if fmt == "anthropic":
                text = self._ai_request_anthropic(base_url, api_key, model, user_content)
            else:
                text = self._ai_request_openai(base_url, api_key, model, user_content, provider)
            self.after(0, lambda: self._update_ai_output(text))
        except Exception as e:
            err = f"[-] AI 审计失败\n\n错误: {e}\n\n提示: 检查 API Key、Base URL 与模型名称是否正确；自定义中转站需填写完整 Base URL。"
            self.after(0, lambda: self._update_ai_output(err))

    def _ai_request_openai(self, base_url, api_key, model, user_content, provider):
        url = self._normalize_ai_chat_url(base_url)
        if not url:
            raise ValueError("Base URL 不能为空")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if provider == "OpenRouter":
            headers["HTTP-Referer"] = "https://github.com/k8s-commander"
            headers["X-Title"] = "K8s Commander"

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": AI_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.3,
        }

        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
        )
        with socks_proxy.urlopen(req, timeout=120) as response:
            res_data = json.loads(response.read().decode("utf-8"))
        choice = res_data.get("choices", [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content", "")
        if isinstance(content, list):
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else str(part) for part in content
            )
        if not content:
            raise ValueError(f"API 返回空内容: {json.dumps(res_data, ensure_ascii=False)[:500]}")
        return content

    def _ai_request_anthropic(self, base_url, api_key, model, user_content):
        url = self._normalize_anthropic_url(base_url)
        if not api_key:
            raise ValueError("Anthropic API 需要 API Key")
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 8192,
            "system": AI_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_content}],
            "temperature": 0.3,
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
        )
        with socks_proxy.urlopen(req, timeout=120) as response:
            res_data = json.loads(response.read().decode("utf-8"))
        blocks = res_data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        if not text:
            raise ValueError(f"Anthropic 返回空内容: {json.dumps(res_data, ensure_ascii=False)[:500]}")
        return text

    def _update_ai_output(self, text):
        self.ai_output_text.delete("1.0", tk.END)
        self.ai_output_text.insert(tk.END, text)
        for marker, tag in [("[💡", "head"), ("[⚠️", "warn"), ("[⚔️", "danger"), ("[🛡️", "head")]:
            start = "1.0"
            while True:
                pos = self.ai_output_text.search(marker, start, stopindex=tk.END)
                if not pos:
                    break
                line_end = f"{pos} lineend"
                self.ai_output_text.tag_add(tag, pos, line_end)
                start = line_end
        self.ai_output_text.see("1.0")
        self._ai_busy = False
        self.ai_analyze_btn.configure(state=tk.NORMAL)
        saved_path = None
        if self.ai_auto_save_var.get() and self._last_ai_raw_data and not text.startswith("[-]"):
            saved_path = self._save_ai_session(self._last_ai_raw_data, text)
        if saved_path:
            self._update_status_bar(f"AI 分析完成，已自动保存: {os.path.basename(saved_path)}")
        else:
            self._update_status_bar("AI 分析完成")

    def _sync_ai_autosave_btn(self):
        on = self.ai_auto_save_var.get()
        self.ai_autosave_btn.configure(text=f"💾 自动保存: {'开' if on else '关'}")

    def _toggle_ai_autosave(self):
        self.ai_auto_save_var.set(not self.ai_auto_save_var.get())
        self._sync_ai_autosave_btn()
        state = "开启" if self.ai_auto_save_var.get() else "关闭"
        self._update_status_bar(f"AI 自动保存已{state} → {REPORTS_DIR}")

    def _ai_session_filepath(self):
        ensure_data_dirs()
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(REPORTS_DIR, f"ai_audit_{stamp}")
        path = base + ".md"
        seq = 1
        while os.path.exists(path):
            path = f"{base}_{seq:03d}.md"
            seq += 1
        return path

    def _save_ai_session(self, raw_data, report_text):
        path = self._ai_session_filepath()
        provider = self.ai_provider_var.get()
        model = self.ai_model_var.get()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        content = (
            f"# AI 安全审计记录\n\n"
            f"- **时间**: {now}\n"
            f"- **厂商**: {provider}\n"
            f"- **模型**: {model}\n\n"
            f"---\n\n"
            f"## 原始数据\n\n"
            f"```\n{raw_data}\n```\n\n"
            f"---\n\n"
            f"## AI 安全审计报告\n\n"
            f"{report_text}\n"
        )
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        return path

    def _save_ai_session_manual(self):
        raw = self._last_ai_raw_data or self.ai_input_text.get("1.0", tk.END).strip()
        report = self.ai_output_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("保存", "没有原始数据可保存。", parent=self)
            return
        if not report or report.startswith("[*]"):
            messagebox.showwarning("保存", "请先完成 AI 分析再保存。", parent=self)
            return
        try:
            path = self._save_ai_session(raw, report)
            messagebox.showinfo("保存成功", f"已保存至:\n{path}", parent=self)
            self._update_status_bar(f"已保存: {os.path.basename(path)}")
        except OSError as e:
            messagebox.showerror("保存失败", str(e), parent=self)

    def _copy_ai_report(self):
        text = self.ai_output_text.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._update_status_bar("AI 报告已复制")

    def _send_output_to_ai(self):
        text = self.out_txt.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("AI 分析", "输出框为空，请先执行命令获取结果。", parent=self)
            return
        self.notebook.select(self.tab_ai)
        self.ai_input_text.delete("1.0", tk.END)
        self.ai_input_text.insert("1.0", text)
        self.start_ai_audit_thread()

    def _copy_output(self):
        try:
            text = self.out_txt.get(tk.SEL_FIRST, tk.SEL_LAST).strip()
        except tk.TclError:
            text = self.out_txt.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._update_status_bar("输出已复制")

    def _build_cmd_tab(self):
        top = tk.Frame(self.tab_cmd, bg=BG2, height=40)
        top.pack(fill=tk.X)
        tk.Label(top, text="⚡ 命令列表", font=("Segoe UI", 11, "bold"), fg=ACCENT, bg=BG2).pack(side=tk.LEFT, padx=10, pady=8)
        ttk.Button(top, text="一键体检", command=self._run_full_audit).pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(top, text="curl", variable=self.mode_var, value="curl").pack(side=tk.RIGHT, padx=8)
        ttk.Radiobutton(top, text="kubectl", variable=self.mode_var, value="kubectl").pack(side=tk.RIGHT, padx=8)

        body = tk.Frame(self.tab_cmd, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        sidebar = tk.Frame(body, bg=BG, width=300)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="分组", bg=BG, fg=TEXT2).pack(anchor=tk.W, padx=4)
        self.group_cb = ttk.Combobox(sidebar, textvariable=self.group_var, values=list(COMMAND_GROUPS.keys()),
                                     state="readonly", width=28, style="Sidebar.TCombobox")
        self.group_cb.pack(fill=tk.X, padx=4, pady=2)
        self._fix_readonly_combobox(self.group_cb)
        self.group_cb.bind("<<ComboboxSelected>>", self._on_group_change)

        tk.Label(sidebar, text="分类", bg=BG, fg=TEXT2).pack(anchor=tk.W, padx=4, pady=(6, 0))
        self.category_cb = ttk.Combobox(sidebar, textvariable=self.category_var, state="readonly", width=28,
                                        style="Sidebar.TCombobox")
        self.category_cb.pack(fill=tk.X, padx=4, pady=2)
        self._fix_readonly_combobox(self.category_cb)
        self.category_cb.bind("<<ComboboxSelected>>", self._on_category_change)

        sf = tk.Frame(sidebar, bg=BG)
        sf.pack(fill=tk.X, padx=4, pady=6)
        tk.Label(sf, text="🔍", bg=BG, fg=TEXT2).pack(side=tk.LEFT)
        self.search_ent = tk.Entry(sf, textvariable=self.search_var, bg=BG3, fg=TEXT, insertbackground=TEXT, relief=tk.FLAT)
        self.search_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.search_var.trace_add("write", lambda *_: self._filter_command_list())

        lb_frame = tk.Frame(sidebar, bg=BG)
        lb_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.cmd_listbox = tk.Listbox(lb_frame, bg=BG2, fg=TEXT, selectbackground=ACCENT, selectforeground="#fff",
                                      font=("Segoe UI", 10), activestyle="none", highlightthickness=0, bd=0)
        lb_scroll = ttk.Scrollbar(lb_frame, orient=tk.VERTICAL, command=self.cmd_listbox.yview)
        self.cmd_listbox.configure(yscrollcommand=lb_scroll.set)
        self.cmd_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.cmd_listbox.bind("<<ListboxSelect>>", self._on_listbox_select)
        self.cmd_listbox.bind("<Double-Button-1>", lambda e: self._execute_current_command())

        main = tk.Frame(body, bg=BG)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        param_card = tk.Frame(main, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        param_card.pack(fill=tk.X, pady=(0, 6))
        inner = tk.Frame(param_card, bg=CARD)
        inner.pack(fill=tk.X, padx=10, pady=8)

        fields = [
            ("API Server", self.apiserver_var, 0, 0, 36),
            ("Namespace", self.ns_var, 0, 2, 14),
            ("Bearer Token", self.token_var, 1, 0, 36),
            ("CA Cert", self.cacert_var, 2, 0, 36),
            ("Node IP", self.node_ip_var, 0, 4, 14),
            ("Role Name", self.role_name_var, 1, 2, 14),
            ("Pod", self.pod_var, 1, 4, 14),
            ("ConfigMap", self.configmap_var, 2, 2, 14),
            ("Secret", self.secret_var, 2, 4, 14),
            ("Deployment", self.deployment_var, 3, 0, 14),
            ("Service", self.service_var, 3, 2, 14),
            ("Container", self.container_var, 3, 4, 14),
            ("Node", self.node_var, 4, 0, 14),
            ("Local Port", self.local_port_var, 4, 2, 8),
            ("Remote Port", self.remote_port_var, 4, 4, 8),
        ]
        for label, var, row, col, width in fields:
            tk.Label(inner, text=label + ":", bg=CARD, fg=TEXT2, font=("Segoe UI", 9)).grid(row=row, column=col, sticky=tk.W, padx=(0, 4), pady=2)
            tk.Entry(inner, textvariable=var, bg=BG3, fg=TEXT, width=width, relief=tk.FLAT,
                     insertbackground=TEXT).grid(row=row, column=col + 1, sticky=tk.W, padx=(0, 12), pady=2)

        token_row = tk.Frame(param_card, bg=CARD)
        token_row.pack(fill=tk.X, padx=10, pady=(0, 6))
        tk.Label(token_row, text="Token 信息", bg=CARD, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        self.token_info_lbl = tk.Label(token_row, text="未加载", bg=CARD, fg=TEXT2, font=("Consolas", 8),
                                       wraplength=900, justify=tk.LEFT, anchor=tk.W)
        self.token_info_lbl.pack(fill=tk.X, anchor=tk.W)

        ttk.Checkbutton(inner, text="跳过 TLS 验证 (-k)", variable=self.skip_tls_var).grid(row=0, column=6, sticky=tk.W, padx=4)
        ttk.Button(inner, text="加载 SA", command=self._load_sa_token).grid(row=1, column=6, sticky=tk.W, padx=4)
        ttk.Button(inner, text="解析 JWT", command=self._parse_token_ui).grid(row=2, column=6, sticky=tk.W, padx=4)
        ttk.Button(inner, text="批量 IMDS", command=self._batch_imds_scan).grid(row=3, column=6, sticky=tk.W, padx=4)
        ttk.Button(inner, text="刷新资源树", command=self._refresh_resource_tree).grid(row=4, column=6, sticky=tk.W, padx=4)

        desc_frame = tk.Frame(main, bg=BG)
        desc_frame.pack(fill=tk.X)
        self.cmd_desc_lbl = tk.Label(desc_frame, text="选择左侧命令", bg=BG, fg=TEXT2, font=("Segoe UI", 9), wraplength=700, justify=tk.LEFT)
        self.cmd_desc_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        preview_frame = tk.Frame(main, bg=BG)
        preview_frame.pack(fill=tk.X, pady=4)
        cmd_box = tk.Frame(preview_frame, bg=BORDER, padx=1, pady=1)
        cmd_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_text = scrolledtext.ScrolledText(
            cmd_box, bg=CARD, fg=CYAN, font=("Consolas", 10), height=3, wrap=tk.NONE,
            insertbackground=TEXT, relief=tk.FLAT, highlightthickness=0, bd=0,
        )
        self.cmd_text.pack(fill=tk.BOTH, expand=True)
        try:
            self.cmd_text.vbar.configure(bg=BG3, troughcolor=BG, activebackground=ACCENT, highlightthickness=0)
        except tk.TclError:
            pass
        ttk.Button(preview_frame, text="复制", command=self._copy_cmd).pack(side=tk.RIGHT, padx=4)
        self.run_btn = ttk.Button(preview_frame, text="▶ 执行", command=self._execute_current_command)
        self.run_btn.pack(side=tk.RIGHT, padx=4)

        out_bar = tk.Frame(main, bg=BG)
        out_bar.pack(fill=tk.X)
        tk.Label(out_bar, text="输出", bg=BG, fg=TEXT2, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Button(out_bar, text="✨ 送去 AI 解释", command=self._send_output_to_ai).pack(side=tk.RIGHT, padx=2)
        ttk.Button(out_bar, text="复制结果", command=self._copy_output).pack(side=tk.RIGHT, padx=2)
        ttk.Button(out_bar, text="导出 Markdown", command=self._export_report_md).pack(side=tk.RIGHT, padx=2)
        ttk.Button(out_bar, text="Base64 解码", command=self._decode_base64_selection).pack(side=tk.RIGHT, padx=2)
        ttk.Button(out_bar, text="保存输出", command=self._save_output).pack(side=tk.RIGHT, padx=2)
        ttk.Button(out_bar, text="清空", command=lambda: self.out_txt.delete("1.0", tk.END)).pack(side=tk.RIGHT)

        self.out_txt = scrolledtext.ScrolledText(main, bg=BG2, fg=TEXT, font=("Consolas", 9), height=10)
        self.out_txt.pack(fill=tk.BOTH, expand=True, pady=4)
        self.out_txt.tag_configure("success", foreground=SUCCESS)
        self.out_txt.tag_configure("warn", foreground=WARN)
        self.out_txt.tag_configure("danger", foreground=DANGER)
        self.out_txt.tag_configure("accent", foreground=CYAN)
        self.out_txt.tag_configure("json_key", foreground=CYAN)
        self.out_txt.tag_configure("json_str", foreground=SUCCESS)
        self.out_txt.tag_configure("json_num", foreground=WARN)
        self.out_txt.tag_configure("json_bool", foreground=ACCENT)

        script_bar = tk.Frame(main, bg=BG)
        script_bar.pack(fill=tk.X, pady=(4, 0))
        tk.Label(script_bar, text="📜 可执行脚本", bg=BG, fg=TEXT2, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Button(script_bar, text="刷新", command=self._update_script_output).pack(side=tk.RIGHT, padx=2)
        ttk.Button(script_bar, text="保存 .sh", command=self._save_script).pack(side=tk.RIGHT, padx=2)
        ttk.Button(script_bar, text="复制脚本", command=self._copy_script).pack(side=tk.RIGHT, padx=2)

        self.script_txt = scrolledtext.ScrolledText(main, bg=CARD, fg=GREEN, font=("Consolas", 9), height=7, wrap=tk.NONE)
        self.script_txt.pack(fill=tk.X, pady=4)

    def _init_command_nav(self):
        cats = COMMAND_GROUPS.get(self.group_var.get(), [])
        self.category_cb["values"] = cats
        if cats:
            self.category_var.set(cats[0])
        self._refresh_command_list()

    def _set_command_nav(self, group, category=None, switch_tab=False):
        if group not in COMMAND_GROUPS:
            return False
        self.group_var.set(group)
        cats = COMMAND_GROUPS[group]
        self.category_cb["values"] = cats
        if category and category in cats:
            self.category_var.set(category)
        elif cats:
            self.category_var.set(cats[0])
        self._refresh_command_list()
        self._fix_readonly_combobox(self.group_cb)
        self._fix_readonly_combobox(self.category_cb)
        if switch_tab and hasattr(self, "notebook"):
            self.notebook.select(self.tab_cmd)
        return True

    def _on_group_change(self, event=None):
        self._set_command_nav(self.group_var.get())

    def _on_category_change(self, event=None):
        self._refresh_command_list()

    def _refresh_command_list(self):
        self.cmd_listbox.delete(0, tk.END)
        self._cmd_list_data = []
        cat = self.category_var.get()
        keyword = self.search_var.get().strip().lower()

        for block in COMMANDS:
            if keyword:
                for item in block["items"]:
                    if keyword in item["name"].lower() or keyword in item.get("desc", "").lower():
                        self.cmd_listbox.insert(tk.END, f"[{block['category']}] {item['name']}")
                        self._cmd_list_data.append(item)
            elif block["category"] == cat:
                for item in block["items"]:
                    self.cmd_listbox.insert(tk.END, item["name"])
                    self._cmd_list_data.append(item)

        if self._cmd_list_data:
            self.cmd_listbox.selection_set(0)
            self._on_listbox_select()

    def _filter_command_list(self):
        self._refresh_command_list()

    def _on_listbox_select(self, event=None):
        sel = self.cmd_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._cmd_list_data):
            return
        self.current_selected_cmd = self._cmd_list_data[idx]
        self._refresh_selected()

    def _refresh_selected(self):
        if not self.current_selected_cmd:
            return
        desc = self.current_selected_cmd.get("desc", "")
        if hasattr(self, "cmd_desc_lbl"):
            self.cmd_desc_lbl.configure(text=desc)
        self._update_cmd_preview()
        self._update_run_button()

    def _update_status_bar(self, msg=None, color=None):
        if not hasattr(self, "status_info"):
            return
        if msg:
            self.status_info.configure(text=msg, fg=color or TEXT2)

    def _update_run_button(self):
        if not hasattr(self, "run_btn") or not self.current_selected_cmd:
            return
        ex = self.current_selected_cmd.get("exec", "both")
        mode = self.mode_var.get()
        if ex == "local":
            self.run_btn.configure(text="▶ 本地执行")
        elif ex == "none":
            self.run_btn.configure(state=tk.DISABLED)
        elif ex in ("kubectl",) and mode == "curl":
            self.run_btn.configure(text="▶ 需 kubectl 模式")
        else:
            self.run_btn.configure(state=tk.NORMAL, text="▶ 执行")

    def _on_mode_change(self):
        if hasattr(self, "status_mode"):
            m = self.mode_var.get()
            self.status_mode.configure(text=f"[模式: {m}]", fg=GREEN if m == "curl" else CYAN)
        self._update_cmd_preview()
        self._update_run_button()

    def _resolve_exec_token(self):
        """本机执行时优先 UI Token，其次尝试读取容器 SA 文件。"""
        token = self.token_var.get().strip()
        if token:
            return token
        if os.path.isfile(SA_TOKEN_PATH):
            try:
                with open(SA_TOKEN_PATH, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except OSError:
                pass
        return ""

    def _is_k8s_api_command(self, cmd=None, item=None):
        item = item or self.current_selected_cmd
        cmd = cmd if cmd is not None else self._get_raw_command()
        if not item:
            return False
        if "k8s_conn" in item.get("tags", []):
            return True
        return bool(cmd and ("Bearer {TOKEN}" in cmd or "{APISERVER}" in cmd))

    def _fill(self, template, for_exec=False, for_container=False):
        if not template:
            return ""
        skip_tls = self.skip_tls_var.get() or for_container
        ui_cacert = self.cacert_var.get().strip()
        tls_val = "-k" if skip_tls else ""

        if for_exec:
            token_val = self._resolve_exec_token()
            cacert_val = ui_cacert
        elif for_container:
            token_val = "$TOKEN"
            cacert_val = ""
        else:
            token_val = "$TOKEN"
            cacert_val = "$CACERT" if not skip_tls else ""

        result = template
        if skip_tls or not cacert_val or (for_exec and not os.path.isfile(cacert_val)) or for_container:
            for pat in (" --cacert {CACERT}", "--cacert {CACERT} ", "--cacert {CACERT}"):
                result = result.replace(pat, "")
        else:
            result = result.replace("--cacert {CACERT}", f"--cacert {cacert_val}")
            result = result.replace("{CACERT}", cacert_val)

        apiserver = self.apiserver_var.get().strip()
        if for_container and apiserver and not apiserver.startswith("http"):
            apiserver = "https://" + apiserver

        replacements = {
            "APISERVER": apiserver if (for_exec or for_container) else "$APISERVER",
            "TOKEN": token_val,
            "NAMESPACE": self.ns_var.get().strip(),
            "TLS": tls_val,
            "ROLE_NAME": self.role_name_var.get().strip(),
            "CONFIGMAP": self.configmap_var.get().strip(),
            "NODE_IP": self.node_ip_var.get().strip(),
            "POD": self.pod_var.get().strip(),
            "CONTAINER": self.container_var.get().strip(),
            "SECRET": self.secret_var.get().strip(),
            "SERVICE": self.service_var.get().strip(),
            "DEPLOYMENT": self.deployment_var.get().strip(),
            "NODE": self.node_var.get().strip(),
            "LOCAL_PORT": self.local_port_var.get().strip(),
            "REMOTE_PORT": self.remote_port_var.get().strip(),
        }
        for key, val in replacements.items():
            result = result.replace("{" + key + "}", val)
        if for_container:
            result = self._normalize_container_curl(result)
        return result

    @staticmethod
    def _normalize_container_curl(cmd):
        """容器内一行命令：curl -sk，去掉 --cacert。"""
        cmd = re.sub(r"curl\s+-s\s+-k\b", "curl -sk", cmd)
        cmd = re.sub(r"curl\s+-s\s+--cacert\s+\S+\s*", "curl -sk ", cmd)
        cmd = re.sub(r"curl\s+-s\b", "curl -sk", cmd)
        return re.sub(r"  +", " ", cmd).strip()

    def _wrap_k8s_container_cmd(self, raw):
        """TOKEN=$(cat ...) curl ... 单行格式（容器内粘贴执行）。"""
        body = self._fill(raw, for_container=True)
        return f"TOKEN=$(cat {SA_TOKEN_PATH}) {body}"

    def _build_cmd_preview_text(self, raw):
        if not raw or raw.startswith("#"):
            return raw or "# 请选择命令"
        if self._is_k8s_api_command(raw, self.current_selected_cmd):
            return self._wrap_k8s_container_cmd(raw)
        return self._fill(raw, for_exec=False)

    def _get_cmd_preview(self):
        if not hasattr(self, "cmd_text"):
            return ""
        return self.cmd_text.get("1.0", tk.END).strip()

    def _set_cmd_preview(self, text):
        self.cmd_text.delete("1.0", tk.END)
        self.cmd_text.insert("1.0", text)

    def _strip_container_token_prefix(self, cmd: str) -> str:
        prefix = f"TOKEN=$(cat {SA_TOKEN_PATH}) "
        if cmd.startswith(prefix):
            return cmd[len(prefix):].strip()
        return cmd.strip()

    def _command_from_preview(self) -> str:
        """执行时优先使用预览框内容；未编辑则仍走模板 _fill。"""
        preview = self._get_cmd_preview()
        if not preview or preview.startswith("#"):
            return ""
        preview = self._strip_container_token_prefix(preview)
        raw = self._get_raw_command()
        if not raw:
            return preview
        default = self._strip_container_token_prefix(self._build_cmd_preview_text(raw))
        if preview == default:
            return self._fill(raw, for_exec=True)
        if "{" in preview and "}" in preview:
            return self._fill(preview, for_exec=True)
        return preview

    def _get_raw_command(self):
        if not self.current_selected_cmd:
            return ""
        mode = self.mode_var.get()
        ex = self.current_selected_cmd.get("exec", "both")
        if ex == "kubectl":
            return self.current_selected_cmd.get("kubectl", "")
        if ex == "curl":
            return self.current_selected_cmd.get("curl", "")
        return self.current_selected_cmd.get(mode, self.current_selected_cmd.get("curl", ""))

    def _update_cmd_preview(self):
        if not hasattr(self, "cmd_text"):
            return
        raw = self._get_raw_command()
        if not raw or raw.startswith("#"):
            self._set_cmd_preview(raw or "# 请选择命令")
            self._update_script_output()
            return
        self._set_cmd_preview(self._build_cmd_preview_text(raw))
        self._update_script_output()

    def _build_shell_script(self):
        raw = self._get_raw_command()
        if not raw or raw.startswith("#"):
            return "#!/bin/bash\n# 请选择命令后自动生成\n"
        name = self.current_selected_cmd["name"] if self.current_selected_cmd else "cmd"
        desc = self.current_selected_cmd.get("desc", "") if self.current_selected_cmd else ""
        lines = [
            "#!/bin/bash",
            f"# K8s Commander — {name}",
            f"# {desc}" if desc else "#",
            f"# {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
            "set -e",
            "",
        ]
        if self._is_k8s_api_command(raw, self.current_selected_cmd):
            lines.append(self._wrap_k8s_container_cmd(raw))
        else:
            lines.append(self._fill(raw, for_exec=False))
        lines.append("")
        return "\n".join(lines)

    def _update_script_output(self):
        if not hasattr(self, "script_txt"):
            return
        self.script_txt.delete("1.0", tk.END)
        self.script_txt.insert("1.0", self._build_shell_script())

    def _copy_cmd(self):
        cmd = self._get_cmd_preview()
        if cmd and not cmd.startswith("#"):
            self.clipboard_clear()
            self.clipboard_append(cmd)
            self._update_status_bar("命令已复制")

    def _copy_script(self):
        text = self.script_txt.get("1.0", tk.END).strip()
        if text and not text.startswith("# 请选择"):
            self.clipboard_clear()
            self.clipboard_append(text)
            self._update_status_bar("脚本已复制")

    def _save_script(self):
        text = self.script_txt.get("1.0", tk.END).strip()
        if not text or text.startswith("# 请选择"):
            messagebox.showinfo("提示", "请先选择命令")
            return
        default = "audit.sh"
        if self.current_selected_cmd:
            default = re.sub(r"[^\w\-]+", "_", self.current_selected_cmd["name"])[:40] + ".sh"
        path = filedialog.asksaveasfilename(defaultextension=".sh", initialfile=default,
                                            filetypes=[("Shell", "*.sh"), ("All", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            self._update_status_bar(f"已保存: {path}")

    def _schedule_env_analyze_confirm(self):
        if self._env_debounce_id:
            self.after_cancel(self._env_debounce_id)
        text = self.env_text.get("1.0", tk.END).strip()
        if text:
            self._env_debounce_id = self.after(400, self._analyze_env_with_confirm)

    def _analyze_env_with_confirm(self):
        self._env_debounce_id = None
        self._analyze_env(offer_navigation=True)

    def _analyze_env(self, offer_navigation=False):
        if self._env_debounce_id:
            self.after_cancel(self._env_debounce_id)
            self._env_debounce_id = None
        text = self.env_text.get("1.0", tk.END)
        env = EnvVarAnalyzer.parse(text)
        result = EnvVarAnalyzer.analyze(env, text)
        self.verdict_lbl.configure(text=result["verdict"])
        self.env_report.delete("1.0", tk.END)
        self.env_report.insert(tk.END, f"共解析 {result['env_count']} 个变量\n\n")
        tag_map = {"sensitive": "sensitive", "cloud": "cloud", "k8s": "k8s"}
        sensitive = [(k, m) for k, m in result["findings"] if k == "sensitive"]
        other = [(k, m) for k, m in result["findings"] if k != "sensitive"]
        if sensitive:
            self.env_report.insert(tk.END, f"── 敏感变量 ({len(sensitive)}) ──\n", "sensitive")
            for _, msg in sensitive:
                self.env_report.insert(tk.END, f"• {msg}\n", "sensitive")
            self.env_report.insert(tk.END, "\n")
        if other:
            self.env_report.insert(tk.END, "── 其他发现 ──\n")
            for kind, msg in other:
                tag = tag_map.get(kind)
                self.env_report.insert(tk.END, f"• {msg}\n", tag)
        if env.get("KUBERNETES_SERVICE_HOST"):
            self.apiserver_var.set(
                f"https://{env['KUBERNETES_SERVICE_HOST']}:{env.get('KUBERNETES_SERVICE_PORT', '443')}"
            )
        if not text.strip():
            self.env_report.insert(tk.END, "\n（环境已清空）\n")
            return
        if offer_navigation:
            self._confirm_and_navigate(result)
        else:
            nav = result.get("nav")
            if nav:
                g, c = nav
                self.env_report.insert(
                    tk.END,
                    f"\n💡 建议跳转: {g} → {c}\n   （点「识别环境」确认跳转）\n",
                    "cloud",
                )

    def _hide_nav_confirm(self):
        self._pending_nav = None
        self.nav_confirm_card.pack_forget()

    def _show_nav_confirm(self, result):
        nav = result.get("nav")
        verdict = result.get("verdict", "未知")
        if not nav:
            self._hide_nav_confirm()
            return
        g, c = nav
        self._pending_nav = (g, c)
        recognized = verdict != "未知" and g != "环境识别"
        if recognized:
            text = f"推荐跳转: {g} → {c}\n环境判定: {verdict}\n是否跳转到该命令分类？"
        else:
            text = f"建议探测: {g} → {c}\n环境判定: {verdict}\n是否跳转到该分类？"
        self.nav_confirm_lbl.configure(text=text)
        self.nav_confirm_card.pack(fill=tk.X, pady=(0, 8), padx=4, after=self.verdict_card)

    def _nav_confirm_yes(self):
        if self._pending_nav:
            g, c = self._pending_nav
            self._set_command_nav(g, c, switch_tab=True)
            self.env_report.insert(tk.END, f"\n✓ 已跳转到: {g} → {c}\n", "cloud")
        self._hide_nav_confirm()

    def _nav_confirm_no(self):
        if self._pending_nav:
            g, c = self._pending_nav
            self.env_report.insert(tk.END, f"\n（已取消跳转，建议: {g} → {c}）\n", "cloud")
        self._hide_nav_confirm()

    def _confirm_and_navigate(self, result):
        self.update_idletasks()
        self._update_status_bar("请确认是否跳转…")
        nav = result.get("nav")
        verdict = result.get("verdict", "未知")
        if not nav:
            self._hide_nav_confirm()
            self.env_report.insert(tk.END, "\n未能推荐跳转目标，请手动选择命令分类。\n", "warn")
            self._update_status_bar("就绪")
            return
        self._show_nav_confirm(result)
        self._update_status_bar("就绪")

    def _show_confirm_dialog(self, title, message, yes_text="确定", no_text="取消", on_yes=None, on_no=None):
        """自定义确认框（比 messagebox 在 Windows 上更可靠）。"""
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.configure(bg=CARD)
        dlg.resizable(False, False)
        dlg.transient(self)

        w, h = 480, 280
        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        dlg.geometry(f"{w}x{h}+{x}+{y}")
        dlg.minsize(w, h)

        tk.Label(dlg, text=title, bg=CARD, fg=ACCENT, font=("Segoe UI", 11, "bold")).pack(
            anchor=tk.W, padx=16, pady=(14, 6)
        )
        tk.Label(dlg, text=message, bg=CARD, fg=TEXT, font=("Segoe UI", 10),
                 justify=tk.LEFT, wraplength=w - 32).pack(anchor=tk.W, padx=16, pady=4, fill=tk.BOTH, expand=True)

        btn_row = tk.Frame(dlg, bg=CARD)
        btn_row.pack(fill=tk.X, padx=16, pady=12)

        def close_yes():
            dlg.grab_release()
            dlg.destroy()
            if on_yes:
                on_yes()

        def close_no():
            dlg.grab_release()
            dlg.destroy()
            if on_no:
                on_no()

        if no_text:
            ttk.Button(btn_row, text=no_text, command=close_no).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text=yes_text, command=close_yes).pack(side=tk.RIGHT, padx=4)

        dlg.protocol("WM_DELETE_WINDOW", close_no if no_text else close_yes)
        dlg.lift()
        dlg.attributes("-topmost", True)
        dlg.focus_force()
        dlg.grab_set()
        self.wait_window(dlg)
        try:
            dlg.attributes("-topmost", False)
        except tk.TclError:
            pass

    def _clear_env(self):
        if self._env_debounce_id:
            self.after_cancel(self._env_debounce_id)
            self._env_debounce_id = None
        self.env_text.delete("1.0", tk.END)
        self.env_report.delete("1.0", tk.END)
        self.verdict_lbl.configure(text="等待输入…")
        self._hide_nav_confirm()

    def _load_local_env(self):
        self.env_text.delete("1.0", tk.END)
        for k, v in sorted(os.environ.items()):
            self.env_text.insert(tk.END, f"{k}={v}\n")
        self._analyze_env_with_confirm()

    def _probe_k8s_env(self):
        self.env_report.insert(tk.END, "\n── IMDS 探测 (并发) ──\n", "cloud")
        for name, url, status, body in EnvironmentDetector.probe_imds(parallel=True):
            self.env_report.insert(tk.END, f"  [{name}] {status}: {url}\n")
            if status == "可达" and body:
                self.env_report.insert(tk.END, f"    {body[:120]}...\n")
        token = self.token_var.get().strip()
        if token:
            ok, ver = EnvironmentDetector.probe_k8s_version(
                self.apiserver_var.get(), token, self.cacert_var.get(), self.skip_tls_var.get())
            self.env_report.insert(tk.END, f"\n── K8s /version ──\n", "k8s")
            self.env_report.insert(tk.END, (ver if ok else f"失败: {ver}") + "\n")
            jwt = EnvironmentDetector.parse_jwt(token)
            if jwt:
                self.env_report.insert(tk.END, f"JWT sub: {jwt.get('sub')}\n")

    def _load_sa_token(self):
        paths = {
            "token": SA_TOKEN_PATH,
            "ns": SA_NS_PATH,
            "ca": SA_CA_PATH,
        }
        loaded = False
        for key, path in paths.items():
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        val = f.read(8192).strip()
                    if key == "token":
                        self.token_var.set(val)
                        loaded = True
                    elif key == "ns":
                        self.ns_var.set(val)
                    elif key == "ca":
                        self.cacert_var.set(path)
                except Exception as e:
                    self._append_log(f"读取 {path} 失败: {e}\n", "danger")
        if loaded:
            self._append_log("[+] SA 凭证已加载\n", "success")
            self._parse_token_ui()
        else:
            messagebox.showwarning("提示", "未找到 SA 挂载路径（可能不在 K8s Pod 内）")

    def _set_busy(self, busy, msg=None):
        self._busy = busy
        if hasattr(self, "run_btn"):
            self.run_btn.configure(state=tk.DISABLED if busy else tk.NORMAL)
        if msg:
            self._update_status_bar(msg, WARN if busy else TEXT2)

    def _make_ssl_context(self, skip_tls=None):
        ctx = ssl.create_default_context()
        if skip_tls is None:
            skip_tls = self.skip_tls_var.get()
        ca = self.cacert_var.get().strip()
        ca_ok = bool(ca and os.path.isfile(ca))
        if skip_tls or not ca_ok:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif ca_ok:
            ctx.load_verify_locations(cafile=ca)
        return ctx, skip_tls or not ca_ok

    def _k8s_api_json(self, path):
        apiserver = self.apiserver_var.get().strip().rstrip("/")
        token = self.token_var.get().strip()
        if not apiserver or not token:
            raise ValueError("需要 API Server 与 Bearer Token")
        if not apiserver.startswith("http"):
            apiserver = "https://" + apiserver
        url = apiserver + path
        headers = {"Authorization": f"Bearer {token}"}
        ca = self.cacert_var.get().strip()
        ca_ok = bool(ca and os.path.isfile(ca))
        user_skip = self.skip_tls_var.get()

        # 尝试顺序：用户配置 → CA 缺失时自动跳过 TLS → SSL 失败时回退跳过 TLS
        try_modes = []
        if user_skip:
            try_modes.append(True)
        elif ca_ok:
            try_modes.append(False)
        else:
            try_modes.append(True)
        if not user_skip and True not in try_modes:
            try_modes.append(True)

        last_err = None
        for skip in try_modes:
            try:
                ctx, _ = self._make_ssl_context(skip_tls=skip)
                req = urllib.request.Request(url, headers=headers)
                with socks_proxy.urlopen(req, context=ctx, timeout=20) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="ignore"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="ignore")[:300]
                raise ValueError(f"HTTP {e.code}: {body or e.reason}") from e
            except ssl.SSLError as e:
                last_err = e
                if skip:
                    break
                continue
            except urllib.error.URLError as e:
                reason = str(e.reason)
                last_err = e
                if "SSL" in reason or "EOF" in reason:
                    if skip:
                        break
                    continue
                raise ValueError(
                    f"无法连接 {apiserver}\n{reason}\n"
                    "请检查 API Server 地址、网络，以及是否在集群外（kubernetes.default.svc 仅 Pod 内可解析）"
                ) from e
            except Exception as e:
                last_err = e
                break

        hint = (
            "SSL/TLS 握手失败（常见于本机运行工具连接集群 API）。\n\n"
            "请尝试：\n"
            "1. 勾选「跳过 TLS 验证 (-k)」\n"
            "2. 确认 API Server 地址可从本机访问\n"
            "3. 在 Pod 内运行工具，或点「加载 SA」获取正确 CA\n"
            "4. Windows 上 CA 路径 /var/run/secrets/... 不存在时需跳过 TLS"
        )
        if last_err:
            # urllib 在 Windows 上偶发 SSL EOF，回退 curl -k
            try:
                return self._k8s_api_json_via_curl(path, skip_tls=True)
            except Exception as curl_err:
                raise ValueError(
                    f"{hint}\n\nurllib: {last_err}\ncurl: {curl_err}"
                ) from curl_err
        raise ValueError(hint)

    def _k8s_api_json_via_curl(self, path, skip_tls=True):
        apiserver = self.apiserver_var.get().strip().rstrip("/")
        token = self.token_var.get().strip()
        if not apiserver.startswith("http"):
            apiserver = "https://" + apiserver
        url = apiserver + path
        curl_exe = self._find_curl_exe()
        cmd = [curl_exe, "-s", "--max-time", "30", "-H", f"Authorization: Bearer {token}"]
        cmd.extend(socks_proxy.curl_proxy_args(url))
        if skip_tls or self.skip_tls_var.get():
            cmd.append("-k")
        else:
            ca = self.cacert_var.get().strip()
            if ca and os.path.isfile(ca):
                cmd.extend(["--cacert", ca])
            else:
                cmd.append("-k")
        cmd.append(url)
        res = subprocess.run(cmd, capture_output=True, timeout=35)
        out = res.stdout.decode("utf-8", errors="ignore")
        err = res.stderr.decode("utf-8", errors="ignore")
        if res.returncode != 0 and not out.strip():
            raise RuntimeError(err or f"curl exit {res.returncode}")
        return json.loads(out)

    def _refresh_resource_tree(self):
        if not self.token_var.get().strip():
            messagebox.showwarning("Token", "请先填写 Bearer Token")
            return
        ca = self.cacert_var.get().strip()
        if (not ca or not os.path.isfile(ca)) and not self.skip_tls_var.get():
            self.skip_tls_var.set(True)
            self._update_status_bar("CA 证书不可用，已自动勾选跳过 TLS", WARN)
        if self._busy:
            return
        self._set_busy(True, "加载资源树…")
        self._executor.submit(self._refresh_resource_tree_worker)

    def _refresh_resource_tree_worker(self):
        err_msg = None
        try:
            pods_data = self._k8s_api_json("/api/v1/pods")
            self.after(0, lambda d=pods_data: self._populate_resource_tree(d))
            self.after(0, lambda: self._update_status_bar("资源树已刷新", SUCCESS))
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda m=err_msg: messagebox.showerror("资源树", m))
            self.after(0, lambda: self._update_status_bar("资源树加载失败", DANGER))
        finally:
            self.after(0, lambda: self._set_busy(False))

    def _populate_resource_tree(self, pods_data):
        self.res_tree.delete(*self.res_tree.get_children())
        self._res_tree_meta = {}
        ns_map = {}
        for pod in pods_data.get("items", []):
            meta = pod.get("metadata", {})
            ns = meta.get("namespace", "default")
            name = meta.get("name", "?")
            if ns not in ns_map:
                ns_id = self.res_tree.insert("", tk.END, text=ns, values=("Namespace",))
                self._res_tree_meta[ns_id] = {"kind": "namespace", "ns": ns}
                ns_map[ns] = ns_id
            pod_id = self.res_tree.insert(ns_map[ns], tk.END, text=name, values=("Pod",))
            self._res_tree_meta[pod_id] = {"kind": "pod", "ns": ns, "pod": name}
            for c in pod.get("spec", {}).get("containers", []):
                cname = c.get("name", "container")
                cid = self.res_tree.insert(pod_id, tk.END, text=cname, values=("Container",))
                self._res_tree_meta[cid] = {"kind": "container", "ns": ns, "pod": name, "container": cname}

    def _on_tree_double_click(self, event=None):
        self._apply_tree_selection()

    def _apply_tree_selection(self):
        sel = self.res_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择 Pod 或 Container 节点")
            return
        meta = self._res_tree_meta.get(sel[0], {})
        if meta.get("kind") in ("pod", "container"):
            self.ns_var.set(meta.get("ns", self.ns_var.get()))
            self.pod_var.set(meta.get("pod", ""))
            if meta.get("container"):
                self.container_var.set(meta["container"])
            self._update_status_bar(f"已填入 Pod: {meta.get('ns')}/{meta.get('pod')}", SUCCESS)
            self._pod_shell_sync_target()
            self.notebook.select(self.tab_pod_shell)
            self.after(200, self._pod_shell_refresh_files)

    def _run_proxy_audit(self):
        self._sync_proxy_from_ui()
        if not socks_proxy.is_enabled():
            messagebox.showwarning(
                "SOCKS5 未启用",
                "请先勾选「启用 SOCKS5 代理」并点击「应用代理」。\n\n"
                "建议先「检测 SOCKS」确认隧道连通，再一键探测。",
            )
            return
        self.notebook.select(self.tab_env)
        self._set_busy(True, "经 SOCKS5 探测中…")
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.env_report.insert(tk.END, f"\n{'=' * 50}\n[{ts}] 经 SOCKS5 探测开始\n", "accent")
        self._append_log(f"\n[{ts}] 经 SOCKS5 一键探测开始\n", "accent")
        self._executor.submit(self._run_proxy_audit_worker)

    def _run_proxy_audit_worker(self):
        def log_report(text, tag=None):
            def _do():
                if tag:
                    self.env_report.insert(tk.END, text, tag)
                else:
                    self.env_report.insert(tk.END, text)
                self.env_report.see(tk.END)
                self._append_log(text, tag)
            self.after(0, _do)

        try:
            proxy_audit.run_proxy_audit(
                apiserver=self.apiserver_var.get(),
                token=self.token_var.get().strip(),
                cacert=self.cacert_var.get(),
                skip_tls=self.skip_tls_var.get(),
                test_url=self.proxy_test_url_var.get(),
                log=log_report,
            )
        except Exception as e:
            log_report(f"探测异常: {e}\n", "danger")
        self.after(0, lambda: self._set_busy(False, "就绪"))

    def _run_full_audit(self):
        if self._busy:
            return
        self._set_busy(True, "一键体检运行中…")
        self._append_log(f"\n{'='*50}\n[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] 一键体检开始\n", "accent")
        self._executor.submit(self._run_full_audit_worker)

    def _run_full_audit_worker(self):
        def log_main(text, tag=None):
            self.after(0, lambda t=text, g=tag: self._append_log(t, g))

        log_main("── [1/4] 本地环境变量筛查 ──\n", "accent")
        if platform.system() == "Windows":
            cmd = 'set | findstr /i "KUBERNETES AWS AZURE GOOGLE GCP ECS K_SERVICE POD HOSTNAME REGION"'
        else:
            cmd = ("env | grep -iE '^(K_|KUBERNETES_|AWS_|ECS_|GOOGLE_|GCP_|AZURE_|POD_|HOSTNAME)' | sort "
                   "|| printenv | head -40")
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, timeout=20)
            out = (res.stdout or res.stderr).decode("utf-8", errors="ignore")
            self.after(0, lambda: self._append_pretty(out or "(无输出)\n"))
        except Exception as e:
            log_main(f"  跳过: {e}\n", "warn")

        log_main("── [2/4] JWT Token 解析 ──\n", "accent")
        token = self.token_var.get().strip()
        if token:
            data = EnvironmentDetector.parse_jwt(token)
            if data:
                for k in ("sub", "iss", "exp"):
                    if k in data:
                        v = data[k]
                        if k == "exp":
                            exp_dt = datetime.datetime.fromtimestamp(v, datetime.timezone.utc)
                            expired = v < time.time()
                            log_main(f"  {k}: {exp_dt} UTC {'[已过期!]' if expired else '[有效]'}\n",
                                     "danger" if expired else "success")
                        else:
                            log_main(f"  {k}: {v}\n")
                self.after(0, self._update_token_panel)
            else:
                log_main("  JWT 解析失败\n", "warn")
        else:
            log_main("  未设置 Token，跳过\n", "warn")

        log_main("── [3/4] 批量 IMDS 扫描 (并发) ──\n", "accent")
        for name, url, status, body in EnvironmentDetector.probe_imds(parallel=True):
            tag = "success" if status == "可达" else "warn"
            log_main(f"  [{name}] {status}  {url}\n", tag)
            if body:
                log_main(f"    {body.replace(chr(10), ' ')[:120]}\n")

        log_main("── [4/4] K8s API /version ──\n", "accent")
        if token:
            ok, ver = EnvironmentDetector.probe_k8s_version(
                self.apiserver_var.get(), token, self.cacert_var.get(), self.skip_tls_var.get())
            log_main((ver if ok else f"失败: {ver}") + "\n", "success" if ok else "danger")
        else:
            log_main("  无 Token，跳过\n", "warn")

        log_main(f"{'='*50}\n一键体检完成\n", "accent")
        self.after(0, lambda: self._set_busy(False))

    def _export_report_md(self):
        text = self.out_txt.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("提示", "输出区为空")
            return
        md = (
            f"# K8s Commander 审计报告\n\n"
            f"- 时间: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"- API: `{self.apiserver_var.get()}`\n"
            f"- Namespace: `{self.ns_var.get()}`\n\n"
            f"## 输出\n\n```\n{text}\n```\n"
        )
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            initialfile=f"audit_{datetime.datetime.now():%Y%m%d_%H%M%S}.md",
            filetypes=[("Markdown", "*.md"), ("All", "*.*")],
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            self._update_status_bar(f"报告已导出: {path}")

    def _highlight_keywords(self):
        patterns = [
            (r"403 Forbidden|401 Unauthorized|Forbidden|denied", "danger"),
            (r"200 OK|\"allowed\":\s*true|\"status\":\s*\"Success\"", "success"),
            (r"\"allowed\":\s*false|failed|error|Error", "warn"),
            (r"Secret|password|token|admin|privileged", "accent"),
        ]
        content = self.out_txt.get("1.0", tk.END)
        for pattern, tag in patterns:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                start = f"1.0+{m.start()}c"
                end = f"1.0+{m.end()}c"
                self.out_txt.tag_add(tag, start, end)

    def _update_token_panel(self):
        if not hasattr(self, "token_info_lbl"):
            return
        token = self.token_var.get().strip()
        if not token:
            self.token_info_lbl.configure(text="未加载", fg=TEXT2)
            return
        data = EnvironmentDetector.parse_jwt(token)
        if not data:
            self.token_info_lbl.configure(text=f"非 JWT 或格式无效（长度 {len(token)}）", fg=WARN)
            return
        parts = []
        for k in ("sub", "iss", "aud"):
            if k in data:
                parts.append(f"{k}={data[k]}")
        ns_key = "kubernetes.io/serviceaccount/namespace"
        if ns_key in data:
            parts.append(f"ns={data[ns_key]}")
        expired = False
        if "exp" in data:
            exp_ts = data["exp"]
            exp = datetime.datetime.fromtimestamp(exp_ts, datetime.timezone.utc)
            expired = exp_ts < time.time()
            parts.append(f"exp={exp:%Y-%m-%d %H:%M} UTC")
            parts.append("已过期!" if expired else "有效")
        self.token_info_lbl.configure(
            text=" | ".join(parts) if parts else "JWT 已解析",
            fg=DANGER if expired else CYAN,
        )

    def _parse_token_ui(self):
        token = self.token_var.get().strip()
        data = EnvironmentDetector.parse_jwt(token)
        if not data:
            self._append_log("[-] JWT 解析失败\n", "warn")
            self._update_token_panel()
            return
        self._append_log("── JWT Payload ──\n", "accent")
        for k in ("sub", "iss", "aud", "exp"):
            if k in data:
                v = data[k]
                if k == "exp":
                    v = datetime.datetime.fromtimestamp(v, datetime.timezone.utc)
                self._append_log(f"  {k}: {v}\n")
        ns_key = "kubernetes.io/serviceaccount/namespace"
        if ns_key in data:
            self.ns_var.set(data[ns_key])
            self._append_log(f"  namespace: {data[ns_key]}\n")
        self._update_token_panel()

    def _validate_token(self):
        if not self.current_selected_cmd:
            return False
        tags = self.current_selected_cmd.get("tags", [])
        ex = self.current_selected_cmd.get("exec", "both")
        if "k8s_conn" not in tags:
            return True
        if ex in ("curl", "both") and self.mode_var.get() == "curl":
            if not self._resolve_exec_token():
                messagebox.showwarning(
                    "Token",
                    "K8s API 命令需要 Bearer Token。\n\n"
                    "请填写 Token，或在容器内通过「加载 SA」读取，"
                    f"或复制下方脚本到 Pod 内执行（自动 cat {SA_TOKEN_PATH}）。",
                )
                return False
        return True

    def _append_log(self, text, tag=None):
        self.out_txt.insert(tk.END, text, tag)
        self.out_txt.see(tk.END)
        self._highlight_keywords()

    def _append_syntax_json(self, formatted):
        base_line = int(self.out_txt.index(tk.END).split(".")[0])
        self.out_txt.insert(tk.END, formatted + "\n")
        for i, line in enumerate(formatted.splitlines()):
            line_no = base_line + i
            for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*:', line):
                self.out_txt.tag_add("json_key", f"{line_no}.{m.start()}", f"{line_no}.{m.end()}")
            for m in re.finditer(r':\s*"([^"\\]*(?:\\.[^"\\]*)*)"', line):
                self.out_txt.tag_add("json_str", f"{line_no}.{m.start(1)}", f"{line_no}.{m.end(1)}")
            for m in re.finditer(r":\s*(-?\d+(?:\.\d+)?)(?=[,\s}\]])", line):
                self.out_txt.tag_add("json_num", f"{line_no}.{m.start(1)}", f"{line_no}.{m.end(1)}")
            for m in re.finditer(r":\s*(true|false|null)", line):
                self.out_txt.tag_add("json_bool", f"{line_no}.{m.start(1)}", f"{line_no}.{m.end(1)}")

    def _append_pretty(self, raw):
        s = raw.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                self._append_syntax_json(json.dumps(json.loads(s), indent=2, ensure_ascii=False))
                return
            except Exception:
                pass
        self._append_log(raw + ("\n" if not raw.endswith("\n") else ""))

    def _save_output(self):
        text = self.out_txt.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("提示", "输出区为空")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"output_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt",
            filetypes=[("Text", "*.txt"), ("JSON", "*.json"), ("All", "*.*")],
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self._update_status_bar(f"输出已保存: {path}")

    def _decode_base64_selection(self):
        try:
            text = self.out_txt.get(tk.SEL_FIRST, tk.SEL_LAST).strip()
        except tk.TclError:
            text = self.out_txt.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("提示", "请先选中要解码的文本")
            return
        # 取最长连续 base64 片段
        candidates = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text)
        blob = max(candidates, key=len) if candidates else text.replace("\n", "").replace(" ", "")
        try:
            pad = "=" * (-len(blob) % 4)
            decoded = base64.b64decode(blob + pad).decode("utf-8", errors="replace")
            self._append_log("\n── Base64 解码 ──\n", "accent")
            self._append_pretty(decoded)
        except Exception as e:
            self._append_log(f"[-] Base64 解码失败: {e}\n", "danger")

    def _batch_imds_scan(self):
        if self._busy:
            return
        self._set_busy(True, "IMDS 并发扫描中…")
        self._append_log(f"\n[{datetime.datetime.now():%H:%M:%S}] ── 批量 IMDS 扫描 (线程池) ──\n", "accent")
        self._executor.submit(self._batch_imds_worker)

    def _batch_imds_worker(self):
        for name, url, status, body in EnvironmentDetector.probe_imds(parallel=True):
            tag = "success" if status == "可达" else "warn"
            self.after(0, lambda n=name, u=url, s=status, t=tag: self._append_log(f"[{n}] {s}  {u}\n", t))
            if body:
                preview = body.replace("\n", " ")[:160]
                self.after(0, lambda p=preview: self._append_log(f"  {p}\n"))
        self.after(0, lambda: self._set_busy(False))
        self.after(0, lambda: self._update_status_bar("IMDS 扫描完成"))

    def _execute_current_command(self):
        if not self.current_selected_cmd:
            messagebox.showinfo("提示", "请选择命令")
            return
        if self._busy:
            return
        name = self.current_selected_cmd.get("name", "")
        ex = self.current_selected_cmd.get("exec", "both")
        if ex == "detect":
            if name == "刷新资源树" or "资源树" in name:
                self._refresh_resource_tree()
            elif "一键" in name:
                self._run_full_audit()
            else:
                self._probe_k8s_env()
            return
        if ex == "local":
            cmd = self._get_cmd_preview()
            if not cmd or cmd.startswith("#"):
                return
            self._set_busy(True, "本地执行中…")
            self._executor.submit(self._exec_local_worker, cmd)
            return
        if not self._validate_token():
            return
        cmd = self._command_from_preview()
        if not cmd or cmd.startswith("#"):
            return
        self._set_busy(True, "执行中…")
        self._executor.submit(self._exec_worker, cmd)

    def _exec_local_worker(self, cmd_str):
        try:
            self.after(0, lambda: self._append_log(f"\n[{datetime.datetime.now():%H:%M:%S}] {cmd_str[:100]}\n", "accent"))
            res = subprocess.run(cmd_str, shell=True, capture_output=True, timeout=60)
            out = res.stdout.decode("utf-8", errors="ignore")
            err = res.stderr.decode("utf-8", errors="ignore")
            if out:
                self.after(0, lambda: self._append_pretty(out))
            if err:
                self.after(0, lambda: self._append_log(err + "\n", "danger"))
        except subprocess.TimeoutExpired:
            self.after(0, lambda: self._append_log("[-] 超时\n", "danger"))
        except Exception as e:
            self.after(0, lambda: self._append_log(f"[-] {e}\n", "danger"))
        finally:
            self.after(0, lambda: self._set_busy(False))

    def _find_curl_exe(self):
        if platform.system() == "Windows":
            for p in ["curl.exe", r"C:\Windows\System32\curl.exe"]:
                try:
                    subprocess.run([p, "--version"], capture_output=True, timeout=3)
                    return p
                except Exception:
                    continue
        return "curl"

    def _exec_worker(self, cmd_str):
        self._append_log(f"\n[{datetime.datetime.now():%H:%M:%S}] {cmd_str[:80]}…\n", "accent")
        mode = self.mode_var.get()
        ex = self.current_selected_cmd.get("exec", "both") if self.current_selected_cmd else "both"

        use_curl = (mode == "curl" and ex in ("curl", "both") and cmd_str.strip().startswith("curl"))
        use_kubectl = (mode == "kubectl" or ex == "kubectl") and not use_curl

        if use_curl and platform.system() == "Windows" and cmd_str.startswith("curl "):
            curl_exe = self._find_curl_exe()
            cmd_str = curl_exe + cmd_str[4:]

        if use_curl and ("http://" in cmd_str or "https://" in cmd_str):
            self._urllib_curl(cmd_str)
        else:
            try:
                res = subprocess.run(cmd_str, shell=True, capture_output=True, timeout=30)
                out = res.stdout.decode("utf-8", errors="ignore")
                err = res.stderr.decode("utf-8", errors="ignore")
                if out:
                    self._append_pretty(out)
                if err:
                    self._append_log(err + "\n", "danger")
            except subprocess.TimeoutExpired:
                self._append_log("[-] 超时\n", "danger")
            except Exception as e:
                self._append_log(f"[-] {e}\n", "danger")

        self.after(0, lambda: self._set_busy(False))

    def _urllib_curl(self, curl_cmd):
        try:
            tokens = shlex.split(curl_cmd)
        except Exception:
            tokens = curl_cmd.split()
        url, headers, method, data = None, {}, "GET", None
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in ("-H", "--header") and i + 1 < len(tokens):
                h = tokens[i + 1]
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 2
            elif t in ("-X", "--request") and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
            elif t in ("-d", "--data") and i + 1 < len(tokens):
                data = tokens[i + 1].encode("utf-8")
                i += 2
            elif t in ("-k", "--insecure"):
                i += 1
            elif t.startswith("http://") or t.startswith("https://"):
                url = t
                i += 1
            else:
                i += 1
        if not url:
            for t in tokens:
                if "://" in t or "169.254" in t or "metadata" in t:
                    url = t if "://" in t else "http://" + t
                    break
        if not url:
            self._append_log("[-] 无法解析 URL\n", "warn")
            return
        try:
            ctx = ssl.create_default_context()
            if self.skip_tls_var.get() or "-k" in curl_cmd:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ca = self.cacert_var.get().strip()
                if ca and os.path.isfile(ca):
                    ctx.load_verify_locations(cafile=ca)
            req = urllib.request.Request(url, headers=headers, method=method, data=data)
            with socks_proxy.urlopen(req, context=ctx, timeout=8) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                self._append_log(f"[+] HTTP {resp.status}\n", "success")
                self._append_pretty(body)
        except urllib.error.HTTPError as e:
            self._append_log(f"[-] HTTP {e.code}\n", "warn")
            try:
                self._append_pretty(e.read().decode("utf-8", errors="ignore"))
            except Exception:
                pass
        except Exception as e:
            self._append_log(f"[-] {e}\n", "danger")

    def _load_config(self):
        migrate_legacy_config()
        if not os.path.isfile(CONFIG_PATH):
            return
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.apiserver_var.set(cfg.get("apiserver", self.apiserver_var.get()))
            self.ns_var.set(cfg.get("namespace", "default"))
            self.cacert_var.set(cfg.get("cacert", self.cacert_var.get()))
            self.node_ip_var.set(cfg.get("node_ip", "127.0.0.1"))
            self.role_name_var.set(cfg.get("role_name", "my-role"))
            self.configmap_var.set(cfg.get("configmap", self.configmap_var.get()))
            self.pod_var.set(cfg.get("pod", self.pod_var.get()))
            self.secret_var.set(cfg.get("secret", self.secret_var.get()))
            self.deployment_var.set(cfg.get("deployment", self.deployment_var.get()))
            self.service_var.set(cfg.get("service", self.service_var.get()))
            self.node_var.set(cfg.get("node", self.node_var.get()))
            self.local_port_var.set(cfg.get("local_port", self.local_port_var.get()))
            self.remote_port_var.set(cfg.get("remote_port", self.remote_port_var.get()))
            self.skip_tls_var.set(cfg.get("skip_tls", self.skip_tls_var.get()))
            self.mode_var.set(cfg.get("mode", "curl"))
            self.group_var.set(cfg.get("group", "K8s"))
            proxy = cfg.get("proxy", {})
            if proxy:
                self.proxy_enabled_var.set(proxy.get("enabled", False))
                self.proxy_host_var.set(proxy.get("host", "127.0.0.1"))
                self.proxy_port_var.set(proxy.get("port", "1080"))
                self.proxy_user_var.set(proxy.get("username", ""))
                self.proxy_pass_var.set(proxy.get("password", ""))
                self.proxy_test_url_var.set(proxy.get("test_url", ""))
                socks_proxy.load_config(proxy)
                if hasattr(self, "proxy_status_lbl"):
                    self.proxy_status_lbl.configure(text=socks_proxy.describe_status())
            ai = cfg.get("ai", {})
            if ai:
                self.ai_provider_var.set(ai.get("provider", self.ai_provider_var.get()))
                self.ai_api_key_var.set(ai.get("api_key", ""))
                self.ai_base_url_var.set(ai.get("base_url", self.ai_base_url_var.get()))
                self.ai_model_var.set(ai.get("model", self.ai_model_var.get()))
                self.ai_format_var.set(ai.get("format", "openai"))
                self.ai_auto_save_var.set(ai.get("auto_save", False))
                if hasattr(self, "ai_model_cb"):
                    self._refresh_ai_model_choices()
                if hasattr(self, "ai_autosave_btn"):
                    self._sync_ai_autosave_btn()
        except json.JSONDecodeError:
            bak = CONFIG_PATH + ".bak." + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            try:
                shutil.copy2(CONFIG_PATH, bak)
                msg = f"配置 JSON 损坏，已备份至 {bak}，使用默认配置"
            except Exception:
                msg = "配置 JSON 损坏且备份失败，使用默认配置"
            if hasattr(self, "status_info"):
                self._update_status_bar(msg, WARN)
        except PermissionError:
            if hasattr(self, "status_info"):
                self._update_status_bar("无权限读取配置文件，使用默认配置", WARN)
        except Exception as e:
            if hasattr(self, "status_info"):
                self._update_status_bar(f"加载配置失败: {e}", WARN)
        if hasattr(self, "ai_provider_var"):
            self.after(400, self._schedule_ai_models_fetch)

    def _persist_config(self):
        """保存当前配置到程序目录 data/config.json。"""
        try:
            ensure_data_dirs()
            cfg = {}
            if os.path.isfile(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            cfg.update({
                "apiserver": self.apiserver_var.get(),
                "namespace": self.ns_var.get(),
                "cacert": self.cacert_var.get(),
                "node_ip": self.node_ip_var.get(),
                "role_name": self.role_name_var.get(),
                "configmap": self.configmap_var.get(),
                "pod": self.pod_var.get(),
                "secret": self.secret_var.get(),
                "deployment": self.deployment_var.get(),
                "service": self.service_var.get(),
                "container": self.container_var.get(),
                "node": self.node_var.get(),
                "local_port": self.local_port_var.get(),
                "remote_port": self.remote_port_var.get(),
                "skip_tls": self.skip_tls_var.get(),
                "mode": self.mode_var.get(),
                "group": self.group_var.get(),
                "ai": {
                    "provider": self.ai_provider_var.get(),
                    "api_key": self.ai_api_key_var.get(),
                    "base_url": self.ai_base_url_var.get(),
                    "model": self.ai_model_var.get(),
                    "format": self.ai_format_var.get(),
                    "auto_save": self.ai_auto_save_var.get(),
                },
                "proxy": {
                    "enabled": self.proxy_enabled_var.get(),
                    "host": self.proxy_host_var.get(),
                    "port": self.proxy_port_var.get(),
                    "username": self.proxy_user_var.get(),
                    "password": self.proxy_pass_var.get(),
                    "test_url": self.proxy_test_url_var.get(),
                },
            })
            self._sync_proxy_from_ui()
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.warning("保存配置失败: %s", e)
            return False

    def _save_config_and_exit(self):
        if not self._persist_config():
            messagebox.showwarning("保存配置", f"无法保存配置，详见 {LOG_PATH}")
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._executor.shutdown(wait=False)
        self.destroy()
