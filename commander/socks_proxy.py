"""SOCKS5 代理：统一 urllib / curl 出口。"""
from __future__ import annotations

import platform
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse
# 全局单例配置（由 GUI「应用代理」写入）
_config = {
    "enabled": False,
    "host": "127.0.0.1",
    "port": "1080",
    "username": "",
    "password": "",
}

# link-local / 本机 / 云元数据 — 不走 SOCKS（IMDS 等需直连）
_BYPASS_HOSTS = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.tencentyun.com",
})
_BYPASS_PREFIXES = (
    "127.",
    "169.254.",
    "100.100.100.",  # 阿里云 IMDS
    "100.96.0.",     # 火山引擎 IMDS
)


def pysocks_available() -> bool:
    try:
        import socks  # noqa: F401
        return True
    except ImportError:
        return False


def get_config() -> dict:
    return dict(_config)


def apply_config(enabled, host, port, username="", password=""):
    """应用 SOCKS5 配置（GUI 调用）。"""
    _config["enabled"] = bool(enabled)
    _config["host"] = (host or "").strip()
    _config["port"] = str(port or "").strip()
    _config["username"] = (username or "").strip()
    _config["password"] = password or ""


def load_config(data: Optional[dict] = None):
    if not data:
        return
    apply_config(
        data.get("enabled", False),
        data.get("host", "127.0.0.1"),
        data.get("port", "1080"),
        data.get("username", ""),
        data.get("password", ""),
    )


def config_to_dict() -> dict:
    return {
        "enabled": _config["enabled"],
        "host": _config["host"],
        "port": _config["port"],
        "username": _config["username"],
        "password": _config["password"],
    }


def is_enabled() -> bool:
    return bool(_config["enabled"] and _config["host"] and _config["port"])


def should_bypass(url: str) -> bool:
    """元数据 / 本机地址不走代理。"""
    if not url:
        return True
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    if not host:
        return True
    if host in _BYPASS_HOSTS:
        return True
    return any(host.startswith(p) for p in _BYPASS_PREFIXES)


def find_curl_exe() -> str:
    if platform.system() == "Windows":
        for p in ("curl.exe", r"C:\Windows\System32\curl.exe"):
            try:
                subprocess.run([p, "--version"], capture_output=True, timeout=3)
                return p
            except (OSError, subprocess.TimeoutExpired):
                continue
    return "curl"


class _HttpResponse:
    """兼容 urllib 的简易响应（经 curl SOCKS 时使用）。"""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def http_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 15,
    skip_tls: bool = True,
    *,
    force_direct: bool = False,
    force_proxy: bool = False,
) -> Tuple[Optional[int], str]:
    """
    HTTP(S) 请求。经 SOCKS 时优先 curl --socks5-hostname（Neo-reGeorg 兼容）。
    返回 (status_code, body)；失败时 status 为 None，body 为错误信息。
    """
    headers = dict(headers or {})
    use_proxy = (
        is_enabled()
        and not force_direct
        and (force_proxy or not should_bypass(url))
    )
    if use_proxy:
        return _http_via_curl(url, method, headers, data, timeout, skip_tls, force_proxy=True)
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        ctx = None
        if url.startswith("https://"):
            ctx = ssl.create_default_context()
            if skip_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        kw = {"timeout": timeout}
        if ctx is not None:
            kw["context"] = ctx
        with urllib.request.urlopen(req, **kw) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return resp.status, body[:2000]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")[:2000]
        return e.code, body
    except Exception as e:
        return None, str(e)


def _metadata_curl_flags(url: str) -> List[str]:
    """与手动 curl 对齐：metadata.google.internal 不用 -4/--http1.1（-4 会导致 Empty reply）。"""
    flags: List[str] = []
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return flags
    if host.startswith("169.254."):
        flags.append("-4")
    if platform.system() == "Windows" and url.startswith("https://"):
        flags.append("--ssl-no-revoke")
    return flags


def _gcp_metadata_headers(url: str, headers: Dict[str, str]) -> Dict[str, str]:
    """GCP metadata：IP 访问时需 Host + Metadata-Flavor。"""
    headers = dict(headers)
    if "computeMetadata" in url or "metadata.google" in url:
        headers.setdefault("Metadata-Flavor", "Google")
    if "169.254.169.254/computeMetadata" in url:
        headers.setdefault("Host", "metadata.google.internal")
    return headers


def _http_via_curl(
    url: str,
    method: str,
    headers: Dict[str, str],
    data: Optional[bytes],
    timeout: int,
    skip_tls: bool,
    force_proxy: bool,
) -> Tuple[Optional[int], str]:
    headers = _gcp_metadata_headers(url, headers)
    marker = "\n__CURL_HTTP_CODE__"
    cmd = [
        find_curl_exe(), "-s", "--max-time", str(timeout),
        "-w", f"{marker}%{{http_code}}",
    ]
    cmd.extend(_metadata_curl_flags(url))
    cmd.extend(curl_proxy_args(url, force_proxy=force_proxy))
    if skip_tls and url.startswith("https://"):
        cmd.append("-k")
    method = method.upper()
    if method != "GET":
        cmd.extend(["-X", method])
    for key, val in headers.items():
        cmd.extend(["-H", f"{key}: {val}"])
    if data is not None:
        cmd.extend(["--data-binary", data if isinstance(data, (bytes, bytearray)) else str(data).encode()])
    cmd.append(url)
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout + 8)
    except subprocess.TimeoutExpired:
        return None, f"curl 超时 ({timeout}s): {url}"
    except OSError as e:
        return None, f"curl 不可用: {e}"
    out = (res.stdout or b"").decode("utf-8", errors="ignore")
    err = (res.stderr or b"").decode("utf-8", errors="ignore").strip()
    if marker in out:
        body, _, code_str = out.rpartition(marker)
        if code_str.isdigit():
            code = int(code_str)
            if code > 0:
                return code, body[:2000]
            return None, (err or body or f"curl 未收到 HTTP 响应 (code 0): {url}").strip()[:500]
    if res.returncode != 0:
        return None, (err or out or f"curl exit {res.returncode}").strip()[:500]
    return 200, out[:2000]


def _proxy_url() -> Optional[str]:
    if not is_enabled():
        return None
    host = _config["host"]
    port = _config["port"]
    user = _config["username"]
    pwd = _config["password"]
    if user:
        auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@"
    else:
        auth = ""
    return f"socks5h://{auth}{host}:{port}"


def _socks_handler():
    """PySocks 的 SocksiPyHandler（urllib ProxyHandler 不支持 socks5h://）。"""
    if not pysocks_available():
        raise RuntimeError("未安装 PySocks，请运行: pip install PySocks")
    import socks
    from sockshandler import SocksiPyHandler

    host = _config["host"] or "127.0.0.1"
    port = int(_config["port"])
    user = (_config["username"] or "").strip()
    pwd = _config["password"] or ""
    if user:
        return SocksiPyHandler(
            socks.SOCKS5, host, port, rdns=True, username=user, password=pwd,
        )
    return SocksiPyHandler(socks.SOCKS5, host, port, rdns=True)


def build_opener(ssl_context=None):
    """构建 urllib opener；启用代理时用 SocksiPyHandler（DNS 经代理解析）。"""
    handlers = []
    if is_enabled():
        handlers.append(_socks_handler())
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    return urllib.request.build_opener(*handlers)


def urlopen(request, context=None, timeout=20, *, force_direct=False, force_proxy=False):
    """
    统一 HTTP(S) 出口。
    force_direct=True 时不走代理。
    force_proxy=True 时强制经 SOCKS（含 IMDS 等 bypass 地址，用于隧道内探测）。
    经 SOCKS 时走 curl --socks5-hostname（与 Neo-reGeorg 手动测试一致）。
    """
    url = request.full_url if hasattr(request, "full_url") else str(request)
    use_proxy = (
        is_enabled()
        and not force_direct
        and (force_proxy or not should_bypass(url))
    )

    if use_proxy:
        method = request.get_method() if hasattr(request, "get_method") else getattr(request, "method", "GET")
        headers = dict(request.header_items()) if hasattr(request, "header_items") else {}
        data = getattr(request, "data", None)
        skip_tls = True
        if context is not None:
            skip_tls = (
                not context.check_hostname
                or context.verify_mode == ssl.CERT_NONE
            )
        status, body = http_fetch(
            url, method, headers, data, int(timeout), skip_tls,
            force_proxy=force_proxy,
        )
        if status is None:
            raise urllib.error.URLError(body)
        body_bytes = body.encode("utf-8", errors="ignore")
        if status >= 400:
            raise urllib.error.HTTPError(url, status, body[:120], headers, _HttpResponse(status, body_bytes))
        return _HttpResponse(status, body_bytes)

    if context is not None:
        return urllib.request.urlopen(request, context=context, timeout=timeout)
    return urllib.request.urlopen(request, timeout=timeout)


def curl_proxy_args(url: Optional[str] = None, force_proxy: bool = False) -> List[str]:
    """返回 curl 的 SOCKS5 参数；url 在 bypass 列表且未 force_proxy 时返回空。"""
    if not is_enabled():
        return []
    if url and should_bypass(url) and not force_proxy:
        return []
    host = _config["host"]
    port = _config["port"]
    args = ["--socks5-hostname", f"{host}:{port}"]
    user = _config["username"]
    if user:
        args.extend(["--proxy-user", f"{user}:{_config['password']}"])
    return args


def describe_status() -> str:
    if not is_enabled():
        return "未启用"
    return f"SOCKS5 {_config['host']}:{_config['port']}"


def probe_local_port(timeout=3) -> Tuple[bool, str]:
    """检测本机 SOCKS 端口是否在监听（Neo-reGeorg 等是否已启动）。"""
    if not is_enabled():
        return False, "代理未启用"
    host = _config["host"] or "127.0.0.1"
    port = int(_config["port"])
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, f"本机 {host}:{port} TCP 端口可达"
    except OSError as e:
        return False, f"无法连接本机 {host}:{port}：{e}\n请确认 Neo-reGeorg 已启动：neoreg -l 127.0.0.1 -p 1080 -vv"


def verify_socks5_handshake(timeout=5) -> Tuple[bool, str]:
    """
    发送标准 SOCKS5 握手，确认 1080 上是 SOCKS5 而非 HTTP 代理。
    Neo-reGeorg 报 Only support Socks5 protocol = 有客户端用 HTTP 连了 SOCKS 端口。
    """
    if not is_enabled():
        return False, "代理未启用"
    host = _config["host"] or "127.0.0.1"
    port = int(_config["port"])
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, 1 method, no auth
        resp = sock.recv(2)
        if len(resp) >= 2 and resp[0] == 0x05:
            return True, f"SOCKS5 协议握手正常（{host}:{port}）"
        if resp[:1] in (b"G", b"P", b"C") or resp.startswith(b"HTTP"):
            return False, (
                f"{host}:{port} 返回 HTTP 响应，不是 SOCKS5。\n"
                "请确认 Neo-reGeorg 使用 -l -p 开启 SOCKS5，且未把系统代理设成 HTTP://127.0.0.1:1080"
            )
        return False, f"非 SOCKS5 响应 {resp!r}；Neo-reGeorg 需 SOCKS5 客户端（本程序已用 PySocks）"
    except OSError as e:
        return False, f"SOCKS5 握手失败：{e}"
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def _format_test_error(exc: Exception, test_url: str) -> str:
    msg = str(exc)
    if "timed out" in msg.lower() or "timeout" in msg.lower():
        host = urlparse(test_url if "://" in test_url else f"https://{test_url}").hostname or test_url
        extra = ""
        if "kubernetes.default" in host:
            extra = (
                "\n\n⚠ kubernetes.default.svc 只能在 Pod/节点内解析！\n"
                "经 Neo-reGeorg 隧道请改用真实 IP，例如：\n"
                "  https://10.96.0.1:443/version\n"
                "  https://<master-ip>:6443/version"
            )
        return f"经 SOCKS 访问超时：{test_url}\n{msg}{extra}"
    if "0x05" in msg or "Connection refused" in msg:
        return (
            f"经 SOCKS 访问目标被拒绝：{test_url}\n"
            f"详情：{msg}\n\n"
            "常见原因（Neo-reGeorg / 内网隧道）：\n"
            "• 本地 1080 已连通，但隧道另一端无法访问该目标\n"
            "• 请改用「测试 URL」填内网 API（如 https://10.x.x.x:6443/version）\n"
            "• 确认 neoreg 已连上 webshell"
        )
    if "0x04" in msg or "Host unreachable" in msg:
        return f"经 SOCKS 无法到达目标：{test_url}\n{msg}"
    return f"{test_url}\n{msg}"


def verify_socks5_tunnel_connect(
    target_host: str = "ifconfig.me",
    target_port: int = 80,
    timeout: int = 12,
    http_probe: bool = True,
) -> Tuple[bool, str]:
    """经 SOCKS5 实际 CONNECT 到目标，验证隧道是否真正可用（与 curl --socks5-hostname 等效）。"""
    if not pysocks_available():
        return False, "未安装 PySocks"
    import socks

    host = _config["host"] or "127.0.0.1"
    port = int(_config["port"])
    user = _config["username"]
    pwd = _config["password"]
    sock = socks.socksocket()
    try:
        if user:
            sock.set_proxy(socks.SOCKS5, host, port, username=user, password=pwd)
        else:
            sock.set_proxy(socks.SOCKS5, host, port)
        sock.settimeout(timeout)
        sock.connect((target_host, target_port))
        base_ok = f"隧道 CONNECT 成功 → {target_host}:{target_port}"
        if not http_probe or target_port != 80:
            return True, base_ok
        try:
            sock.settimeout(min(6, timeout))
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
            )
            data = sock.recv(1024)
            if data:
                body = data.decode("utf-8", errors="ignore")
                snippet = body.strip().split("\n")[-1][:40] if body else ""
                detail = f"（{snippet}）" if snippet else ""
                return True, f"隧道连通成功 → {target_host}:{target_port}{detail}"
            return True, (
                f"{base_ok}（{target_host} 无 HTTP 响应，内网 webshell 常见，隧道仍可用）"
            )
        except (socket.timeout, TimeoutError, OSError):
            return True, (
                f"{base_ok}（外网 {target_host} 不可达，内网隧道仍可用；"
                f"建议在「探测 URL」填内网地址验证）"
            )
    except Exception as e:
        return False, f"隧道连接失败 → {target_host}:{target_port}：{e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _step_line(ok: bool, label: str, detail: str) -> str:
    mark = "✓" if ok else "✗"
    return f"  {mark} {label}：{detail}"


def test_connection(test_urls: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    三步检测 SOCKS5 是否连接成功：
    ① TCP 端口  ② SOCKS5 握手  ③ 经代理隧道连通（默认 ifconfig.me:80）
    三步全部通过 → 连接成功；任一步失败 → 连接失败。
    """
    if not is_enabled():
        return False, "代理未启用"
    if not pysocks_available():
        return False, "未安装 PySocks（pip install PySocks）"

    lines = ["SOCKS5 连接检测", ""]

    ok_port, port_msg = probe_local_port()
    lines.append(_step_line(ok_port, "TCP 端口", port_msg))
    if not ok_port:
        lines.extend(["", "结论：连接失败（Neo-reGeorg 未监听或端口错误）"])
        return False, "\n".join(lines)

    ok_socks, socks_msg = verify_socks5_handshake()
    lines.append(_step_line(ok_socks, "SOCKS5 握手", socks_msg))
    if not ok_socks:
        lines.extend([
            "",
            "结论：连接失败（1080 不是 SOCKS5 或被 HTTP 代理占用）",
            "提示：关闭系统 HTTP 代理；Neo-reGeorg 用 -l 127.0.0.1 -p 1080",
        ])
        return False, "\n".join(lines)

    urls = [u.strip() for u in (test_urls or []) if u and u.strip()]
    if urls:
        url = urls[0]
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")
        try:
            status, body = http_fetch(url, "GET", timeout=15, skip_tls=True, force_proxy=True)
            if status is None:
                raise urllib.error.URLError(body)
            if status >= 400:
                raise urllib.error.URLError(f"HTTP {status}: {body[:120]}")
            lines.append(_step_line(True, "隧道 HTTP", f"访问成功 → {url}"))
        except Exception as e:
            lines.append(_step_line(False, "隧道 HTTP", _format_test_error(e, url).replace("\n", " ")))
            lines.extend(["", "结论：连接失败（握手正常但隧道无法访问目标）"])
            return False, "\n".join(lines)
    else:
        ok_tunnel, tunnel_msg = verify_socks5_tunnel_connect()
        lines.append(_step_line(ok_tunnel, "隧道连通", tunnel_msg))
        if not ok_tunnel:
            lines.extend([
                "",
                "结论：连接失败（SOCKS 握手正常，但隧道未通）",
                "提示：确认 Neo-reGeorg 已连上 webshell（窗口显示 All seems fine）",
            ])
            return False, "\n".join(lines)
        if "内网" in tunnel_msg or "无 HTTP 响应" in tunnel_msg or "不可达" in tunnel_msg:
            lines.extend([
                "",
                "  ⚠ 外网探测受限，但 SOCKS 隧道已建立，可经代理访问内网 K8s / IMDS",
                "  建议：在「探测 URL」填写内网地址（如 K8s API 或 169.254.169.254）",
            ])

    host = _config["host"] or "127.0.0.1"
    port = _config["port"]
    lines.extend([
        "",
        "结论：连接成功 ✓",
        "",
        f"手动：curl --socks5-hostname {host}:{port} http://metadata.google.internal/computeMetadata/v1/ -H \"Metadata-Flavor: Google\"",
        "程序内经 SOCKS 的请求同样走 curl --socks5-hostname。",
    ])
    return True, "\n".join(lines)