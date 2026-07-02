"""云/容器环境探测器（IMDS 等）。"""
import json
import os
import ssl
import urllib.error
import urllib.request

from commander import socks_proxy
from concurrent.futures import ThreadPoolExecutor, as_completed


class EnvironmentDetector:
    IMDS_ENDPOINTS = [
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/", 8, {"Metadata-Flavor": "Google"}),
        ("GCP 169.254", "http://169.254.169.254/computeMetadata/v1/", 8, {"Metadata-Flavor": "Google"}),
        ("AWS/通用 v1", "http://169.254.169.254/latest/meta-data/", 3, {}),
        ("阿里云 v1", "http://100.100.100.200/latest/meta-data/", 3, {}),
        ("腾讯云", "http://metadata.tencentyun.com/latest/meta-data/", 3, {}),
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", 3, {"Metadata": "true"}),
        ("Oracle OCI", "http://169.254.169.254/opc/v2/instance/", 3, {"Authorization": "Bearer Oracle"}),
        ("IBM Cloud", "http://169.254.169.254/metadata/v1/instance", 3, {}),
        ("火山引擎", "http://100.96.0.96/volcstack/latest/meta-data/", 3, {}),
    ]

    @staticmethod
    def _http_request(url, method="GET", headers=None, timeout=3, data=None, via_proxy=False):
        try:
            kw = {"force_proxy": True} if via_proxy else {"force_direct": True}
            status, body = socks_proxy.http_fetch(
                url, method, headers, data, timeout, skip_tls=True, **kw,
            )
            if status is None:
                return None, body
            return status, body[:2000]
        except Exception as e:
            return None, str(e)

    @staticmethod
    def _http_get(url, headers=None, timeout=3, via_proxy=False):
        return EnvironmentDetector._http_request(url, "GET", headers, timeout, via_proxy=via_proxy)

    @classmethod
    def _probe_aws_imdsv2(cls, via_proxy=False):
        status, token = cls._http_request(
            "http://169.254.169.254/latest/api/token", "PUT",
            {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, 3, via_proxy=via_proxy)
        if not status or status >= 400 or not token.strip():
            return None, token or "IMDSv2 token 获取失败"
        return cls._http_get(
            "http://169.254.169.254/latest/meta-data/",
            {"X-aws-ec2-metadata-token": token.strip()}, 3, via_proxy=via_proxy)

    @classmethod
    def _probe_aliyun_imdsv2(cls, via_proxy=False):
        status, token = cls._http_request(
            "http://100.100.100.200/latest/api/token", "PUT",
            {"X-aliyun-ecs-metadata-token-ttl-seconds": "21600"}, 3, via_proxy=via_proxy)
        if not status or status >= 400 or not token.strip():
            return None, token or "IMDSv2 token 获取失败"
        return cls._http_get(
            "http://100.100.100.200/latest/meta-data/",
            {"X-aliyun-ecs-metadata-token": token.strip()}, 3, via_proxy=via_proxy)

    @classmethod
    def _probe_single(cls, name, url, timeout, headers, via_proxy=False):
        status, body = cls._http_get(url, headers, timeout, via_proxy=via_proxy)
        if status and status < 400:
            return name, url, "可达", body[:200]
        if body and "Metadata-Flavor" in body:
            return name, url, "GCP特征", body[:200]
        return name, url, "不可达", (body[:100] if body else "")

    GCP_METADATA_FIELDS = (
        ("project-id", "/project/project-id"),
        ("hostname", "/instance/hostname"),
        ("zone", "/instance/zone"),
        ("machine-type", "/instance/machine-type"),
        ("service-account", "/instance/service-accounts/default/email"),
    )

    @classmethod
    def probe_gcp_metadata(cls, via_proxy=False, timeout=10):
        """GCP 元数据专项探测（经 SOCKS 时优先 metadata.google.internal，与手动 curl 一致）。"""
        hdr = {"Metadata-Flavor": "Google"}
        bases = (
            "http://metadata.google.internal/computeMetadata/v1",
            "http://169.254.169.254/computeMetadata/v1",
        )
        results = []
        for label, path in cls.GCP_METADATA_FIELDS:
            for base in bases:
                url = base + path
                status, body = cls._http_get(url, hdr, timeout, via_proxy=via_proxy)
                if status and status < 400 and body.strip():
                    results.append((label, url, "可达", body.strip()[:500]))
                    break
                if body and "Metadata-Flavor" in body:
                    results.append((label, url, "GCP特征", body.strip()[:200]))
                    break
        return results

    @classmethod
    def probe_imds(cls, parallel=True, max_workers=6, via_proxy=False):
        jobs = []
        for name, url, to, hdrs in cls.IMDS_ENDPOINTS:
            jobs.append((
                name,
                lambda n=name, u=url, t=to, h=hdrs, vp=via_proxy: cls._probe_single(n, u, t, h, vp),
            ))
        jobs.append(("AWS IMDSv2", lambda vp=via_proxy: cls._probe_aws_imdsv2_wrapped(vp)))
        jobs.append(("阿里云 IMDSv2", lambda vp=via_proxy: cls._probe_aliyun_imdsv2_wrapped(vp)))

        if not parallel:
            return [fn() for _, fn in jobs]

        results = [None] * len(jobs)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_idx = {pool.submit(fn): i for i, (_, fn) in enumerate(jobs)}
            for fut in as_completed(fut_idx):
                results[fut_idx[fut]] = fut.result()
        return results

    @classmethod
    def _probe_aws_imdsv2_wrapped(cls, via_proxy=False):
        status, body = cls._probe_aws_imdsv2(via_proxy=via_proxy)
        url = "http://169.254.169.254/latest/meta-data/ (v2)"
        if status and status < 400:
            return "AWS IMDSv2", url, "可达", body[:200]
        return "AWS IMDSv2", url, "不可达", (body[:100] if body else "")

    @classmethod
    def _probe_aliyun_imdsv2_wrapped(cls, via_proxy=False):
        status, body = cls._probe_aliyun_imdsv2(via_proxy=via_proxy)
        url = "http://100.100.100.200/latest/meta-data/ (v2)"
        if status and status < 400:
            return "阿里云 IMDSv2", url, "可达", body[:200]
        return "阿里云 IMDSv2", url, "不可达", (body[:100] if body else "")

    @staticmethod
    def probe_k8s_version(apiserver, token, cacert, skip_tls=False):
        url = apiserver.rstrip("/") + "/version"
        if not url.startswith("http"):
            url = "https://" + url.lstrip("/")
        ca_ok = bool(cacert and os.path.isfile(cacert))
        modes = [True] if skip_tls else ([False] if ca_ok else [True])
        if not skip_tls and True not in modes:
            modes.append(True)
        last_err = None
        for use_skip in modes:
            try:
                ctx = ssl.create_default_context()
                if use_skip or not ca_ok:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                elif ca_ok:
                    ctx.load_verify_locations(cafile=cacert)
                req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
                with socks_proxy.urlopen(req, context=ctx, timeout=8) as resp:
                    return True, resp.read().decode("utf-8", errors="ignore")
            except Exception as e:
                last_err = e
                if use_skip:
                    break
        return False, str(last_err) if last_err else "连接失败"

    @staticmethod
    def parse_jwt(token):
        if not token or token.count(".") != 2:
            return None
        try:
            import base64
            payload_b64 = token.split(".")[1]
            rem = len(payload_b64) % 4
            if rem:
                payload_b64 += "=" * (4 - rem)
            decoded = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return None
