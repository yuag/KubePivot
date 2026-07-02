"""环境变量分析器。"""
import os
import re

class EnvVarAnalyzer:
    SENSITIVE_KEYS = re.compile(
        r"(TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE|AUTH_TOKEN|BEARER|"
        r"ACCESS_KEY|SECRET_KEY|NPM_|GITHUB_TOKEN|GITLAB_|DOCKER_.*PASS)", re.I
    )
    SENSITIVE_KEY_SUFFIX = re.compile(r"(_KEY|_KEY_ID|_TOKEN|_SECRET)$", re.I)
    SENSITIVE_SKIP = frozenset({
        "SSH_AUTH_SOCK", "XAUTHORITY", "PAGER", "LESSOPEN", "LESSCLOSE",
        "LS_COLORS", "HOSTKEY", "MONKEY", "KEYBOARD",
    })
    MASKED_VALUES = frozenset({"***", "****", "*****", "[hidden]", "[redacted]", "<redacted>"})
    NPM_TOKEN = re.compile(r"NPM_TOKEN", re.I)
    NEXT_PUBLIC = re.compile(r"^NEXT_PUBLIC_", re.I)

    @classmethod
    def _is_sensitive_key(cls, k):
        if k in cls.SENSITIVE_SKIP:
            return False
        if cls.NPM_TOKEN.search(k):
            return True
        if cls.SENSITIVE_KEYS.search(k):
            return True
        if cls.SENSITIVE_KEY_SUFFIX.search(k):
            return True
        return False

    @classmethod
    def _should_report_sensitive(cls, k, v):
        if not cls._is_sensitive_key(k):
            return False
        v = (v or "").strip()
        if v in cls.MASKED_VALUES:
            return True
        return len(v) > 4

    @staticmethod
    def parse(text):
        env = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("==="):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                env[k] = v
        return env

    @classmethod
    def enrich_from_text(cls, env, text):
        """从自查命令输出、IMDS 探测结果等自由文本中补充识别线索。"""
        if not text:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("==="):
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
                env.setdefault(k, v)

        if re.search(r"\bIN_DOCKER\b", text):
            env["_IN_DOCKER"] = "yes"
        if re.search(r"serviceaccount/token|/var/run/secrets/kubernetes", text, re.I):
            env["_HAS_SA"] = "yes"

        imds_patterns = [
            ("_HINT_AWS", r"\[AWS[^\]]*\][\s\S]{0,120}?(ami-id|instance-id|iam/security-credentials)", "☁️ AWS (亚马逊云)"),
            ("_HINT_ALIYUN", r"\[阿里云\][\s\S]{0,120}?(instance-id|ram/)", "🟠 阿里云"),
            ("_HINT_TENCENT", r"\[腾讯云\][\s\S]{0,80}\S", "🔵 腾讯云"),
            ("_HINT_GCP", r"\[GCP\][\s\S]{0,120}?(project|computeMetadata|instance/)", "🟢 GCP (谷歌云)"),
            ("_HINT_AZURE", r"\[Azure\][\s\S]{0,120}?(compute|subscription|resourceGroup)", "🔷 Azure (微软云)"),
            ("_HINT_VOLCANO", r"\[火山引擎\][\s\S]{0,80}\S", "🌋 火山引擎"),
            ("_HINT_OCI", r"\[Oracle OCI\][\s\S]{0,80}\S", "🟣 Oracle OCI"),
            ("_HINT_IBM", r"\[IBM Cloud\][\s\S]{0,80}\S", "🔶 IBM Cloud"),
        ]
        for key, pat, _ in imds_patterns:
            if re.search(pat, text, re.I):
                env[key] = "reachable"

        if re.search(r"ami-id|aws_ec2|amazonaws\.com", text, re.I):
            env.setdefault("_HINT_AWS", "reachable")
        if re.search(r"metadata\.google|computeMetadata|googleapis", text, re.I):
            env.setdefault("_HINT_GCP", "reachable")
        hn = env.get("HOSTNAME", "")
        if re.search(r"\.ec2\.|\.compute\.internal", hn, re.I):
            env.setdefault("_HINT_AWS", "reachable")
        if re.search(r"\.google|gcp|cloud\.run", hn, re.I):
            env.setdefault("_HINT_GCP", "reachable")

    @classmethod
    def analyze(cls, env, raw_text=""):
        cls.enrich_from_text(env, raw_text)
        findings = []
        verdict_parts = []
        platform_hint = "未知"
        region = None

        if env.get("AWS_EXECUTION_ENV", "").startswith("AWS_ECS"):
            platform_hint = "AWS ECS/Fargate"
            findings.append(("cloud", "AWS_EXECUTION_ENV=" + env["AWS_EXECUTION_ENV"]))
        if env.get("ECS_CONTAINER_METADATA_URI") or env.get("ECS_CONTAINER_METADATA_URI_V4"):
            platform_hint = "AWS ECS"
            findings.append(("cloud", "检测到 ECS 容器元数据 URI"))
        if env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION"):
            region = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
            findings.append(("region", f"AWS 区域: {region}"))
        if env.get("EKS_CLUSTER_NAME") or "eks" in env.get("KUBERNETES_SERVICE_HOST", "").lower():
            platform_hint = "AWS EKS"
            if env.get("EKS_CLUSTER_NAME"):
                findings.append(("cloud", f"EKS 集群: {env['EKS_CLUSTER_NAME']}"))

        if env.get("KUBERNETES_SERVICE_HOST"):
            platform_hint = "Kubernetes"
            findings.append(("k8s", f"K8s API: {env['KUBERNETES_SERVICE_HOST']}:{env.get('KUBERNETES_SERVICE_PORT', '443')}"))
        if env.get("KUBERNETES_PORT"):
            findings.append(("k8s", f"KUBERNETES_PORT={env['KUBERNETES_PORT']}"))

        gcp_keys = ["GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT", "GKE_CLUSTER_NAME"]
        for gk in gcp_keys:
            if env.get(gk):
                platform_hint = "GCP / GKE"
                findings.append(("cloud", f"{gk}={env[gk]}"))

        azure_keys = ["WEBSITE_SITE_NAME", "AZURE_SUBSCRIPTION_ID", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"]
        for ak in azure_keys:
            if env.get(ak):
                platform_hint = "Azure"
                findings.append(("cloud", f"{ak} 已设置"))

        if env.get("VERCEL") or env.get("VERCEL_ENV"):
            platform_hint = "Vercel / Next.js"
            findings.append(("framework", f"Vercel: {env.get('VERCEL_ENV', 'yes')}"))
        if env.get("NEXT_RUNTIME") or any(k.startswith("NEXT_") for k in env):
            findings.append(("framework", "Next.js 运行时环境"))
        if env.get("__NEXT_PRIVATE_ORIGIN") or env.get("NEXT_DEPLOYMENT_ID"):
            findings.append(("framework", "Next.js 部署标识已检测到"))
        if env.get("NODE_VERSION") or env.get("NODE_ENV"):
            nv = env.get("NODE_VERSION") or env.get("NODE_ENV")
            findings.append(("runtime", f"Node: {nv}"))
        if env.get("npm_package_name"):
            findings.append(("runtime", f"npm 包名: {env['npm_package_name']}"))
        if env.get("npm_package_version"):
            findings.append(("runtime", f"npm 版本: {env['npm_package_version']}"))
        if env.get("npm_lifecycle_event"):
            findings.append(("runtime", f"npm 生命周期: {env['npm_lifecycle_event']}"))

        # DigitalOcean App Platform
        if env.get("DO_APP_ID") or env.get("DO_APP_NAME"):
            platform_hint = "DigitalOcean App"
            findings.append(("cloud", f"DO App: {env.get('DO_APP_NAME', env.get('DO_APP_ID'))}"))

        # Heroku-style
        if env.get("DYNO") or env.get("HEROKU_APP_NAME"):
            platform_hint = "Heroku"
            findings.append(("cloud", f"Heroku: {env.get('HEROKU_APP_NAME', env.get('DYNO'))}"))

        # Cloud Run / Knative (Google Cloud)
        if env.get("K_SERVICE") or env.get("K_CONFIGURATION") or env.get("K_REVISION"):
            platform_hint = "GCP Cloud Run / Knative"
            findings.append(("cloud", f"Knative 服务: {env.get('K_SERVICE', '?')}"))
            if env.get("K_REVISION"):
                findings.append(("cloud", f"K_REVISION={env['K_REVISION']}"))
            if env.get("K_CONFIGURATION"):
                findings.append(("cloud", f"K_CONFIGURATION={env['K_CONFIGURATION']}"))
            if env.get("PORT"):
                findings.append(("info", f"监听端口 PORT={env['PORT']}"))
            proj = env.get("GOOGLE_CLOUD_PROJECT") or env.get("GCP_PROJECT") or env.get("GCLOUD_PROJECT")
            if proj:
                findings.append(("cloud", f"GCP 项目: {proj}"))

        # Docker / container hints
        if env.get("container") or env.get("DOCKER_CONTAINER_ID"):
            findings.append(("info", "Docker 容器环境变量"))

        for k, v in env.items():
            if cls._should_report_sensitive(k, v):
                label = "NPM Token 敏感" if cls.NPM_TOKEN.search(k) else "敏感变量"
                findings.append(("sensitive", f"{k}=*** ({label})"))
            if cls.NEXT_PUBLIC.match(k) and ("http://" in v or "https://" in v):
                findings.append(("url", f"{k}={v}"))

        if env.get("HOSTNAME") and len(env.get("HOSTNAME", "")) > 8:
            findings.append(("info", f"HOSTNAME={env['HOSTNAME']}"))
        if env.get("POD_NAME") or env.get("POD_NAMESPACE"):
            findings.append(("k8s", f"Pod: {env.get('POD_NAMESPACE', '?')}/{env.get('POD_NAME', '?')}"))

        # 国内云 / 其他云特征变量
        if env.get("ALIBABA_CLOUD_REGION_ID") or env.get("ALIYUN_REGION_ID") or env.get("ECS_METADATA"):
            platform_hint = "阿里云"
            findings.append(("cloud", "检测到阿里云环境变量"))
        if env.get("TENCENTCLOUD_REGION") or env.get("TENCENTCLOUD_APPID") or env.get("TENCENTCLOUD_SECRETID"):
            platform_hint = "腾讯云"
            findings.append(("cloud", "检测到腾讯云环境变量"))
        if env.get("HUAWEICLOUD_SDK_PROJECT_ID") or env.get("HUAWEICLOUD_DEFAULT_REGION") or env.get("PAAS_APP_NAME"):
            platform_hint = "华为云"
            findings.append(("cloud", "检测到华为云环境变量"))
        if env.get("BAIDU_CLOUD_REGION") or env.get("BCE_REGION"):
            platform_hint = "百度云"
            findings.append(("cloud", "检测到百度云环境变量"))
        if env.get("VOLCENGINE_REGION") or env.get("VOLCENGINE_ACCESS_KEY"):
            platform_hint = "火山引擎"
            findings.append(("cloud", "检测到火山引擎环境变量"))
        if env.get("UCLOUD_REGION") or env.get("UCLOUD_PROJECT_ID"):
            platform_hint = "UCloud"
            findings.append(("cloud", "检测到 UCloud 环境变量"))

        # IMDS / 自查输出中的云平台线索（无标准 env 变量时）
        if env.get("_HINT_GCP") and platform_hint in ("未知", "Kubernetes"):
            platform_hint = "GCP Cloud Run / Knative" if env.get("K_SERVICE") else "GCP / GKE"
            findings.append(("cloud", "IMDS/输出检测到 GCP"))
        if env.get("_HINT_AWS") and platform_hint in ("未知", "Kubernetes"):
            platform_hint = "AWS"
            findings.append(("cloud", "IMDS/输出检测到 AWS"))
        if env.get("_HINT_ALIYUN") and platform_hint == "未知":
            platform_hint = "阿里云"
            findings.append(("cloud", "IMDS/输出检测到阿里云"))
        if env.get("_HINT_TENCENT") and platform_hint == "未知":
            platform_hint = "腾讯云"
            findings.append(("cloud", "IMDS/输出检测到腾讯云"))
        if env.get("_HINT_AZURE") and platform_hint == "未知":
            platform_hint = "Azure"
            findings.append(("cloud", "IMDS/输出检测到 Azure"))

        nav = cls.suggest_navigation(env, platform_hint)
        if nav:
            findings.append(("cloud", f"导航: {nav[0]} → {nav[1]}"))
        elif platform_hint == "未知" and env:
            findings.append(("info", "未明确识别 → 环境识别 → 📋 快速自查 或 🐧 Linux 探测"))

        verdict = platform_hint
        if region:
            verdict += f" ({region})"
        return {"verdict": verdict, "findings": findings, "env_count": len(env), "region": region, "nav": nav}

    @classmethod
    def suggest_navigation(cls, env, platform_hint):
        """根据环境变量推断应跳转的命令分组/分类。云平台优先于 K8s，K8s 优先于环境识别。"""
        if not env and platform_hint == "未知":
            return None

        if env.get("K_SERVICE") or env.get("K_CONFIGURATION") or env.get("K_REVISION"):
            return ("云平台", "🚀 Cloud Run / Knative")

        if (env.get("AWS_EXECUTION_ENV", "").startswith("AWS_ECS")
                or env.get("ECS_CONTAINER_METADATA_URI")
                or env.get("ECS_CONTAINER_METADATA_URI_V4")):
            return ("云平台", "☁️ AWS (亚马逊云)")

        if env.get("ALIBABA_CLOUD_REGION_ID") or env.get("ALIYUN_REGION_ID") or env.get("ECS_METADATA"):
            return ("云平台", "🟠 阿里云")
        if env.get("TENCENTCLOUD_REGION") or env.get("TENCENTCLOUD_APPID"):
            return ("云平台", "🔵 腾讯云")
        if env.get("HUAWEICLOUD_SDK_PROJECT_ID") or env.get("HUAWEICLOUD_DEFAULT_REGION") or env.get("PAAS_APP_NAME"):
            return ("云平台", "🔴 华为云")
        if env.get("BAIDU_CLOUD_REGION") or env.get("BCE_REGION"):
            return ("云平台", "🟡 百度云")
        if env.get("VOLCENGINE_REGION") or env.get("VOLCENGINE_ACCESS_KEY"):
            return ("云平台", "🌋 火山引擎")
        if env.get("UCLOUD_REGION") or env.get("UCLOUD_PROJECT_ID"):
            return ("云平台", "🔹 UCloud")

        azure_keys = ["WEBSITE_SITE_NAME", "AZURE_SUBSCRIPTION_ID", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"]
        if any(env.get(k) for k in azure_keys):
            return ("云平台", "🔷 Azure (微软云)")

        if env.get("DO_APP_ID") or env.get("DO_APP_NAME"):
            return ("云平台", "🌊 DigitalOcean")

        gcp_keys = ["GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT", "GKE_CLUSTER_NAME"]
        if any(env.get(k) for k in gcp_keys):
            return ("云平台", "🟢 GCP (谷歌云)")

        if env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or env.get("EKS_CLUSTER_NAME"):
            return ("云平台", "☁️ AWS (亚马逊云)")

        # IMDS / 自查输出线索
        hint_cloud = [
            ("_HINT_GCP", "🟢 GCP (谷歌云)"),
            ("_HINT_AWS", "☁️ AWS (亚马逊云)"),
            ("_HINT_ALIYUN", "🟠 阿里云"),
            ("_HINT_TENCENT", "🔵 腾讯云"),
            ("_HINT_AZURE", "🔷 Azure (微软云)"),
            ("_HINT_VOLCANO", "🌋 火山引擎"),
            ("_HINT_OCI", "🟣 Oracle OCI"),
            ("_HINT_IBM", "🔶 IBM Cloud"),
        ]
        for key, cat in hint_cloud:
            if env.get(key):
                return ("云平台", cat)

        # 按 platform_hint 判定跳转（云平台 / K8s）
        in_pod = bool(env.get("POD_NAME") or env.get("POD_NAMESPACE") or env.get("_HAS_SA"))
        hint_map = {
            "GCP Cloud Run / Knative": ("云平台", "🚀 Cloud Run / Knative"),
            "AWS ECS/Fargate": ("云平台", "☁️ AWS (亚马逊云)"),
            "AWS ECS": ("云平台", "☁️ AWS (亚马逊云)"),
            "AWS": ("云平台", "☁️ AWS (亚马逊云)"),
            "AWS EKS": ("K8s", "🔍 查看资源"),
            "GCP / GKE": ("云平台", "🟢 GCP (谷歌云)"),
            "Azure": ("云平台", "🔷 Azure (微软云)"),
            "Kubernetes": ("K8s", "🔎 容器内自查" if in_pod else "🔍 查看资源"),
            "阿里云": ("云平台", "🟠 阿里云"),
            "腾讯云": ("云平台", "🔵 腾讯云"),
            "华为云": ("云平台", "🔴 华为云"),
            "百度云": ("云平台", "🟡 百度云"),
            "火山引擎": ("云平台", "🌋 火山引擎"),
            "UCloud": ("云平台", "🔹 UCloud"),
            "DigitalOcean App": ("云平台", "🌊 DigitalOcean"),
        }
        for key, nav in hint_map.items():
            if key in platform_hint:
                return nav

        if env.get("KUBERNETES_SERVICE_HOST") or env.get("KUBERNETES_PORT_443_TCP"):
            return ("K8s", "🔎 容器内自查" if in_pod else "🔍 查看资源")

        if env.get("VERCEL") or env.get("VERCEL_ENV"):
            return ("环境识别", "📋 快速自查")

        if platform_hint == "未知" and env:
            return ("环境识别", "📋 快速自查")
        return None

    @classmethod
    def format_report(cls, env, result):
        """Generate a multi-line text report from analyze() output."""
        lines = [
            f"环境判定: {result['verdict']}",
            f"变量总数: {result['env_count']}",
            "",
            "── 发现项 ──",
        ]
        for kind, msg in result["findings"]:
            prefix = {"sensitive": "[!]", "cloud": "[C]", "k8s": "[K]", "region": "[R]"}.get(kind, "[i]")
            lines.append(f"  {prefix} {msg}")
        if result.get("region"):
            lines.append(f"\n区域: {result['region']}")
        return "\n".join(lines)

    @classmethod
    def detect_from_os_environ(cls):
        return cls.analyze(dict(os.environ))
