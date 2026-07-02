"""AI 模型列表动态拉取。"""
import json
import ssl
import urllib.error
import urllib.request

from commander.ai_providers import AI_PROVIDERS
from commander.config import logger
from commander import socks_proxy

class AIModelFetcher:
    """统一模型列表获取。新增厂商只需在 AI_PROVIDERS 配置 models_api，并注册对应 fetcher。"""

    _registry = {}

    @classmethod
    def register(cls, api_type):
        def decorator(fn):
            cls._registry[api_type] = fn
            return fn
        return decorator

    @classmethod
    def _needs_api_key(cls, cfg):
        if cfg.get("requires_key") is False:
            return False
        return cfg.get("models_api") not in ("ollama", "none")

    @classmethod
    def fetch(cls, provider_name, base_url, api_key="", provider_cfg=None):
        """返回 (models, used_fallback, error_message)。"""
        cfg = provider_cfg or AI_PROVIDERS.get(provider_name, {})
        api_type = cfg.get("models_api", "openai")
        if api_type == "none":
            return [], False, None
        if cls._needs_api_key(cfg) and not (api_key or "").strip():
            logger.info("厂商 %s 未配置 API Key，使用静态模型列表", provider_name)
            return cls._fallback(cfg), True, None
        fetcher = cls._registry.get(api_type)
        if not fetcher:
            logger.warning("厂商 %s 未注册 models_api=%s fetcher，使用静态兜底", provider_name, api_type)
            return cls._fallback(cfg), True, "未注册 fetcher"
        fetch_err = None
        try:
            models = fetcher(base_url, api_key, cfg)
            if models:
                return models, False, None
            fetch_err = "接口返回空列表"
            logger.info("厂商 %s 模型列表为空，使用静态兜底", provider_name)
        except urllib.error.HTTPError as e:
            fetch_err = cls._format_http_error(e)
            if e.code in (401, 403) and not (api_key or "").strip():
                logger.info("厂商 %s 需要 API Key (HTTP %s)", provider_name, e.code)
            else:
                logger.warning("厂商 %s 模型列表 %s", provider_name, fetch_err)
        except urllib.error.URLError as e:
            fetch_err = cls._format_url_error(e)
            logger.warning("厂商 %s %s", provider_name, fetch_err)
        except Exception as e:
            fetch_err = str(e)[:200]
            logger.warning("厂商 %s 模型列表失败: %s", provider_name, e)
        return cls._fallback(cfg), True, fetch_err

    @staticmethod
    def _format_http_error(exc):
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="ignore")[:120]
        except Exception:
            pass
        msg = f"HTTP {exc.code} {exc.reason}"
        if body:
            msg += f": {body}"
        if exc.code in (401, 403):
            msg += "（请检查 API Key 是否正确）"
        return msg

    @staticmethod
    def _format_url_error(exc):
        reason = str(exc.reason)
        low = reason.lower()
        if "ssl" in low or "eof" in low or "certificate" in low:
            return f"SSL/TLS 连接失败（可能被防火墙、杀毒软件或代理拦截）: {reason}"
        if "timed out" in low or "timeout" in low:
            return f"连接超时（请检查网络、代理或防火墙）: {reason}"
        if "10061" in reason or "connection refused" in low:
            return f"无法连接服务器（Ollama 未启动或地址错误）: {reason}"
        if "getaddrinfo" in low or "11001" in reason or "name or service not known" in low:
            return f"DNS 解析失败，无法解析域名: {reason}"
        if "10060" in reason or "10054" in reason:
            return f"网络连接被中断: {reason}"
        return f"网络错误: {reason}"

    @staticmethod
    def _fallback(cfg):
        if not cfg:
            return []
        static = cfg.get("models")
        if isinstance(static, list) and static:
            return list(static)
        default = cfg.get("model", "")
        return [default] if default else []

    @staticmethod
    def _build_ssl_context(verify):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            try:
                import certifi
                ctx.load_verify_locations(certifi.where())
            except ImportError:
                pass
            if hasattr(ssl, "TLSVersion"):
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                except (AttributeError, ValueError):
                    pass
        return ctx

    @staticmethod
    def _http_get_json(url, headers=None, timeout=25):
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", "K8sCommander/2.7")
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        last_err = None
        for verify in (True, False):
            try:
                ctx = AIModelFetcher._build_ssl_context(verify)
                with socks_proxy.urlopen(req, context=ctx, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except ssl.SSLError as e:
                last_err = e
                if not verify:
                    raise
                continue
            except urllib.error.URLError as e:
                reason = str(e.reason)
                if verify and (
                    "SSL" in reason or "EOF" in reason or "certificate" in reason.lower()
                ):
                    last_err = e
                    continue
                raise
        if last_err:
            raise last_err
        raise RuntimeError("HTTP 请求失败")

    @staticmethod
    def normalize_openai_models_url(base_url):
        """将 Base URL 规范为 OpenAI 兼容的 GET /models 端点。"""
        base = (base_url or "").strip().rstrip("/")
        if not base:
            return ""
        if base.endswith("/chat/completions"):
            base = base.rsplit("/chat/completions", 1)[0]
        if base.endswith("/models"):
            return base
        return f"{base}/models"

    @staticmethod
    def _parse_openai_models_payload(data):
        items = data.get("data") or data.get("models") or []
        names = []
        for item in items:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                mid = item.get("id") or item.get("name") or item.get("model")
                if mid:
                    names.append(str(mid))
        return sorted(set(names))


@AIModelFetcher.register("openai")
def _fetch_models_openai(base_url, api_key, cfg):
    url = AIModelFetcher.normalize_openai_models_url(base_url)
    if not url:
        return []
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    data = AIModelFetcher._http_get_json(url, headers=headers)
    return AIModelFetcher._parse_openai_models_payload(data)


@AIModelFetcher.register("openrouter")
def _fetch_models_openrouter(base_url, api_key, cfg):
    url = AIModelFetcher.normalize_openai_models_url(base_url)
    if not url:
        return []
    headers = {"HTTP-Referer": "https://github.com/k8s-commander", "X-Title": "K8s Commander"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    data = AIModelFetcher._http_get_json(url, headers=headers)
    return AIModelFetcher._parse_openai_models_payload(data)


@AIModelFetcher.register("anthropic")
def _fetch_models_anthropic(base_url, api_key, cfg):
    if not api_key:
        return []
    base = (base_url or "https://api.anthropic.com/v1").strip().rstrip("/")
    if base.endswith("/messages"):
        base = base[: -len("/messages")].rstrip("/")
    url = base + "/models" if not base.endswith("/models") else base
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    data = AIModelFetcher._http_get_json(url, headers=headers)
    return AIModelFetcher._parse_openai_models_payload(data)


@AIModelFetcher.register("ollama")
def _fetch_models_ollama(base_url, api_key, cfg):
    base = (base_url or "http://127.0.0.1:11434/v1").strip().rstrip("/")
    if base.endswith("/v1"):
        root = base[: -len("/v1")]
    else:
        root = base.split("/v1")[0] if "/v1" in base else base
    url = root.rstrip("/") + "/api/tags"
    data = AIModelFetcher._http_get_json(url)
    models = []
    for item in data.get("models") or []:
        name = item.get("name") if isinstance(item, dict) else None
        if name:
            models.append(name.split(":")[0] if ":" in name else name)
    return sorted(set(models))
