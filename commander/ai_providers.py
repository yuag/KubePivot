"""AI 厂商预设与系统 Prompt。"""

# AI 厂商预设（models_api 指定动态拉取策略；models 为网络失败时的静态兜底列表）
AI_PROVIDERS = {
    "DeepSeek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "format": "openai",
        "models_api": "openai",
    },
    "通义千问 (阿里云)": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "models": ["qwen-turbo", "qwen-plus", "qwen-max", "qwen-long"],
        "format": "openai",
        "models_api": "openai",
    },
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1", "o3-mini"],
        "format": "openai",
        "models_api": "openai",
    },
    "Anthropic Claude": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-20250514",
        "models": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
        "format": "anthropic",
        "models_api": "anthropic",
    },
    "OpenRouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "anthropic/claude-3.5-sonnet",
        "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "google/gemini-2.0-flash-001", "deepseek/deepseek-chat"],
        "format": "openai",
        "models_api": "openrouter",
    },
    "Moonshot (Kimi)": {
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "format": "openai",
        "models_api": "openai",
    },
    "智谱 GLM": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",
        "models": ["glm-4-flash", "glm-4-plus", "glm-4-air"],
        "format": "openai",
        "models_api": "openai",
    },
    "Groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "models": ["llama-3.3-70b-versatile", "mixtral-8x7b-32768", "gemma2-9b-it"],
        "format": "openai",
        "models_api": "openai",
    },
    "Google Gemini (OpenAI 兼容)": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.0-flash",
        "models": ["gemini-2.0-flash", "gemini-2.5-flash-preview-05-20", "gemini-1.5-pro"],
        "format": "openai",
        "models_api": "openai",
    },
    "Ollama (本地)": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "llama3.2",
        "models": ["llama3.2", "qwen2.5", "deepseek-r1"],
        "format": "openai",
        "models_api": "ollama",
        "requires_key": False,
    },
    "自定义": {
        "base_url": "",
        "model": "",
        "models": [],
        "format": "openai",
        "models_api": "none",
        "requires_key": False,
    },
}

AI_SYSTEM_PROMPT = (
    "你是一个顶级的云原生安全专家、Kubernetes 渗透测试专家。输入给你的数据是用户在集群内获取的原始信息"
    "（可能是 /pods、/nodes、env、RBAC、或配置快照）。请对这些数据进行彻底的风险和隐患排查。你的任务是发现：\n"
    "1. 特权容器 (privileged: true)、hostNetwork、hostPID 等危险隔离越界行为。\n"
    "2. 敏感卷挂载（如挂载了宿主机的 /var/run/docker.sock 或 / 根目录）。\n"
    "3. 命名空间权限、弱口令、未授权暴露的服务、敏感环境变量（密码、Key）。\n"
    "4. 可利用的 RBAC、ServiceAccount Token、ClusterRoleBinding 等提权路径。\n"
    "请用清晰的 Markdown 格式输出：[💡 风险评估大观]、[⚠️ 严重隐患列表]、[⚔️ 潜在提权/利用链]、[🛡️ 修复防护建议]。"
)
