"""RBAC 提权攻击图（Mermaid + SVG）自动生成。"""
from __future__ import annotations

import html
from typing import Dict, List, Set, Tuple

# 固定 DAG 模板：与 Canvas / 设计文档 5 链一致（展示顺序）
_GRAPH_CHAINS = [
    {
        "id": "direct_binding",
        "num": 1,
        "edges": [
            ("SA", "C1P"),
            ("C1P", "C1A"),
            ("C1A", "TARGET"),
        ],
        "nodes": {
            "C1P": "create clusterrolebindings",
            "C1A": "创建 CRB 绑定 cluster-admin",
        },
    },
    {
        "id": "pod_secret_theft",
        "num": 2,
        "edges": [
            ("SA", "C2P"),
            ("SA", "C2S"),
            ("C2P", "C2A"),
            ("C2S", "C2A"),
            ("C2A", "TARGET"),
        ],
        "nodes": {
            "C2P": "create pods",
            "C2S": "get/list secrets",
            "C2A": "Pod 挂载 Secret 读 token",
        },
    },
    {
        "id": "webhook_hijacking",
        "num": 3,
        "edges": [
            ("SA", "C3P"),
            ("C3P", "C3A"),
            ("C3A", "TARGET"),
        ],
        "nodes": {
            "C3P": "create/patch webhook",
            "C3A": "恶意 Webhook 拦截注入",
        },
    },
    {
        "id": "sa_impersonation",
        "num": 4,
        "edges": [
            ("SA", "C4P"),
            ("SA", "C4L"),
            ("C4P", "C4A"),
            ("C4L", "C4A"),
            ("C4A", "TARGET"),
        ],
        "nodes": {
            "C4P": "create pods",
            "C4L": "list serviceaccounts",
            "C4A": "假冒高权限 SA Pod",
        },
    },
    {
        "id": "deployment_image_hijack",
        "num": 5,
        "edges": [
            ("SA", "C5P"),
            ("C5P", "C5A"),
            ("C5A", "TARGET"),
        ],
        "nodes": {
            "C5P": "patch deployments",
            "C5A": "镜像劫持 → RCE",
        },
    },
]


# SVG 固定布局（5 列提权链）
_SVG_LAYOUT: Dict[str, Tuple[int, int, int, int]] = {
    "SA": (350, 16, 260, 52),
    "TARGET": (390, 548, 180, 44),
    "C1P": (40, 110, 168, 38),
    "C1A": (40, 188, 168, 38),
    "C2P": (220, 110, 148, 36),
    "C2S": (220, 158, 148, 36),
    "C2A": (210, 236, 168, 38),
    "C3P": (390, 110, 148, 36),
    "C3A": (380, 188, 168, 38),
    "C4P": (560, 110, 140, 36),
    "C4L": (560, 158, 156, 36),
    "C4A": (550, 236, 168, 38),
    "C5P": (730, 110, 148, 36),
    "C5A": (720, 188, 168, 38),
}

_SVG_EDGES = [
    ("SA", "C1P"), ("C1P", "C1A"), ("C1A", "TARGET"),
    ("SA", "C2P"), ("SA", "C2S"), ("C2P", "C2A"), ("C2S", "C2A"), ("C2A", "TARGET"),
    ("SA", "C3P"), ("C3P", "C3A"), ("C3A", "TARGET"),
    ("SA", "C4P"), ("SA", "C4L"), ("C4P", "C4A"), ("C4L", "C4A"), ("C4A", "TARGET"),
    ("SA", "C5P"), ("C5P", "C5A"), ("C5A", "TARGET"),
]

_SVG_NODE_LABELS: Dict[str, str] = {
    "SA": "",
    "TARGET": "cluster-admin\n完全控制",
    "C1P": "链1\ncreate clusterrolebindings",
    "C1A": "链1\n创建 CRB 绑定",
    "C2P": "链2\ncreate pods",
    "C2S": "链2\nget/list secrets",
    "C2A": "链2\nPod 挂载 Secret",
    "C3P": "链3\ncreate/patch webhook",
    "C3A": "链3\n恶意 Webhook",
    "C4P": "链4\ncreate pods",
    "C4L": "链4\nlist serviceaccounts",
    "C4A": "链4\n假冒高权限 SA",
    "C5P": "链5\npatch deployments",
    "C5A": "链5\n镜像劫持 RCE",
}

_NODE_CHAIN: Dict[str, str] = {
    "C1P": "direct_binding", "C1A": "direct_binding",
    "C2P": "pod_secret_theft", "C2S": "pod_secret_theft", "C2A": "pod_secret_theft",
    "C3P": "webhook_hijacking", "C3A": "webhook_hijacking",
    "C4P": "sa_impersonation", "C4L": "sa_impersonation", "C4A": "sa_impersonation",
    "C5P": "deployment_image_hijack", "C5A": "deployment_image_hijack",
}


def _rules_hint(result: dict) -> str:
    rs = result.get("rules_summary") or {}
    for line in rs.get("lines") or []:
        stripped = line.strip()
        if stripped.startswith("*") and "selfsubject" not in stripped.lower():
            return stripped
    if is_effectively_cluster_admin(result):
        return "* * (*)"
    return ""


def _sa_label(result: dict) -> str:
    ns = result.get("sa_namespace") or result.get("namespace") or "default"
    name = result.get("service_account") or "unknown"
    return f"{ns}/{name}"


def is_effectively_cluster_admin(result: dict) -> bool:
    """RulesReview 含 * * (*) 时视为已等价 cluster-admin。"""
    rs = result.get("rules_summary") or {}
    for line in rs.get("lines") or []:
        normalized = line.replace(" ", "").lower()
        if "*(*)" in normalized or "*.*" in normalized:
            return True
        if line.strip() in ("* * (*)", "* *"):
            return True
    allowed = result.get("allowed_permissions") or []
    critical_bind = sum(
        1 for p in allowed
        if p.get("allowed")
        and p.get("verb") in ("create", "patch", "bind", "escalate")
        and "clusterrole" in (p.get("resource") or "")
    )
    return critical_bind >= 4 and len(allowed) >= 28


def matched_chain_ids(result: dict) -> Set[str]:
    return {c.get("id", "") for c in (result.get("escalation_chains") or []) if c.get("id")}


def _mermaid_escape(text: str) -> str:
    return text.replace('"', "'").replace("[", "(").replace("]", ")")


def build_attack_graph_mermaid(result: dict) -> str:
    """根据审计结果生成 Mermaid flowchart（GitHub / Typora / VS Code 可渲染）。"""
    sa = _mermaid_escape(_sa_label(result))
    matched = matched_chain_ids(result)
    rules_hint = _mermaid_escape(_rules_hint(result))

    node_defs = {
        "SA": f'SA["{sa}<br/>{rules_hint}"]',
        "TARGET": 'TARGET["cluster-admin<br/>完全控制"]',
    }
    hit_nodes: List[str] = ["SA"]
    miss_nodes: List[str] = []

    if matched:
        hit_nodes.append("TARGET")
    else:
        miss_nodes.append("TARGET")

    for chain in _GRAPH_CHAINS:
        active = chain["id"] in matched
        for nid, label in chain["nodes"].items():
            prefix = f"链{chain['num']}: "
            node_defs[nid] = f'{nid}["{prefix}{_mermaid_escape(label)}"]'
            (hit_nodes if active else miss_nodes).append(nid)

    shared_edges = [
        "    SA --> C1P", "    C1P --> C1A", "    C1A --> TARGET",
        "    SA --> C2P", "    SA --> C2S", "    C2P --> C2A", "    C2S --> C2A", "    C2A --> TARGET",
        "    SA --> C3P", "    C3P --> C3A", "    C3A --> TARGET",
        "    SA --> C4P", "    SA --> C4L", "    C4P --> C4A", "    C4L --> C4A", "    C4A --> TARGET",
        "    SA --> C5P", "    C5P --> C5A", "    C5A --> TARGET",
    ]

    lines = [
        "flowchart TB",
        f"    {node_defs['SA']}",
        f"    {node_defs['TARGET']}",
    ]
    for nid in sorted(node_defs.keys()):
        if nid in ("SA", "TARGET"):
            continue
        lines.append(f"    {node_defs[nid]}")
    lines.extend(shared_edges)
    lines.append("")
    lines.append("    classDef hit fill:#3d1f1f,stroke:#ff5555,stroke-width:2px,color:#fff")
    lines.append("    classDef miss fill:#1e1e2e,stroke:#45475a,color:#a6adc8")
    if hit_nodes:
        lines.append(f"    class {','.join(dict.fromkeys(hit_nodes))} hit")
    if miss_nodes:
        lines.append(f"    class {','.join(dict.fromkeys(miss_nodes))} miss")

    return "\n".join(lines)


def _svg_node_center(nid: str) -> Tuple[int, int]:
    x, y, w, h = _SVG_LAYOUT[nid]
    return x + w // 2, y + h // 2


def _svg_anchor(nid: str, toward: str) -> Tuple[int, int]:
    x, y, w, h = _SVG_LAYOUT[nid]
    cx, cy = x + w // 2, y + h // 2
    tx, ty = _svg_node_center(toward)
    if abs(ty - cy) >= abs(tx - cx):
        return cx, y + h if ty > cy else y
    return x + w if tx > cx else x, cy


def build_attack_graph_svg(result: dict) -> str:
    """生成 SVG 攻击图（任意 Markdown 阅读器均可显示图片）。"""
    matched = matched_chain_ids(result)
    sa_main = _sa_label(result)
    hint = _rules_hint(result)
    sa_label = f"{sa_main}\n{hint}" if hint else sa_main

    labels = dict(_SVG_NODE_LABELS)
    labels["SA"] = sa_label

    def node_active(nid: str) -> bool:
        if nid == "SA":
            return True
        if nid == "TARGET":
            return bool(matched)
        chain_id = _NODE_CHAIN.get(nid)
        return chain_id in matched if chain_id else False

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="960" height="620" viewBox="0 0 960 620">',
        '<defs>',
        '  <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">',
        '    <path d="M 0 0 L 10 5 L 0 10 z" fill="#7c6af7"/>',
        '  </marker>',
        '</defs>',
        '<rect width="960" height="620" fill="#1e1e2e"/>',
        '<text x="480" y="28" fill="#cdd6f4" font-family="Segoe UI, sans-serif" font-size="16" font-weight="600" text-anchor="middle">RBAC 提权攻击图</text>',
    ]

    for src, dst in _SVG_EDGES:
        active = node_active(src) and node_active(dst)
        sx, sy = _svg_anchor(src, dst)
        tx, ty = _svg_anchor(dst, src)
        color = "#ff5555" if active else "#45475a"
        width = 2 if active else 1
        parts.append(
            f'<line x1="{sx}" y1="{sy}" x2="{tx}" y2="{ty}" stroke="{color}" stroke-width="{width}" marker-end="url(#arrow)"/>'
        )

    for nid, (x, y, w, h) in _SVG_LAYOUT.items():
        active = node_active(nid)
        fill = "#4a2020" if active else "#2a2a3e"
        stroke = "#ff5555" if active else "#45475a"
        text_color = "#ffecec" if active else "#a6adc8"
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        lines = labels.get(nid, nid).split("\n")
        for i, line in enumerate(lines[:3]):
            ty = y + 16 + i * 14
            parts.append(
                f'<text x="{x + w // 2}" y="{ty}" fill="{text_color}" font-family="Consolas, monospace" '
                f'font-size="10" text-anchor="middle">{html.escape(line)}</text>'
            )

    parts.append(
        '<text x="480" y="608" fill="#6c7086" font-family="Segoe UI, sans-serif" font-size="10" text-anchor="middle">'
        '红色=命中提权链 · 灰色=未命中典型模式 · K8s Commander</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def format_attack_graph_section(result: dict, image_ref: str | None = None) -> List[str]:
    """Markdown 章节：摘要 + 图片 + Mermaid 代码块。"""
    overall = result.get("overall_risk") or {}
    allowed_n = len(result.get("allowed_permissions") or [])
    total_n = len(result.get("permissions") or [])
    chains_n = len(result.get("escalation_chains") or [])
    admin = is_effectively_cluster_admin(result)

    md = [
        "## 提权攻击图",
        "",
        "| 指标 | 值 |",
        "|------|-----|",
        f"| ServiceAccount | `{_sa_label(result)}` |",
        f"| 有效权限 | {allowed_n}/{total_n} |",
        f"| 匹配提权链 | {chains_n} |",
        f"| 总体风险 | {overall.get('emoji', '')} **{overall.get('label', '')}** |",
        "",
    ]

    if admin:
        md.extend([
            "> **说明**：SelfSubjectRulesReview 显示集群级 `* * (*)` 或等效权限，"
            "当前身份已等价 **cluster-admin**。下图 **红色节点** 为本次审计命中的提权链路径；"
            "灰色节点为未命中但仍属典型风险模式（低权限 SA 上可能出现）。",
            "",
        ])
    else:
        md.extend([
            "> **说明**：下图 **红色** 为本次审计命中的提权链，**灰色** 为未命中的典型模式。",
            "",
        ])

    if image_ref:
        md.extend([
            f"![RBAC 提权攻击图]({image_ref})",
            "",
            "*（上图为 SVG，与 Markdown 同目录保存；任意编辑器均可直接预览）*",
            "",
        ])

    md.extend([
        "<details>",
        "<summary>Mermaid 源码（GitHub / Typora 可渲染）</summary>",
        "",
        "```mermaid",
        build_attack_graph_mermaid(result),
        "```",
        "",
        "</details>",
        "",
        "### 命中提权链一览",
        "",
    ])

    chains = result.get("escalation_chains") or []
    if chains:
        for i, c in enumerate(chains, 1):
            md.append(f"{i}. **{c.get('name', '')}** ({c.get('risk', '')}) — 需要: `{', '.join(c.get('requires') or [])}`")
    else:
        md.append("（本次未匹配预定义提权链）")

    md.append("")
    return md
