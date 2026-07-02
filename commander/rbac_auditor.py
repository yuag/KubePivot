"""RBAC 权限审计（SelfSubjectAccessReview + 提权链匹配）。"""
from __future__ import annotations

import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from commander import socks_proxy
from commander.env_detector import EnvironmentDetector
from commander.rbac_graph import format_attack_graph_section
from commander.rbac_rules import (
    ESCALATION_PATTERNS,
    LEVEL_LABEL,
    LEVEL_ORDER,
    PERMISSION_CHECKS,
    RECOMMENDATIONS,
)

ProgressFn = Optional[Callable[[str, int, int], None]]

SSAR_PATH = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
RULES_PATH = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


def _perm_key(verb: str, resource: str) -> str:
    return f"{verb} {resource}"


def _scope_label(scope: str, namespace: str) -> str:
    if scope == "cluster":
        return "cluster"
    if scope == "kube-system":
        return "kube-system"
    return namespace or "default"


class RBACAuditor:
    def __init__(
        self,
        apiserver: str,
        token: str,
        namespace: str = "default",
        skip_tls: bool = True,
    ):
        self.apiserver = (apiserver or "").strip().rstrip("/")
        if self.apiserver and not self.apiserver.startswith("http"):
            self.apiserver = "https://" + self.apiserver
        self.token = (token or "").strip()
        self.namespace = (namespace or "default").strip()
        self.skip_tls = skip_tls

    def _post_json(self, path: str, payload: dict, timeout: int = 15) -> Tuple[Optional[dict], Optional[str]]:
        url = self.apiserver + path
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        body = json.dumps(payload).encode("utf-8")
        status, text = socks_proxy.http_fetch(
            url, "POST", headers, body, timeout, skip_tls=self.skip_tls,
        )
        if status is None:
            return None, text
        if status >= 400:
            return None, f"HTTP {status}: {text[:300]}"
        try:
            return json.loads(text), None
        except json.JSONDecodeError as e:
            return None, f"JSON 解析失败: {e}"

    def can_i(self, check: dict) -> dict:
        scope = check["scope"]
        ns = self.namespace
        if scope == "kube-system":
            ns = "kube-system"
        elif scope == "cluster":
            ns = None

        attrs: Dict[str, Any] = {
            "verb": check["verb"],
            "resource": check["resource"],
        }
        if check.get("group"):
            attrs["group"] = check["group"]
        if ns:
            attrs["namespace"] = ns

        payload = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": attrs},
        }
        data, err = self._post_json(SSAR_PATH, payload)
        allowed = False
        reason = err or ""
        if data:
            st = data.get("status") or {}
            allowed = bool(st.get("allowed"))
            reason = st.get("reason") or ("allowed" if allowed else "denied")

        label = _scope_label(scope, self.namespace)
        return {
            "level": check["level"],
            "verb": check["verb"],
            "resource": check["resource"],
            "group": check.get("group") or "",
            "scope": label,
            "allowed": allowed,
            "reason": reason,
            "key": _perm_key(check["verb"], check["resource"]),
        }

    def fetch_rules_review(self) -> Tuple[Optional[dict], Optional[str]]:
        payload = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": self.namespace},
        }
        return self._post_json(RULES_PATH, payload)

    def audit(self, progress: ProgressFn = None) -> dict:
        if not self.apiserver or not self.token:
            raise ValueError("需要 API Server 与 Bearer Token")

        total = len(PERMISSION_CHECKS)
        results: List[dict] = []

        def run_one(idx_check):
            idx, check = idx_check
            return idx, self.can_i(check)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(run_one, (i, c)): i
                for i, c in enumerate(PERMISSION_CHECKS)
            }
            done = 0
            for fut in as_completed(futures):
                idx, item = fut.result()
                results.append((idx, item))
                done += 1
                if progress:
                    progress(
                        f"检测 {item['verb']} {item['resource']} @ {item['scope']}",
                        done, total,
                    )

        results.sort(key=lambda x: x[0])
        permissions = [r[1] for r in results]
        allowed = [p for p in permissions if p["allowed"]]
        allowed_keys = list(dict.fromkeys(p["key"] for p in allowed))

        if progress:
            progress("SelfSubjectRulesReview…", total, total + 1)
        rules_data, rules_err = self.fetch_rules_review()
        rules_summary = _summarize_rules(rules_data, rules_err)

        chains = _match_escalation_chains(allowed_keys)
        overall = _overall_risk(allowed, chains)
        recommendations = _build_recommendations(allowed, chains)

        jwt = EnvironmentDetector.parse_jwt(self.token) or {}
        sa_ns = jwt.get("kubernetes.io/serviceaccount/namespace", self.namespace)
        sa_name = ""
        sub = jwt.get("sub", "")
        if sub.startswith("system:serviceaccount:"):
            parts = sub.split(":")
            if len(parts) >= 4:
                sa_name = parts[3]
                sa_ns = parts[2]

        return {
            "apiserver": self.apiserver,
            "namespace": self.namespace,
            "service_account": sa_name or sub or "unknown",
            "sa_namespace": sa_ns,
            "permissions": permissions,
            "allowed_permissions": allowed,
            "allowed_keys": allowed_keys,
            "escalation_chains": chains,
            "overall_risk": overall,
            "recommendations": recommendations,
            "rules_summary": rules_summary,
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        }


def _summarize_rules(data: Optional[dict], err: Optional[str]) -> dict:
    if err or not data:
        return {"error": err or "无响应", "lines": []}
    status = data.get("status") or {}
    lines = []
    for rule in (status.get("resourceRules") or [])[:15]:
        verbs = ",".join(rule.get("verbs") or [])
        resources = ",".join(rule.get("resources") or [])
        api_groups = ",".join(rule.get("apiGroups") or [""])
        lines.append(f"{verbs} {resources} ({api_groups})")
    return {"lines": lines, "truncated": len(status.get("resourceRules") or []) > 15}


def _match_escalation_chains(allowed_keys: List[str]) -> List[dict]:
    allowed_set = set(allowed_keys)
    matched = []
    for pat in ESCALATION_PATTERNS:
        for req_list in pat["requires_any"]:
            if all(r in allowed_set for r in req_list):
                matched.append({
                    "id": pat["id"],
                    "name": pat["name"],
                    "risk": pat["risk"],
                    "requires": req_list,
                    "steps": pat["steps"],
                    "poc": pat["poc"],
                })
                break
    risk_order = {"critical": 0, "high": 1}
    matched.sort(key=lambda x: risk_order.get(x["risk"], 9))
    return matched


def _overall_risk(allowed: List[dict], chains: List[dict]) -> dict:
    if not allowed:
        return {"level": "low", "label": "低", "emoji": "🟢", "summary": "未发现高危权限"}

    levels = {p["level"] for p in allowed}
    if "critical" in levels or any(c["risk"] == "critical" for c in chains):
        return {
            "level": "critical",
            "label": "严重",
            "emoji": "🔴",
            "summary": f"发现严重权限 / {len(chains)} 条提权链",
        }
    if "high" in levels or chains:
        return {
            "level": "high",
            "label": "高",
            "emoji": "🟠",
            "summary": f"存在高风险权限，{len(chains)} 条提权链",
        }
    if "medium" in levels:
        return {"level": "medium", "label": "中", "emoji": "🟡", "summary": "存在中等风险权限"}
    return {"level": "low", "label": "低", "emoji": "🟢", "summary": "主要为信息收集级权限"}


def _build_recommendations(allowed: List[dict], chains: List[dict]) -> List[str]:
    recs = []
    levels = {p["level"] for p in allowed}
    for lv in ("critical", "high", "medium"):
        if lv in levels:
            recs.extend(RECOMMENDATIONS.get(lv, []))
    if chains and "建议对 ServiceAccount 做定期 RBAC 审计" not in recs:
        recs.append("建议对 ServiceAccount 做定期 RBAC 审计并记录变更")
    return list(dict.fromkeys(recs))[:8]


def format_report_text(result: dict) -> str:
    overall = result["overall_risk"]
    lines = [
        "=" * 56,
        "RBAC 权限审计报告",
        "=" * 56,
        f"时间:     {result['timestamp']}",
        f"API:      {result['apiserver']}",
        f"SA:       {result['sa_namespace']}/{result['service_account']}",
        f"Namespace:{result['namespace']}",
        f"总体风险: {overall['emoji']} {overall['label']} — {overall['summary']}",
        "",
    ]

    allowed = result["allowed_permissions"]
    lines.append(f"── 有效权限 ({len(allowed)}/{len(result['permissions'])}) ──")
    if allowed:
        sorted_allowed = sorted(allowed, key=lambda p: (LEVEL_ORDER.get(p["level"], 9), p["key"]))
        for p in sorted_allowed:
            lv = LEVEL_LABEL.get(p["level"], p["level"])
            lines.append(f"  ✅ [{lv}] {p['verb']} {p['resource']}  @ {p['scope']}")
    else:
        lines.append("  （无检测项返回 allowed）")

    denied_sample = [p for p in result["permissions"] if not p["allowed"]][:5]
    if denied_sample:
        lines.append("")
        lines.append("── 部分拒绝（示例）──")
        for p in denied_sample:
            lines.append(f"  ✗ {p['verb']} {p['resource']} @ {p['scope']}")

    chains = result["escalation_chains"]
    lines.append("")
    lines.append(f"── 提权链 ({len(chains)}) ──")
    if chains:
        for i, c in enumerate(chains, 1):
            lines.append(f"\n【链 {i}】{c['name']}  (风险: {c['risk']})")
            lines.append(f"  需要: {', '.join(c['requires'])}")
            for step in c["steps"]:
                lines.append(f"  • {step}")
            lines.append("  PoC:")
            for pl in c["poc"].split("\n"):
                lines.append(f"    {pl}")
    else:
        lines.append("  未匹配到预定义提权链（仍可能存在其他组合风险）")

    rs = result.get("rules_summary") or {}
    lines.append("")
    lines.append("── SelfSubjectRulesReview 摘要 ──")
    if rs.get("error"):
        lines.append(f"  {rs['error']}")
    elif rs.get("lines"):
        for ln in rs["lines"]:
            lines.append(f"  • {ln}")
        if rs.get("truncated"):
            lines.append("  …（已截断，完整规则见 API 响应）")
    else:
        lines.append("  （无规则数据）")

    recs = result.get("recommendations") or []
    if recs:
        lines.append("")
        lines.append("── 修复建议 ──")
        for r in recs:
            lines.append(f"  • {r}")

    lines.append("")
    lines.append("=" * 56)
    return "\n".join(lines)


def format_report_markdown(result: dict, graph_image: str | None = None) -> str:
    overall = result["overall_risk"]
    md = [
        "# RBAC 权限审计报告",
        "",
        f"- **时间**: {result['timestamp']}",
        f"- **API Server**: `{result['apiserver']}`",
        f"- **ServiceAccount**: `{result['sa_namespace']}/{result['service_account']}`",
        f"- **Namespace**: `{result['namespace']}`",
        f"- **总体风险**: {overall['emoji']} **{overall['label']}** — {overall['summary']}",
        "",
    ]
    md.extend(format_attack_graph_section(result, image_ref=graph_image))
    md.extend([
        "## 有效权限",
        "",
    ])
    allowed = sorted(
        result["allowed_permissions"],
        key=lambda p: (LEVEL_ORDER.get(p["level"], 9), p["key"]),
    )
    if allowed:
        md.append("| 等级 | 权限 | 范围 |")
        md.append("|------|------|------|")
        for p in allowed:
            lv = LEVEL_LABEL.get(p["level"], p["level"])
            md.append(f"| {lv} | `{p['verb']} {p['resource']}` | {p['scope']} |")
    else:
        md.append("（无）")

    md.extend(["", "## 提权链", ""])
    for i, c in enumerate(result["escalation_chains"], 1):
        md.append(f"### 链 {i}: {c['name']}")
        md.append(f"- **风险**: {c['risk']}")
        md.append(f"- **需要权限**: {', '.join(f'`{r}`' for r in c['requires'])}")
        md.append("- **步骤**:")
        for step in c["steps"]:
            md.append(f"  1. {step}")
        md.append("")
        md.append("```bash")
        md.append(c["poc"])
        md.append("```")
        md.append("")

    md.extend(["## RulesReview 摘要", ""])
    rs = result.get("rules_summary") or {}
    if rs.get("lines"):
        md.append("```")
        md.extend(rs["lines"])
        md.append("```")
    else:
        md.append(rs.get("error") or "（无）")

    md.extend(["", "## 修复建议", ""])
    for r in result.get("recommendations") or []:
        md.append(f"- {r}")

    return "\n".join(md)
