#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K8s Commander — Kubernetes 安全审计 / 命令生成工具
仅用于已授权的安全自查、合规性审计与运维排错。

入口脚本；实现代码位于 commander/ 包。
"""
from commander.config import APP_VERSION, DATA_DIR, ensure_data_dirs, migrate_legacy_config

ensure_data_dirs()
migrate_legacy_config()

from commander.app import K8sCommander

if __name__ == "__main__":
    print(f"K8s Commander {APP_VERSION}")
    print(f"数据目录: {DATA_DIR}")
    K8sCommander().mainloop()
