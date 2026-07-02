"""主题色、路径与日志。"""
import os
import logging
import shutil

BG = "#1e1e2e"
BG2 = "#2a2a3e"
BG3 = "#313145"
ACCENT = "#7c6af7"
ACCENT2 = "#5e5bd4"
SUCCESS = "#50fa7b"
WARN = "#f1fa8c"
DANGER = "#ff5555"
TEXT = "#cdd6f4"
TEXT2 = "#a6adc8"
BORDER = "#45475a"
GREEN = "#a6e3a1"
CYAN = "#89dceb"
CARD = "#252538"
HOVER = "#3d3d55"

# commander 包的上一级，即 k8s_commander.py 所在目录（程序根目录）
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(APP_ROOT, "data")

# 容器内 ServiceAccount 默认挂载路径（命令脚本 / 预览用）
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

CONFIG_DIR = DATA_DIR
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
CONFIG_EXAMPLE_PATH = os.path.join(DATA_DIR, "config.example.json")
LOG_PATH = os.path.join(DATA_DIR, "k8s_commander.log")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

APP_VERSION = "v2.11.2"

# 旧版配置位置（%APPDATA%\k8s-commander），首次启动时自动迁移
_LEGACY_CONFIG_DIR = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")), "k8s-commander",
)
_LEGACY_CONFIG_PATH = os.path.join(_LEGACY_CONFIG_DIR, "config.json")

logger = logging.getLogger("k8s_commander")


def ensure_data_dirs():
    """确保 data/ 及 reports/ 目录存在。"""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    readme = os.path.join(DATA_DIR, "说明.txt")
    if not os.path.isfile(readme):
        try:
            with open(readme, "w", encoding="utf-8") as f:
                f.write(
                    "K8s Commander 数据目录\n\n"
                    "config.json       — API Key 与界面配置\n"
                    "k8s_commander.log — 运行日志\n"
                    "reports/          — AI 审计报告\n\n"
                    "整包复制程序文件夹（含 data/）即可迁移到其他电脑。\n"
                )
        except OSError:
            pass


def ensure_example_config():
    """首次运行：若无 config.json，从 config.example.json 复制（无密钥模板）。"""
    if os.path.isfile(CONFIG_PATH):
        return
    if not os.path.isfile(CONFIG_EXAMPLE_PATH):
        return
    try:
        ensure_data_dirs()
        shutil.copy2(CONFIG_EXAMPLE_PATH, CONFIG_PATH)
        logger.info("已从模板创建配置: %s", CONFIG_PATH)
    except OSError as e:
        logger.warning("从模板创建配置失败: %s", e)


def migrate_legacy_config():
    """若程序目录尚无配置，则从旧版 APPDATA 位置迁移一次。"""
    if os.path.isfile(CONFIG_PATH):
        return
    ensure_example_config()
    if os.path.isfile(CONFIG_PATH):
        return
    if not os.path.isfile(_LEGACY_CONFIG_PATH):
        return
    try:
        ensure_data_dirs()
        shutil.copy2(_LEGACY_CONFIG_PATH, CONFIG_PATH)
        logger.info("已从旧位置迁移配置: %s -> %s", _LEGACY_CONFIG_PATH, CONFIG_PATH)
    except OSError as e:
        logger.warning("迁移旧配置失败: %s", e)


def _setup_logging():
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    try:
        ensure_data_dirs()
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        pass


_setup_logging()
