"""Pod 内非交互命令、文件浏览与 kubectl cp 下载。"""
import os
import platform
import re
import shlex
import subprocess
from typing import List, Optional, Tuple

_LS_LINE = re.compile(
    r"^(?P<mode>[d-][rwx-]{9})\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+(?:\d{2}:\d{2}|\d{4})\s+(?P<name>.+)$"
)


def exec_in_pod(
    namespace: str,
    pod: str,
    shell_cmd: str,
    container: Optional[str] = None,
    timeout: int = 60,
) -> Tuple[int, str, str]:
    """在 Pod 内执行单条 shell 命令（非交互，无 -it）。"""
    args = ["kubectl", "exec", pod, "-n", namespace]
    if container:
        args.extend(["-c", container])
    args.extend(["--", "sh", "-c", shell_cmd])
    try:
        res = subprocess.run(
            args, capture_output=True, timeout=timeout, text=True, errors="replace",
        )
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"超时 ({timeout}s)"
    except FileNotFoundError:
        return -1, "", "未找到 kubectl，请安装并加入 PATH"


def cp_from_pod(
    namespace: str,
    pod: str,
    remote_path: str,
    local_path: str,
    container: Optional[str] = None,
    timeout: int = 120,
) -> Tuple[int, str, str]:
    """从 Pod 复制文件/目录到本机。"""
    remote = f"{namespace}/{pod}:{remote_path}"
    args = ["kubectl", "cp", remote, local_path]
    if container:
        args.extend(["-c", container])
    try:
        res = subprocess.run(
            args, capture_output=True, timeout=timeout, text=True, errors="replace",
        )
        msg = (res.stderr or res.stdout or "").strip()
        return res.returncode, msg, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"超时 ({timeout}s)"
    except FileNotFoundError:
        return -1, "", "未找到 kubectl，请安装并加入 PATH"


def join_pod_path(base: str, name: str) -> str:
    base = (base or "/").rstrip("/") or ""
    if base == "":
        return f"/{name.lstrip('/')}"
    return f"{base}/{name}"


def parent_pod_path(path: str) -> str:
    path = (path or "/").rstrip("/")
    if not path or path == "/":
        return "/"
    parent = os.path.dirname(path).replace("\\", "/")
    return parent or "/"


def parse_ls_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or line.startswith("total "):
        return None
    m = _LS_LINE.match(line)
    if not m:
        return None
    mode = m.group("mode")
    name = m.group("name").strip()
    if name in (".", ".."):
        return None
    return {
        "name": name,
        "kind": "dir" if mode.startswith("d") else "file",
        "mode": mode,
        "raw": line,
    }


def list_dir(
    namespace: str,
    pod: str,
    path: str = "/",
    container: Optional[str] = None,
) -> Tuple[int, List[dict], str]:
    """列出 Pod 内目录内容。"""
    path = (path or "/").strip() or "/"
    quoted = shlex.quote(path)
    code, out, err = exec_in_pod(
        namespace, pod, f"ls -la {quoted} 2>&1", container=container, timeout=45,
    )
    entries = []
    for line in out.splitlines():
        ent = parse_ls_line(line)
        if ent:
            ent["path"] = join_pod_path(path, ent["name"])
            entries.append(ent)
    if code != 0 and not entries:
        return code, [], (err or out).strip()
    return 0 if entries else code, entries, err


def read_file(
    namespace: str,
    pod: str,
    remote_path: str,
    container: Optional[str] = None,
    max_bytes: int = 512_000,
) -> Tuple[int, str, str]:
    """读取 Pod 内文本文件（过大则截断）。"""
    quoted = shlex.quote(remote_path)
    code, out, err = exec_in_pod(
        namespace,
        pod,
        f"wc -c {quoted} 2>/dev/null; cat {quoted} 2>&1",
        container=container,
        timeout=60,
    )
    if code != 0:
        return code, "", (err or out).strip()
    lines = out.splitlines()
    if not lines:
        return 0, "", ""
    # 第一行可能是 wc 输出
    body = out
    if lines and lines[0].strip().isdigit() and len(lines) > 1:
        try:
            size = int(lines[0].strip())
            body = "\n".join(lines[1:])
            if size > max_bytes:
                body = body[:max_bytes] + f"\n\n… 已截断（文件约 {size} 字节，仅显示前 {max_bytes} 字节）"
        except ValueError:
            pass
    elif len(out.encode("utf-8", errors="ignore")) > max_bytes:
        body = out[:max_bytes] + f"\n\n… 已截断（仅显示前 {max_bytes} 字节）"
    return 0, body, ""


def open_external_shell(
    namespace: str,
    pod: str,
    container: Optional[str] = None,
) -> Tuple[bool, str]:
    """在新终端窗口打开 kubectl exec -it 交互 shell。"""
    args = ["kubectl", "exec", "-it", pod, "-n", namespace]
    if container:
        args.extend(["-c", container])
    args.extend(["--", "/bin/sh"])

    system = platform.system()
    try:
        if system == "Windows":
            try:
                subprocess.Popen(["wt.exe", "new-tab", "--"] + args, close_fds=True)
                return True, "已在 Windows Terminal 中打开"
            except FileNotFoundError:
                subprocess.Popen(
                    ["cmd", "/c", "start", "K8s Pod Shell", "cmd", "/k"] + args,
                    close_fds=True,
                )
                return True, "已在新 cmd 窗口中打开"
        for term in (
            ["x-terminal-emulator", "-e"] + args,
            ["gnome-terminal", "--"] + args,
            ["konsole", "-e"] + args,
            ["xterm", "-e"] + args,
        ):
            try:
                subprocess.Popen(term, close_fds=True)
                return True, "已在外部终端中打开"
            except FileNotFoundError:
                continue
        subprocess.Popen(args, close_fds=True)
        return True, "已启动 kubectl exec（请查看当前终端）"
    except Exception as e:
        return False, str(e)
