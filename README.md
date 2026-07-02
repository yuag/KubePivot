
<img width="1536" height="1024" alt="Generated_image" src="https://github.com/user-attachments/assets/e74403a0-094e-4b17-850e-962d042106b8" />



# KubePivot 使用说明


> 用途：已授权环境下的 K8s / 容器 / 云渗透

---

## 1. 启动

```bash
python k8s_commander.py
```

或双击 **`run.bat`**。。

---

## 2. 界面一览

| 标签 | 干什么 |
|------|--------|
| 环境识别 | 粘贴 env、云/K8s 判定、经 SOCKS 探测 |
| 基础命令 | 命令库 + 参数 + 执行（可改预览框再执行） |
| 资源浏览 | 看 Pod 树，双击进 Pod 终端 |
| Pod 终端 | 列目录、看文件、下载、外部开 shell |
| RBAC 审计 | 查 SA 权限、提权链、导出报告+攻击图 |
| AI 安全专家 | 大模型分析结果 |
| SOCKS5 代理 | Neo-reGeorg 等隧道 |

---

## 3. 连本地 K8s（Docker Desktop / Goat）

| 参数 | 填什么 |
|------|--------|
| API Server | `https://127.0.0.1:6443` |
| Bearer Token | `kubectl create token xxx -n default --duration=24h` |
| 跳过 TLS | 勾选 |

测试：选 **K8s API /version** → 执行。

---

## 4. SOCKS 内网（Neo-reGeorg）

1. SOCKS5 页：启用 → `127.0.0.1:1080` → 应用 → 检测  
2. API 用 **内网 IP**，不要用 `kubernetes.default.svc`  
3. 环境识别 → **经 SOCKS 探测**



---

## 5. 常用操作

**进容器**  
资源浏览 → 双击 Pod → **Pod 终端** → 外部终端打开

**RBAC 审计**  
填 API + Token → RBAC 审计 → 执行 → **导出 Markdown**（含 SVG 攻击图）

**加载 SA**  
只在 **Pod 内** 有效；Windows 本机请手动填 Token。

---



---

## 6. 常见问题

| 问题               | 处理                          |
| ------------------ | ----------------------------- |
| `my-pod` not found | 资源浏览双击真实 Pod          |
| exec 卡住          | 用 Pod 终端 → 外部终端       |
| 导出没图           | 同目录找 `*_attack_graph.svg` |
| 加载 SA 失败       | 本机手动填 Token              |

---





---

## 7. 功能展示
<br>

  自动识别环境

<img width="1206" height="829" alt="image" src="https://github.com/user-attachments/assets/e596bca1-be4d-4c47-8942-fb4c4ba2d57f" />

<br>
<br>

 k8s+云平台基础命令+可以发送给ai识别是否有漏洞



<img width="1866" height="994" alt="image" src="https://github.com/user-attachments/assets/f864d2b9-0d21-47dd-95b1-85770c1144bc" />

<br>
<br>

资源浏览需要最高权限

<img width="1639" height="493" alt="image" src="https://github.com/user-attachments/assets/88b36164-b648-4b07-b2d7-1526ce14991a" />

<br>
<br>



进入环境+可以执行命令+下载文件

<img width="1885" height="839" alt="image" src="https://github.com/user-attachments/assets/1b3a3763-4d46-48c4-b53c-d31e1a70a689" />


<br>
<br>



自动检查看是否有漏洞过出+poc+可以导出markdown 查看攻击方法

<img width="1321" height="966" alt="image" src="https://github.com/user-attachments/assets/76691860-2384-433f-a113-fd8ee0f34f44" />

<img width="1200" height="796" alt="image" src="https://github.com/user-attachments/assets/3a31d850-6999-4b0e-909c-618a44f406a0" />



<br>
<br>

ai评估，ai每一次回答都自动保存

<img width="1895" height="970" alt="6b011d3f7340aa19614762d2860c8797" src="https://github.com/user-attachments/assets/b8b8dd54-00ff-49b8-b422-57d04b575476" />


<br>
<br>


socks5代理建议使用工具(https://github.com/L-codes/Neo-reGeorg/releases)



<img width="1299" height="805" alt="image" src="https://github.com/user-attachments/assets/ac95db49-84fe-443a-81e6-5fdaa33e7919" />






---







<br>
<br>
## 免责声明

仅限 **已获得授权** 的安全测试。 使用违法，后果自负。
