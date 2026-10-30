# Pxxl App · VLESS + WS + TLS（纯 Node 版）

> Pxxl Free 的 TLS 在平台边缘（`<name>.pxxlspace.cv:443`）终止，容器里只跑明文 WS。
> 客户端参数：`security=tls`、`type=ws`、`sni=<host>`、`host=<host>`。
> 本目录用**一个纯 Node 进程**实现 VLESS/WS，不下载 Xray、不用 `unzip`、不拉子进程；部署步骤和客户端参数与
> [free-dam-man/pxxl-xray-ws-tls-skill](https://github.com/free-dam-man/pxxl-xray-ws-tls-skill) 一致。

## 文件

```text
pxxl/
├─ package.json      # Pxxl 识别为 Node；start = node server.js
├─ server.js         # VLESS + WS + TCP 转发 + /__health
├─ make_link.sh      # 生成 vless:// TLS 链接
├─ .env.example      # 环境变量模板（占位符）
└─ .gitignore        # 不提交 .uuid/.env/sub
```

## 部署步骤

### 1. 推到 GitHub

在 GitHub 新建一个空仓库（public/private 都行），把本目录三个文件推上去：

```bash
cd pxxl
git init
git add package.json server.js make_link.sh README.md .gitignore
git commit -m "Pxxl VLESS WS node"
git branch -M main
git remote add origin https://github.com/<你的账号>/<仓库名>.git
git push -u origin main
```

> 不要提交 `.env.local`、真实 UUID、真实 WSPATH、`.uuid`。`.gitignore` 已忽略它们。

### 2. 在 Pxxl 创建项目

1. 打开 [app.pxxl.app](https://app.pxxl.app)，用 **GitHub OAuth** 登录。
2. 安装 **Pxxl GitHub App**，只授权刚才那个仓库。
3. 从该仓库创建项目：
   - Language / 环境：**Node**
   - Start command：`npm start`（或 `node server.js`）
   - **Free 方案不要选 Docker / Dockerfile / Drop**
4. 在环境变量里填：

| 变量 | 值 | 说明 |
|---|---|---|
| `UUID` | 你的 UUIDv4 | 必填；也可用别名 `APP_KEY` |
| `WSPATH` | `/px-xxxxxxxx` | 必填，以 `/` 开头；也可用 `API_ROUTE` |
| `PUBLIC_HOST` | `<项目名>.pxxlspace.cv` | 部署后拿到的主机名；先留空也行 |
| `EDGE_TLS` | `1` | 让控制台按 TLS/443 打印链接 |
| `NODE_NAME` | `Pxxl-WS` | 客户端显示名，可选 |

> `PORT` 由 Pxxl 注入，**不要手动设**。

5. 点 Deploy，等状态变成 **Deployed**，记下 HTTPS 主机名（形如 `xxx.pxxlspace.cv`）。

### 3. 生成客户端链接

部署后把 `PUBLIC_HOST` 改成真实主机名、`EDGE_TLS=1`，重启一次；控制台会打印：

```text
vless://<UUID>@<HOST>:443?encryption=none&security=tls&type=ws&host=<HOST>&path=%2Fpx-...&sni=<HOST>#Pxxl-WS
```

也可以本地生成：

```bash
bash pxxl/make_link.sh <UUID> <HOST> <WSPATH> Pxxl-WS
```

### 4. 验收（必须做）

用真实客户端（Clash/mihomo、Xray、sing-box）导入上面的链接，经本地 SOCKS 请求：

```bash
curl -sS --socks5-hostname 127.0.0.1:<SOCKS端口> \
  -o /dev/null -w '%{http_code}\n' https://www.gstatic.com/generate_204
```

必须是 **204**，再查出口 IP/ASN（Pxxl 免费池通常是 AWS 机房）。面板显示 Deployed 不算验收。

健康检查：`https://<HOST>/__health` 应返回 `{"ok":true,...}`。

## 限制与风险

- **Pxxl Free 条款没有明确写“允许代理”**；它有滥用扫描和封禁条款。免费实例可能被回收/停服，**当备用，不要当主力**。
- 出口是 AWS 机房 IP，不是住宅宽带；换实例可能变。
- Pxxl 边缘到容器是明文 WS；客户端到边缘是 TLS。不要在容器里再谈“端到端加密”。
- 免费方案只支持 GitHub 仓库部署；Docker/Drop 是付费路径。
- 不要把真实 UUID/WSPATH/主机名/订阅提交到公开仓库；泄露后任何人都能用你的出口。
- 本项目不提供绕过平台检测的混淆或伪装；平台是否允许这类用途由它的条款决定。

## 本地自测

```bash
PORT=24007 UUID=<uuid> WSPATH=/px-test PUBLIC_HOST=demo.pxxlspace.cv EDGE_TLS=1 \
  node pxxl/server.js
curl -sS http://127.0.0.1:24007/__health
```

本地只验证容器内的 VLESS/WS；TLS 由 Pxxl 边缘提供，必须部署后用真实客户端验收。
