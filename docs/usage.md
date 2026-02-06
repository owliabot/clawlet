# Clawlet 使用指南

> Agent-native wallet engine for OpenClaw — 给本地 agent 用的链上操作引擎

---

## 目录

1. [快速开始](#快速开始)
2. [安装](#安装)
3. [初始化](#初始化)
4. [配置文件](#配置文件)
5. [启动服务](#启动服务)
6. [Token 认证](#token-认证)
7. [API 接口](#api-接口)
8. [策略配置](#策略配置)
9. [常见问题](#常见问题)

---

## 快速开始

```bash
# 1. 安装
cargo install --git https://github.com/owliabot/clawlet clawlet-cli

# 2. 初始化（生成钱包 + 配置）
clawlet init

# 3. 授权 AI agent（生成 token）
clawlet auth grant --scope read,trade --label "my-agent"

# 4. 启动服务
clawlet serve

# 5. 测试
curl -H "Authorization: Bearer <token>" http://127.0.0.1:9100/health
```

---

## 安装

### 从源码编译

```bash
# 需要 Rust 工具链: https://rustup.rs
git clone https://github.com/owliabot/clawlet.git
cd clawlet
cargo build --release
sudo cp target/release/clawlet /usr/local/bin/
```

### 使用 cargo install

```bash
cargo install --git https://github.com/owliabot/clawlet clawlet-cli
```

### 验证安装

```bash
clawlet --version
# clawlet 0.1.0
```

---

## 初始化

### 创建新钱包

```bash
clawlet init
```

这会：
1. 生成 24 词 BIP-39 助记词
2. 派生第一个地址（m/44'/60'/0'/0/0）
3. 用密码加密私钥（Ethereum V3 keystore 格式）
4. 创建默认配置文件

**⚠️ 重要**：请安全备份显示的助记词，这是恢复钱包的唯一方式。

### 从助记词恢复

```bash
clawlet init --from-mnemonic
```

按提示输入已有的助记词。

### 自定义数据目录

```bash
clawlet init --data-dir /path/to/clawlet
```

默认数据目录：`~/.clawlet/`

### 初始化后的目录结构

```
~/.clawlet/
├── config.yaml          # 主配置文件
├── policy.yaml          # 策略规则
├── keystore/            # 加密私钥
│   └── UTC--2026-...    # V3 keystore 文件
└── audit.jsonl          # 审计日志（启动后生成）
```

---

## 配置文件

### config.yaml

```yaml
# RPC 绑定地址
rpc_bind: "127.0.0.1:9100"

# 策略文件路径
policy_path: "~/.clawlet/policy.yaml"

# Keystore 目录
keystore_path: "~/.clawlet/keystore"

# 审计日志路径
audit_log_path: "~/.clawlet/audit.jsonl"

# 链 RPC 节点
chain_rpc_urls:
  8453: "https://mainnet.base.org"           # Base
  1: "https://eth.llamarpc.com"              # Ethereum Mainnet
  10: "https://mainnet.optimism.io"          # Optimism
  42161: "https://arb1.arbitrum.io/rpc"      # Arbitrum
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `CLAWLET_HOME` | 数据目录 | `~/.clawlet` |
| `CLAWLET_AUTH_TOKEN` | 认证 token（dev mode） | 无 |
| `CLAWLET_LOG` | 日志级别 | `info` |

---

## 启动服务

### HTTP 模式（默认）

```bash
clawlet serve
```

服务运行在 `127.0.0.1:9100`。

### Unix Socket 模式

适用于 Node.js / Python 等非 Rust 客户端：

```bash
clawlet serve --socket
# 默认: /run/clawlet/clawlet.sock

# 自定义路径
clawlet serve --socket /tmp/clawlet.sock
```

### 指定配置文件

```bash
clawlet serve --config /path/to/config.yaml
```

### 作为 systemd 服务运行

参见 [deployment.md](./deployment.md) 获取完整的 systemd 配置。

---

## Token 认证

Clawlet 使用 session token 机制控制 AI agent 的访问权限。

### 生成 Token

```bash
# 只读权限
clawlet auth grant --scope read --label "monitor-bot"

# 交易权限
clawlet auth grant --scope read,trade --label "trading-agent"
```

输出示例：
```
Token: clwt_abc123...xyz789
Scope: read, trade
Label: trading-agent
Expires: never

Save this token — it cannot be retrieved later.
```

### 权限范围（Scope）

| Scope | 说明 | 可调用接口 |
|-------|------|-----------|
| `read` | 只读 | `/health`, `/balance` |
| `trade` | 交易 | `/transfer` |

### 列出所有 Token

```bash
clawlet auth list
```

输出：
```
ID      Label           Scope           Created
─────────────────────────────────────────────────
a1b2    monitor-bot     read            2026-02-04 10:30
c3d4    trading-agent   read,trade      2026-02-04 11:45
```

### 撤销 Token

```bash
clawlet auth revoke --id a1b2
```

---

## API 接口

### 认证

所有请求需要在 Header 中带 Bearer token：

```bash
curl -H "Authorization: Bearer clwt_xxx" http://127.0.0.1:9100/...
```

### GET /health

健康检查（无需认证）。

```bash
curl http://127.0.0.1:9100/health
```

响应：
```json
{"status": "ok"}
```

### GET /balance

查询余额（需要 `read` scope）。

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9100/balance?address=0x742d35Cc6634C0532925a3b844Bc9e7595f0Ab&chain_id=8453"
```

参数：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `address` | string | 是 | 要查询的地址 |
| `chain_id` | number | 是 | 链 ID |
| `tokens` | string[] | 否 | ERC-20 合约地址列表 |

响应：
```json
{
  "eth": "1.234567890123456789",
  "tokens": [
    {
      "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
      "symbol": "USDC",
      "decimals": 6,
      "balance": "1000.000000"
    }
  ]
}
```

### POST /transfer

执行转账（需要 `trade` scope）。

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0Ab",
    "amount": "0.1",
    "token": "ETH",
    "chain_id": 8453
  }' \
  http://127.0.0.1:9100/transfer
```

请求体：
| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `to` | string | 是 | 目标地址 |
| `amount` | string | 是 | 转账金额 |
| `token` | string | 是 | `"ETH"` 或 ERC-20 合约地址 |
| `chain_id` | number | 是 | 链 ID |

成功响应：
```json
{
  "status": "success",
  "tx_hash": "0xabc...def",
  "audit_id": "evt_123456"
}
```

失败响应（策略拒绝）：
```json
{
  "status": "denied",
  "reason": "Transfer exceeds daily limit (100 USD)"
}
```

### Unix Socket 调用示例

使用 JSON-RPC 2.0 协议：

```bash
# 使用 nc (netcat)
echo '{"jsonrpc":"2.0","method":"balance","params":{"address":"0x...","chain_id":8453},"id":1,"meta":{"authorization":"Bearer clwt_xxx"}}' | nc -U /run/clawlet/clawlet.sock
```

Node.js 示例：
```javascript
const net = require('net');

const socket = net.createConnection('/run/clawlet/clawlet.sock');

socket.write(JSON.stringify({
  jsonrpc: '2.0',
  method: 'balance',
  params: { address: '0x...', chain_id: 8453 },
  id: 1,
  meta: { authorization: 'Bearer clwt_xxx' }
}));

socket.on('data', (data) => {
  console.log(JSON.parse(data.toString()));
});
```

---

## 策略配置

### policy.yaml

```yaml
# 每日转账限额（美元）
daily_transfer_limit_usd: 1000.0

# 单笔转账限额（美元）
per_tx_limit_usd: 100.0

# 需要人工审批的金额阈值
require_approval_above_usd: 500.0

# 允许的 token（空 = 允许全部）
allowed_tokens:
  - ETH
  - USDC
  - USDT

# 允许的链（空 = 允许全部）
allowed_chains:
  - 1       # Ethereum
  - 8453    # Base
  - 10      # Optimism
  - 42161   # Arbitrum
```

### 策略检查顺序

1. **单笔限额** — 超过 `per_tx_limit_usd` 立即拒绝
2. **Token 白名单** — 不在 `allowed_tokens` 立即拒绝
3. **链白名单** — 不在 `allowed_chains` 立即拒绝
4. **每日累计** — 超过 `daily_transfer_limit_usd` 拒绝
5. **审批阈值** — 超过 `require_approval_above_usd` 返回需审批

---

## 审计日志

所有操作记录在 `~/.clawlet/audit.jsonl`（append-only JSONL 格式）：

```json
{"timestamp":"2026-02-04T10:30:00Z","event_type":"transfer","details":{"to":"0x...","amount":"0.1","token":"ETH","chain_id":8453},"outcome":"success"}
{"timestamp":"2026-02-04T10:31:00Z","event_type":"transfer","details":{"to":"0x...","amount":"200","token":"USDC","chain_id":8453},"outcome":"denied","reason":"exceeds per_tx_limit"}
```

---

## 常见问题

### Q: 忘记 keystore 密码怎么办？

无法恢复密码。如果有助记词备份，可以重新初始化：
```bash
rm -rf ~/.clawlet/keystore
clawlet init --from-mnemonic
```

### Q: 如何添加更多地址？

目前只支持单地址。多地址支持计划在 M4 实现。

### Q: 支持哪些链？

任何 EVM 兼容链。在 `config.yaml` 的 `chain_rpc_urls` 中添加 RPC 节点即可。

### Q: 如何查看审计日志？

```bash
# 查看最近 10 条
tail -10 ~/.clawlet/audit.jsonl | jq

# 搜索转账记录
grep '"event_type":"transfer"' ~/.clawlet/audit.jsonl | jq
```

### Q: 转账失败但没有错误信息？

检查：
1. Token 是否有授权（`CLAWLET_LOG=debug clawlet serve`）
2. 是否超出策略限额
3. RPC 节点是否可达

---

## 下一步

- [部署指南](./deployment.md) — 生产环境部署与安全加固
- [设计文档](../design.md) — 架构与路线图
- [API 参考](./api-reference.md) — 完整 API 文档（计划中）

---

*最后更新: 2026-02-06*
