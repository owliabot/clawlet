# Clawlet 安全边界分析

## 1. 部署模型

采用 **UID 隔离 + 手动启动** 模式，macOS 和 Linux 通用。

- 创建专用 `clawlet` 系统用户
- 所有数据文件归 `clawlet` 用户所有，权限 `600`
- 当前用户通过 `sudo -u clawlet clawlet serve` 启动 daemon
- daemon 交互式读取密码后 fork 到后台运行
- 不依赖自动重启、开机启动

```
$ sudo -u clawlet clawlet serve
Enter keystore password: ********
Daemon started (PID: 12345)
$
```

### 架构总览

```
┌──────────────────────────────────────────────────────┐
│  Host Machine                                         │
│                                                       │
│  当前用户 (如 johnz)                                   │
│  ┌──────────────┐                                     │
│  │  AI Agent     │──── HTTP 127.0.0.1:9100 ───┐      │
│  │  Bearer Token │                              │      │
│  └──────────────┘                              │      │
│  ┌──────────────┐                              │      │
│  │  其他进程     │──── 无 Token, 被拒 ────╳    │      │
│  └──────────────┘                              │      │
│                                                │      │
│  clawlet 用户 (UID 隔离)                       ▼      │
│  ┌─────────────────────────────────────────────────┐ │
│  │  clawlet daemon (后台进程)                       │ │
│  │                                                   │ │
│  │  密钥: 进程内存 (scrypt 解密后加载)               │ │
│  │  认证: Bearer Token + Admin 密码                  │ │
│  │  限制: Policy Engine                              │ │
│  │                                                   │ │
│  │  ~/.clawlet/          全部 600, owner=clawlet     │ │
│  │  ├── keystore/*.json  scrypt 加密的私钥密文       │ │
│  │  ├── policy.yaml      转账限额策略                │ │
│  │  ├── spending.json    日限额累计                   │ │
│  │  ├── config.yaml      配置                        │ │
│  │  ├── sessions.json    token hash                  │ │
│  │  └── audit.jsonl      审计日志                    │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

### 文件权限

```
~clawlet/.clawlet/           drwx------  clawlet:clawlet  (700)
├── keystore/                drwx------  clawlet:clawlet  (700)
│   └── <uuid>.json          -rw-------  clawlet:clawlet  (600)
├── policy.yaml              -rw-------  clawlet:clawlet  (600)
├── spending.json            -rw-------  clawlet:clawlet  (600)
├── config.yaml              -rw-------  clawlet:clawlet  (600)
├── sessions.json            -rw-------  clawlet:clawlet  (600)
└── audit.jsonl              -rw-------  clawlet:clawlet  (600)
```

非 clawlet 用户（包括当前用户和 AI Agent）在非 sudo 模式下**无法读写任何文件**。

### 启动流程

```
当前用户终端
  │
  │  sudo -u clawlet clawlet serve
  │
  ▼
clawlet 进程 (前台, UID=clawlet)
  │  继承当前终端 TTY
  │  rpassword::read_password() → 读取密码
  │  Keystore::unlock() → scrypt 解密 → 私钥加载到内存
  │  密码 zeroize 清零
  │
  ▼
fork() + setsid()
  ├── 父进程: 打印 PID, 退出 → 终端释放给用户
  └── 子进程: 脱离终端, 启动 tokio runtime + RPC Server
       │
       ▼
     127.0.0.1:9100 就绪
```

fork 发生在 tokio runtime 启动之前（单线程阶段），macOS 和 Linux 均安全。

## 2. 威胁模型

### 2.1 被保护的资产

| 资产 | 机密性 | 完整性 | 存储位置 |
|------|:------:|:------:|----------|
| secp256k1 私钥 | 极高 | 高 | keystore 密文(磁盘) + 明文(进程内存) |
| 助记词 | 极高 | 高 | 仅 init 时显示, 不落盘 |
| Admin 密码 | 高 | 高 | 仅人脑 + 进程内存(启动时短暂存在) |
| Bearer Token | 中 | 中 | sessions.json (hash) + Agent 侧(明文) |
| Policy 配置 | 中 | 高 | policy.yaml |
| 审计日志 | 低 | 高 | audit.jsonl |

### 2.2 攻击者画像

| 攻击者 | 能力 | 典型场景 |
|--------|------|----------|
| **A1**: 被入侵的 AI Agent | 当前用户进程, 持有 trade scope Bearer Token | prompt injection, Agent 框架漏洞 |
| **A2**: 同用户恶意软件 | 当前用户进程, 无 Bearer Token | npm/pip 供应链攻击, 浏览器漏洞 |
| **A3**: 物理攻击者 | 拿到磁盘或解锁的设备 | 设备被盗, 物理接触 |
| **A4**: root 攻击者 | 完整系统控制 | 特权提升漏洞 (**超出防御范围**) |
| **A5**: 远程网络攻击者 | 能发送网络请求 | SSRF, 同网段扫描 |

## 3. 攻击面分析

本部署模型只有**一个外部入口**: TCP 127.0.0.1:9100 (JSON-RPC over HTTP)。

| 入口 | 可达性 | 防御 |
|------|--------|------|
| RPC 端口 (TCP 9100) | 任何本地进程 | Bearer Token + Admin 密码 + Policy |
| 文件系统 | 仅 clawlet UID | chmod 600 (内核强制) |
| 进程内存 | 仅同 UID 或 root | UID 隔离 (不同用户无法 attach) |

对比其他模式的攻击面:

| 入口 | 隔离用户模式 (本方案) | 同用户模式 |
|------|:--:|:--:|
| RPC 端口 | 开放 (靠 Token 防御) | 开放 (靠 Token 防御) |
| 文件系统 | **关闭** (UID 隔离) | 开放 (同用户可读写) |
| Keychain API | **不使用** | 开放 (同用户可调用) |
| 进程内存 | **关闭** (不同 UID) | 需要 Hardened Runtime |

## 4. 逐攻击者安全边界

### 4.1 A1: 被入侵的 AI Agent

Agent 以当前用户身份运行, 持有 trade scope Bearer Token, 通过 RPC 与 daemon 交互。

| 攻击 | 路径 | 结果 |
|------|------|------|
| 小额转账 | RPC `transfer` → Policy `check_transfer()` | 受 `per_tx_limit_usd` 约束 |
| 高频转账 | 多次 `transfer` | 受 `daily_transfer_limit_usd` 约束 |
| 大额转账 | `transfer` 超过审批阈值 | `RequiresApproval` 拒绝 |
| grant 新 token | RPC `auth.grant` | 需要 admin 密码 → Agent 不知道 → **拒绝** |
| 提升 scope | RPC `auth.grant` scope=admin | 同上 → **拒绝** |
| 篡改 policy | 直接改文件 | UID 不同 → **permission denied** |
| 重置日限额 | 改 spending.json | UID 不同 → **permission denied** |
| 删除审计日志 | 改 audit.jsonl | UID 不同 → **permission denied** |

**最大损失**: `min(per_tx_limit_usd, daily_transfer_limit_usd)`，完全由 policy 配置决定。

**不可提权**: admin 密码是唯一的提权凭据, Agent 没有获取途径。

### 4.2 A2: 同用户恶意软件

以当前用户身份运行的恶意进程, 没有 Bearer Token。

| 攻击 | 路径 | 结果 |
|------|------|------|
| 连接 RPC | TCP 127.0.0.1:9100 | 连接成功, 但无 Token → 所有操作 **拒绝** |
| 暴力猜 Token | 遍历 token 空间 | 32 bytes = 2^256 → **不可行** |
| 读 keystore 密文 | `cat ~clawlet/.clawlet/keystore/*.json` | **permission denied** |
| 读 policy | `cat ~clawlet/.clawlet/policy.yaml` | **permission denied** |
| 篡改 policy | 写 policy.yaml | **permission denied** |
| 篡改 spending | 写 spending.json | **permission denied** |
| 篡改 audit | 写 audit.jsonl | **permission denied** |
| 读进程内存 | `task_for_pid()` / `ptrace()` | 不同 UID → **拒绝** |
| 注入动态库 | `DYLD_INSERT_LIBRARIES` | 不同 UID 进程 → **无效** |
| sudo 读文件 | `sudo -u clawlet cat ...` | 需要当前用户密码 + TTY → A2 **做不到** |
| 盗取 Agent token | 读 Agent 的 token 文件 | 同用户 → **可读** ⚠️ → 受 Policy 约束 |

**结论**: A2 的唯一可行路径是盗取 Agent 侧存储的 token, 但损失上限 = `daily_transfer_limit_usd`。clawlet 侧的所有文件完全不可触碰。

### 4.3 A3: 物理攻击者

| 场景 | 攻击路径 | 结果 |
|------|----------|------|
| FileVault ON | 磁盘加密 | **不可读** |
| FileVault OFF | 读 keystore 密文 → 离线暴力破解 scrypt | 取决于密码强度 |
| 设备解锁状态 | 打开终端 → 需要知道 admin 密码才能操作 | 受密码保护 |

scrypt 暴力破解成本参考 (N=8192, r=8, p=1):

| 密码强度 | GPU (RTX 4090) | 可行性 |
|----------|----------------|--------|
| 8 位小写字母 | ~2 天 | 可行 ⚠️ |
| 12 位混合 | ~300 年 | 不可行 |
| 16 位随机 | ~10^15 年 | 不可行 |

### 4.4 A5: 远程网络攻击者

RPC 绑定 `127.0.0.1`, 远程不可达。**完全阻止。**

## 5. 安全边界总览

```
══════════════════════════════════════════════════════
  不可防御区域 (超出安全边界)

  • root 权限攻击 (A4)
  • 内核漏洞
  • 用户主动禁用安全机制
══════════════════════════════════════════════════════
        ▲ 安全天花板
        │
  ┌─────┴────────────────────────────────────────┐
  │  Policy 限额 (per_tx + daily)                 │ ← A1 损失硬上限
  ├──────────────────────────────────────────────┤
  │  Bearer Token (32 bytes, SHA-256)            │ ← A2 无 token 被完全拒绝
  ├──────────────────────────────────────────────┤
  │  Admin 密码 (scrypt 验证 + 锁定)             │ ← A1 不可提权
  ├──────────────────────────────────────────────┤
  │  UID 隔离 + chmod 600                        │ ← A2 文件/内存完全不可访问
  ├──────────────────────────────────────────────┤
  │  scrypt 加密 (N=8192, AES-256-GCM)          │ ← A3 离线暴力破解成本
  ├──────────────────────────────────────────────┤
  │  127.0.0.1 绑定                              │ ← A5 完全阻止
  └──────────────────────────────────────────────┘
        │
        ▼ 安全地板
══════════════════════════════════════════════════════
  已消除的威胁

  • A2 读写 clawlet 文件 (UID 隔离)
  • A2 篡改 policy / audit / spending (UID 隔离)
  • A2 读取进程内存 (不同 UID)
  • A1 无限转账 (Policy 限额)
  • A1 自行提权 (Admin 密码)
  • A5 远程访问 (localhost 绑定)
══════════════════════════════════════════════════════
```

## 6. 残余风险

| # | 风险 | 严重度 | 触发条件 | 缓解措施 |
|---|------|:------:|----------|----------|
| R1 | Agent token 被 A2 盗取后用于转账 | 中 | A2 能读 Agent 的 token 文件 | Agent 将 token 存为 chmod 600 文件, 不用环境变量 |
| R2 | 弱密码 + 磁盘被盗 + 无 FileVault | 中 | 三个条件同时满足 | `clawlet init` 强制密码 >= 16 位; 检测 FileVault 状态 |
| R3 | daemon 崩溃后停机 | 低 | 进程异常退出 | 停机 = 安全; 监控脚本告警即可 |
| R4 | clawlet 进程被 exploit | 极低 | RPC 解析漏洞 | Rust 内存安全; 攻击面仅 JSON-RPC |

## 7. 此模型不提供的能力

以下能力在本模型中**有意不包含**, 属于未来升级方向:

| 能力 | 本模型 | 未来 (Developer ID) |
|------|:------:|:-------------------:|
| 自动重启 / 开机启动 | 不支持 | Secure Enclave + LaunchAgent |
| Touch ID 物理确认 | 不支持 | LocalAuthentication.framework |
| 硬件级密钥保护 | 不支持 (靠 scrypt) | Secure Enclave KEK |
| 物理盗窃完全防护 | 靠 FileVault + 密码强度 | Secure Enclave (硬件绑定) |
| Keychain Access Group | 不需要 (UID 隔离替代) | Code Signing + Access Group |

从本模型迁移到 Secure Enclave 模型需要切换到当前用户 + LaunchAgent 架构, 并运行 `clawlet migrate --hardware` 迁移 keystore。

## 8. 部署步骤

### macOS

```bash
# 1. 创建系统用户
sudo dscl . -create /Users/clawlet
sudo dscl . -create /Users/clawlet UserShell /usr/bin/false
sudo dscl . -create /Users/clawlet UniqueID 399
sudo dscl . -create /Users/clawlet PrimaryGroupID 399
sudo dscl . -create /Users/clawlet NFSHomeDirectory /var/clawlet
sudo mkdir -p /var/clawlet
sudo chown clawlet:clawlet /var/clawlet

# 2. 安装
cargo build --release -p clawlet-cli
sudo cp target/release/clawlet /usr/local/bin/clawlet
sudo chmod 755 /usr/local/bin/clawlet

# 3. 初始化 (会提示设置密码, 备份助记词)
sudo -u clawlet clawlet init

# 4. 配置
sudo -u clawlet nano /var/clawlet/.clawlet/config.yaml

# 5. 启动 (输入密码后 daemon 进入后台)
sudo -u clawlet clawlet serve
```

### Linux

```bash
# 1. 创建系统用户
sudo useradd --system --create-home --shell /usr/sbin/nologin clawlet

# 2. 安装
cargo build --release -p clawlet-cli
sudo cp target/release/clawlet /usr/local/bin/clawlet
sudo chmod 755 /usr/local/bin/clawlet

# 3. 初始化
sudo -u clawlet clawlet init

# 4. 配置
sudo -u clawlet nano ~clawlet/.clawlet/config.yaml

# 5. 启动
sudo -u clawlet clawlet serve
```

### 进程管理

```bash
# 查看状态
ps aux | grep clawlet

# 停止
sudo -u clawlet kill $(cat ~clawlet/.clawlet/clawlet.pid)

# 查看日志
sudo -u clawlet tail -f ~clawlet/.clawlet/clawlet.log

# 查看审计
sudo -u clawlet tail -f ~clawlet/.clawlet/audit.jsonl
```

## 9. 安全清单

### 用户隔离

- [ ] 创建了 `clawlet` 系统用户 (shell = `/usr/bin/false` 或 `/usr/sbin/nologin`)
- [ ] `~clawlet/.clawlet/` 目录权限 `700`, owner = `clawlet`
- [ ] 所有数据文件权限 `600`, owner = `clawlet`
- [ ] 验证当前用户无法直接读取: `cat ~clawlet/.clawlet/policy.yaml` → permission denied

### 密码强度

- [ ] keystore 密码 >= 16 位随机字符
- [ ] 密码不保存在任何文件、环境变量、Keychain 中

### 网络

- [ ] RPC 绑定 `127.0.0.1` (不是 `0.0.0.0`)
- [ ] 防火墙阻止外部访问 9100 端口

### Policy

- [ ] `daily_transfer_limit_usd` 设置为可接受的最大日损失
- [ ] `per_tx_limit_usd` 设置为合理的单笔限额
- [ ] `allowed_tokens` 和 `allowed_chains` 按需配置白名单
- [ ] `require_approval_above_usd` 已设置

### Token 管理

- [ ] Agent 的 Bearer Token 存储在 `chmod 600` 文件中
- [ ] Token 不通过环境变量传递 (防止 `ps` 泄露)
- [ ] Token scope 遵循最小权限原则 (能用 `read` 不用 `trade`)

### 磁盘加密

- [ ] macOS: FileVault 已启用 (`fdesetup status`)
- [ ] Linux: LUKS 全盘加密已启用

### 备份

- [ ] 助记词已离线安全存储
- [ ] 恢复流程已测试
