# Clawlet macOS Deployment Guide

## 1. 为什么隔离用户模式不适用于 macOS

Linux 部署方案（见 [deployment.md](deployment.md)）使用独立的 `clawlet` 系统用户实现密钥隔离。但在 macOS 上，这条路走不通：

| 问题 | 原因 |
|------|------|
| Daemon 无法交互输入密码 | 系统用户没有 TTY，`rpassword::read_password()` 失败 |
| Keychain 不可用 | 系统用户没有 login session，没有 login keychain |
| Secure Enclave 不可用 | Secure Enclave 密钥通过 Keychain 存储引用，同样依赖 login keychain |
| 自动重启死循环 | 以上三点导致 daemon 启动必然失败，launchd `KeepAlive` 触发反复重启 |

**结论：macOS 上不使用隔离用户模式，改为当前用户 + Secure Enclave 硬件保护。**

## 2. macOS 推荐架构

```
┌─────────────────────────────────────────────────────────┐
│  macOS (当前登录用户)                                      │
│                                                          │
│  ┌──────────────┐      HTTP (127.0.0.1:9100)            │
│  │  AI Agent     │ ──────────────────────────────►       │
│  │  (同用户进程)  │      Bearer token auth               │
│  └──────────────┘                                        │
│         ╳ Keychain Access Group 阻止直接访问 KEK           │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  clawlet (LaunchAgent, 同用户)                    │    │
│  │                                                   │    │
│  │  ┌───────────┐    ┌──────────────────────────┐   │    │
│  │  │ RPC Server │    │ Secure Enclave            │   │    │
│  │  │ (policy +  │◄──►│ ┌──────────────────────┐ │   │    │
│  │  │  audit)    │    │ │ KEK (不可导出)         │ │   │    │
│  │  └───────────┘    │ │ 硬件绑定, 签名限定访问  │ │   │    │
│  │       │            │ └──────────────────────┘ │   │    │
│  │  ┌────▼──────┐    └──────────────────────────┘   │    │
│  │  │ ~/.clawlet │                                   │    │
│  │  │ ├── keystore/ (KEK 加密的密文)                 │    │
│  │  │ ├── config.yaml                               │    │
│  │  │ ├── policy.yaml                               │    │
│  │  │ └── audit.jsonl                               │    │
│  │  └───────────┘                                   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### 安全模型对比

| 维度 | Linux (隔离用户) | macOS (Secure Enclave) |
|------|-------------------|------------------------|
| 密钥保护 | 文件权限 (OS user isolation) | 硬件 KEK (Secure Enclave) |
| 进程隔离 | 不同 OS 用户 | Code Signing + Keychain Access Group |
| Daemon 管理 | systemd (LaunchDaemon) | launchd LaunchAgent |
| 运行用户 | 专用 `clawlet` 用户 | 当前登录用户 |
| 密码需求 | 软件加密需要密码 | 硬件模式无需密码 |
| 自动重启 | systemd `Restart=on-failure` | launchd `KeepAlive` |
| 磁盘被盗 | 密文可被离线暴力破解 | KEK 绑定硬件芯片，无法解密 |

## 3. 安全层次

### 3.1 Secure Enclave 硬件保护

`clawlet init --hardware` 时在 Secure Enclave 中生成 KEK（Key Encryption Key），用于加密/解密钱包私钥。

- KEK **永远不会离开** Secure Enclave 芯片
- 加解密操作在芯片内部完成
- 磁盘上只有 KEK 加密后的密文，无密码也无法离线解密
- Daemon 重启时自动通过 Secure Enclave 解密，无需交互

### 3.2 Code Signing + Keychain Access Group

**问题**：同用户的其他进程（如 AI Agent）也可以调用 Keychain API 访问 Secure Enclave 中的 KEK。

**解决方案**：通过 code signing identity 限制 Keychain 条目的访问权限。

```
Keychain Item (KEK 引用)
├── kSecAttrAccessGroup: "com.openclaw.clawlet"
├── kSecAttrAccessibleWhenUnlockedThisDeviceOnly
└── 只有 code signing identity 匹配的二进制能访问
```

| 攻击场景 | 无 Access Group | 有 Access Group |
|----------|-----------------|-----------------|
| 同用户恶意进程调用 Keychain API | 能访问 KEK | **被拒绝** |
| 磁盘被盗离线攻击 | 无法解密 (硬件绑定) | 无法解密 |
| 其他用户进程 | 被 Keychain 拒绝 | 被 Keychain 拒绝 |
| 未签名/伪造签名的 clawlet | 能访问 KEK | **被拒绝** |

> **注意**：Keychain Access Group 要求二进制必须经过 code signing。开发阶段可先不启用，正式发布时必须配置。

### 3.3 Touch ID 生物认证（高权限操作）

通过 macOS `LocalAuthentication.framework` 对高权限操作要求 Touch ID 验证。

**设计原则**：日常操作不需要生物认证（保证 daemon 可自动重启），仅在高权限操作时触发。

| 操作 | 认证方式 | 原因 |
|------|---------|------|
| 启动 daemon / 自动重启 | 无需认证（Secure Enclave 自动解密） | 保证可用性 |
| 读取余额、小额转账 | Bearer token | 日常操作 |
| `auth grant` 授权 token | **Touch ID** | 高权限 |
| `auth revoke` / `revoke_all` | **Touch ID** | 高权限 |
| 超过 `require_approval_above_usd` 的转账 | **Touch ID** | 大额交易 |
| 修改 policy 配置 | **Touch ID** | 安全关键配置 |

**触发流程**：

```
Agent 发起大额转账 / 管理员执行 auth grant
  │
  ▼
RPC Server 判断: 是否需要生物认证?
  │
  ├─ 否 (日常操作) → 正常执行
  │
  └─ 是 (高权限)  → 调用 LAContext.evaluatePolicy()
                      │
                      ▼
                   macOS 弹出 Touch ID 对话框
                      │
                      ├─ 验证通过 → 执行操作
                      └─ 验证失败/超时 → 拒绝，返回错误
```

**实现说明**：

- 在应用层（RPC handler）调用 `LocalAuthentication.framework`，不改变 Secure Enclave 密钥的访问控制
- macOS LaunchAgent 后台进程可以触发 Touch ID 弹窗（用户已登录即可）
- 通过 FFI 调用，与现有 Security.framework 调用方式一致
- 无 Touch ID 的 Mac（如远程服务器）回退到 admin 密码验证

```rust
// 伪代码示意
fn require_biometric(reason: &str) -> Result<(), AuthError> {
    // LAContext *ctx = [[LAContext alloc] init];
    // [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
    //     localizedReason:reason
    //               reply:^(BOOL success, NSError *error) { ... }];
    //
    // 如果设备不支持生物认证，回退到:
    // LAPolicyDeviceOwnerAuthentication (系统密码)
}
```

### 3.4 RPC 层 Policy 约束

即使进程能够与 clawlet 通信，所有操作仍受 policy 约束：

- 每日转账限额 (`daily_transfer_limit_usd`)
- 单笔限额 (`per_tx_limit_usd`)
- 代币/链白名单 (`allowed_tokens`, `allowed_chains`)
- 高额审批 (`require_approval_above_usd`)
- Bearer token 认证 + 审计日志

### 3.5 安全模型总览

```
┌─────────────────────────────┐
│   Touch ID 生物认证          │  ← 高权限操作门控
├─────────────────────────────┤
│   Policy 限额 + 审计日志     │  ← 日常操作约束
├─────────────────────────────┤
│   Bearer Token 认证          │  ← 身份验证
├─────────────────────────────┤
│   Secure Enclave 硬件保护    │  ← 密钥保护
├─────────────────────────────┤
│   Code Signing 签名限定      │  ← 进程隔离
└─────────────────────────────┘
```

五层防御，各层独立，互不依赖。即使某一层被突破，其他层仍然有效。

## 4. 安装与部署

### 4.1 安装二进制

```bash
# 源码编译
cargo build --release -p clawlet-cli
cp target/release/clawlet /usr/local/bin/clawlet

# 或通过安装脚本（普通模式，不使用 --isolated）
./scripts/install.sh
```

### 4.2 初始化（硬件模式）

```bash
clawlet init --hardware
```

这将：
- 在 Secure Enclave 中生成 KEK
- 生成助记词并用 KEK 加密存储
- 创建 V2 keystore 文件
- 设置 admin 密码（仅用于 RPC 认证，不用于密钥解密）

### 4.3 安装 LaunchAgent

创建 `~/Library/LaunchAgents/com.openclaw.clawlet.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.clawlet</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/clawlet</string>
        <string>serve</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/tmp/clawlet.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/clawlet.stderr.log</string>

    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
```

> **注意**：使用 `LaunchAgent`（用户级），不是 `LaunchDaemon`（系统级）。LaunchAgent 在用户登录后运行，login keychain 已解锁，Secure Enclave 可正常访问。

### 4.4 加载服务

```bash
launchctl load ~/Library/LaunchAgents/com.openclaw.clawlet.plist
```

验证运行状态：

```bash
launchctl list | grep clawlet
curl -s http://127.0.0.1:9100/health
```

查看日志：

```bash
tail -f /tmp/clawlet.stderr.log
```

## 5. 打包分发

### 方案 A：`.pkg` 安装包（推荐）

适合命令行用户和自动化部署。

```bash
# 构建 payload
mkdir -p pkg-root/usr/local/bin
cp target/release/clawlet pkg-root/usr/local/bin/

# 打包（postinstall 脚本负责创建 LaunchAgent plist）
pkgbuild \
    --root pkg-root \
    --scripts scripts/pkg/ \
    --identifier com.openclaw.clawlet \
    --version 0.1.0 \
    --install-location / \
    clawlet-0.1.0.pkg

# 可选：用 productbuild 包装为带 GUI 向导的安装包
productbuild \
    --package clawlet-0.1.0.pkg \
    --product scripts/pkg/requirements.plist \
    clawlet-0.1.0-installer.pkg
```

`postinstall` 脚本内容示例：

```bash
#!/bin/bash
# 为当前用户安装 LaunchAgent plist
PLIST_DIR="$HOME/Library/LaunchAgents"
mkdir -p "$PLIST_DIR"
cp /usr/local/share/clawlet/com.openclaw.clawlet.plist "$PLIST_DIR/"
# 不在 postinstall 中 launchctl load，让用户 init 后自行启动
```

### 方案 B：`.app` Bundle + Privileged Helper

适合需要 GUI 管理界面的场景。

```
Clawlet.app/
├── Contents/
│   ├── MacOS/
│   │   └── Clawlet              # GUI 前端 (SwiftUI/AppKit)
│   ├── Library/
│   │   └── LaunchServices/
│   │       └── com.openclaw.clawlet.helper  # daemon 二进制
│   ├── Resources/
│   │   └── ...
│   └── Info.plist
```

- GUI 前端：状态查看、policy 编辑、日志查看
- Daemon：通过 `SMAppService` (macOS 13+) 注册为 LaunchAgent
- 两者通过 XPC 或本地 HTTP 通信

> 如果不需要 GUI 管理界面，方案 A 足够。方案 B 适合面向非技术用户的产品化阶段。

## 6. Token 管理交互（TUI）

CLI 子命令（`clawlet auth grant --agent ... --scope ... --expires ...`）参数多、不直观。macOS 部署推荐使用 TUI 交互模式简化操作。

**进入方式**：不带子命令直接运行 `clawlet auth`，带子命令时保持原有行为（脚本兼容）。

```
$ clawlet auth

🔐 Enter admin password: ********

? What would you like to do?
❯ Grant new token
  List sessions
  Revoke session
  Revoke all sessions
  Back

? Agent identifier: owliabot
? Permission scope:
❯ trade
  read
  admin
? Expiry: 7d

  [Touch ID 验证弹窗]

✅ Token granted to: owliabot
   Token: clw_a8f3...
   Scope: trade
   Expires: 2026-02-17
```

撤回操作直接从活跃 session 列表中选择，无需手动输入 agent 名：

```
? Select session to revoke:
❯ owliabot  [trade]  expires 2026-02-17  (42 requests)
  scanner   [read]   expires 2026-03-12  (7 requests)
  Cancel

  [Touch ID 验证弹窗]

✅ Session revoked for agent: owliabot
```

**实现方案**：使用 `dialoguer` 或 `inquire` crate 提供交互式 prompt（选择菜单、文本输入、确认），无需 `ratatui` 等全屏 TUI 框架。

## 7. Daemon 自动重启流程

```
用户登录
  │
  ▼
launchd 加载 LaunchAgent
  │
  ▼
启动 clawlet serve
  │
  ▼
检测 V2 keystore (硬件模式)
  │
  ▼
通过 Keychain API 访问 Secure Enclave KEK
  │  (login keychain 已解锁，无需密码)
  ▼
KEK 解密私钥到内存
  │
  ▼
RPC Server 就绪 (127.0.0.1:9100)
  │
  ▼
[如果崩溃] ──► launchd KeepAlive 自动重启 ──► 回到 "启动 clawlet serve"
```

整个流程**无需任何人工交互**，密码仅在 `clawlet init --hardware` 时设置一次（admin 密码），之后密钥解密完全由硬件完成。

## 8. 安全清单

### 硬件保护

- [ ] 使用 `clawlet init --hardware` 初始化（Secure Enclave 模式）
- [ ] 确认 keystore 文件为 V2 格式（`"version": 2, "protection": "hardware"`）
- [ ] 助记词已离线备份到安全位置

### Code Signing（正式发布时）

- [ ] 二进制使用 Apple Developer ID 签名
- [ ] 配置 Keychain Access Group (`com.openclaw.clawlet`)
- [ ] 通过 Apple 公证 (notarization)
- [ ] 验证未签名进程无法访问 KEK

### 网络

- [ ] RPC 绑定 `127.0.0.1`（不是 `0.0.0.0`）
- [ ] 防火墙阻止外部访问 9100 端口

### Touch ID

- [ ] 高权限操作已配置 Touch ID 门控（auth grant/revoke、大额转账、policy 修改）
- [ ] 无 Touch ID 设备已验证回退到系统密码认证
- [ ] Touch ID 超时/失败时正确返回错误（不默认放行）

### 认证与审计

- [ ] Bearer token 已配置且足够随机（>= 32 bytes）
- [ ] Admin 密码强度足够
- [ ] 审计日志已启用并定期检查
- [ ] Policy 限额设置合理

### 备份

- [ ] 助记词离线安全存储
- [ ] 恢复流程已文档化并测试过
