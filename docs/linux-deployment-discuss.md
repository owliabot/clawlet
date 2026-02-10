# Clawlet Linux Deployment Guide

## 1. 架构概览

Linux 部署使用 **OS 用户隔离 + 纵深防御** 模型：

```
┌──────────────────────────────────────────────────────────────┐
│  Linux Host                                                   │
│                                                               │
│  ┌──────────────┐                                            │
│  │  Agent 用户   │    Unix Socket / TCP 127.0.0.1:9100       │
│  │  (如 ocbot)   │ ────────────────────────────────────►     │
│  │  不能读密钥   │    Bearer token auth                      │
│  └──────────────┘                                            │
│         ╳ 文件权限 + MAC 阻止直接访问                          │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  clawlet 用户 (systemd service)                        │   │
│  │                                                        │   │
│  │  ┌───────────┐    ┌────────────────────────────────┐  │   │
│  │  │ RPC Server │    │ TPM 2.0 (如果有)                │  │   │
│  │  │ (policy +  │◄──►│ ┌────────────────────────────┐ │  │   │
│  │  │  audit)    │    │ │ KEK (sealed to PCR)        │ │  │   │
│  │  └───────────┘    │ │ 硬件绑定, 开机后自动解封    │ │  │   │
│  │       │            │ └────────────────────────────┘ │  │   │
│  │  ┌────▼──────┐    └────────────────────────────────┘  │   │
│  │  │ ~/.clawlet │                                        │   │
│  │  │ ├── keystore/ (加密的密钥文件)                      │   │
│  │  │ ├── config.yaml                                    │   │
│  │  │ ├── policy.yaml                                    │   │
│  │  │ └── audit.jsonl                                    │   │
│  │  └───────────┘                                        │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  内核安全层                                             │   │
│  │  SELinux / AppArmor + seccomp-bpf + systemd 沙箱       │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### macOS 方案对比

| 维度 | macOS | Linux |
|------|-------|-------|
| 密钥保护 | Secure Enclave | TPM 2.0 (或软件加密) |
| 用户隔离 | 不使用（同用户 + Code Signing） | **专用 clawlet 系统用户** |
| 进程隔离 | Code Signing + Keychain Access Group | SELinux / AppArmor |
| 高权限审批 | Touch ID | admin 密码 |
| Daemon 管理 | launchd LaunchAgent | systemd |
| 无人值守重启 | Secure Enclave 自动解密 | TPM unseal 自动解密 |

## 2. 安全层次

```
┌─────────────────────────────────────┐
│  Policy 限额 + 审计日志              │  ← 业务约束
├─────────────────────────────────────┤
│  Bearer Token 认证                   │  ← 身份验证
├─────────────────────────────────────┤
│  OS User Isolation                   │  ← 文件级隔离
├─────────────────────────────────────┤
│  SELinux / AppArmor                  │  ← 强制访问控制
├─────────────────────────────────────┤
│  systemd 沙箱 + seccomp             │  ← 系统调用限制
├─────────────────────────────────────┤
│  TPM 2.0 硬件保护 (可选)             │  ← 密钥保护
└─────────────────────────────────────┘
```

### 2.1 OS User Isolation

| 用户 | 角色 | 权限 |
|------|------|------|
| `clawlet` | 系统用户，拥有 keystore，运行 RPC server | 完整访问 `~/.clawlet/` |
| agent 用户（如 `ocbot`） | AI agent 进程 | 仅通过 RPC 接口访问，不能读 keystore 文件 |

### 2.2 TPM 2.0 硬件保护（可选）

有 TPM 时，密钥加密方式从「密码派生 KEK」升级为「TPM sealed KEK」：

| 对比 | 软件模式（无 TPM） | 硬件模式（有 TPM） |
|------|-------------------|-------------------|
| KEK 来源 | 密码经 Argon2 派生 | TPM 芯片内生成 |
| 启动需要 | 交互输入密码 | 自动（TPM unseal） |
| 磁盘被盗 | 可离线暴力破解密码 | 无法解密（硬件绑定） |
| 自动重启 | 不支持（无人输密码） | **支持** |
| 可用性 | 所有环境 | 需要 TPM 2.0 硬件或 vTPM |

**检查 TPM 是否可用**：

```bash
# 检查设备节点
ls /dev/tpm*

# 检查 TPM 版本
tpm2_getcap properties-fixed 2>/dev/null | head -5

# 云环境检查 vTPM
# AWS: Nitro 实例默认有 vTPM
# GCP: 创建 VM 时启用 vTPM
# Azure: 可信启动 VM 默认有 vTPM
```

### 2.3 systemd 安全沙箱

通过 systemd unit 配置限制 clawlet 进程的能力：

| 配置项 | 作用 |
|--------|------|
| `NoNewPrivileges=true` | 禁止提权 |
| `ProtectSystem=strict` | 根文件系统只读 |
| `ProtectHome=read-only` | 其他用户 home 只读 |
| `ReadWritePaths=~/.clawlet` | 仅允许写自己的数据目录 |
| `PrivateTmp=true` | 独立 /tmp |
| `MemoryDenyWriteExecute=true` | 禁止 W^X（防 shellcode） |
| `SystemCallFilter=@system-service` | 只允许基本系统调用 |
| `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` | 只保留绑定端口能力 |
| `RestrictAddressFamilies=AF_INET AF_UNIX` | 只允许 IPv4 和 Unix socket |
| `RestrictNamespaces=true` | 禁止创建新 namespace |
| `IPAddressAllow=127.0.0.1` | 只允许 localhost 网络 |

### 2.4 SELinux / AppArmor

在 OS 用户隔离之上，MAC 进一步限制被攻破的 clawlet 进程能做什么：

| 攻击场景 | 无 MAC | 有 MAC |
|----------|--------|--------|
| 执行 `curl` 外传密钥 | 能（同用户权限） | **被拒绝**（deny exec） |
| 反弹 shell | 能 | **被拒绝**（deny exec + 网络限制） |
| 写入 keystore 目录外的文件 | 能（同用户可写位置） | **被拒绝** |
| 开新的监听端口 | 能 | **被拒绝**（只允许 9100） |

> 选择哪个取决于发行版：RHEL/CentOS → SELinux，Ubuntu/Debian → AppArmor。

## 3. 安装步骤

### 3.1 创建系统用户

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin clawlet
```

创建 agent 用户组（用于 Unix socket 访问控制）：

```bash
sudo groupadd clawlet-agents
sudo usermod -aG clawlet-agents ocbot   # 把 agent 用户加入组
```

### 3.2 安装二进制

```bash
# 方式 A: 安装脚本
./scripts/install.sh --isolated

# 方式 B: 源码编译
cargo build --release -p clawlet-cli
sudo cp target/release/clawlet /usr/local/bin/clawlet
sudo chmod 755 /usr/local/bin/clawlet
```

### 3.3 初始化

```bash
# 软件模式（所有环境可用）
sudo -u clawlet clawlet init

# 硬件模式（需要 TPM 2.0，自动重启无需密码）
sudo -u clawlet clawlet init --tpm
```

初始化会创建：
- `~clawlet/.clawlet/keystore/` — 加密的钱包密钥
- `~clawlet/.clawlet/config.yaml` — 默认配置
- `~clawlet/.clawlet/policy.yaml` — 默认限额策略

### 3.4 配置

```bash
# 编辑 RPC 端点
sudo -u clawlet nano ~clawlet/.clawlet/config.yaml
```

```yaml
chain_rpc_urls:
  1: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
  8453: "https://mainnet.base.org"
  42161: "https://arb1.arbitrum.io/rpc"
```

```bash
# 编辑策略限额
sudo -u clawlet nano ~clawlet/.clawlet/policy.yaml
```

### 3.5 锁定文件权限

```bash
sudo chmod 700 ~clawlet/.clawlet
sudo chmod 700 ~clawlet/.clawlet/keystore
sudo chmod 600 ~clawlet/.clawlet/keystore/*
sudo chmod 600 ~clawlet/.clawlet/config.yaml
sudo chmod 600 ~clawlet/.clawlet/policy.yaml
```

## 4. systemd Service

创建 `/etc/systemd/system/clawlet.service`：

```ini
[Unit]
Description=Clawlet Wallet Engine
Documentation=https://github.com/owliabot/clawlet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clawlet
Group=clawlet

# 环境变量
Environment=RUST_LOG=info
Environment=CLAWLET_HOME=/home/clawlet/.clawlet

# 执行
ExecStart=/usr/local/bin/clawlet serve
Restart=on-failure
RestartSec=5

# === 安全加固 (基础) ===
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/clawlet/.clawlet
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

# === 安全加固 (增强) ===
# 系统调用过滤 — 只允许基本服务所需的系统调用
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallArchitectures=native

# 能力限制 — 只保留绑定网络端口
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=

# 网络限制 — 只允许 localhost
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressAllow=127.0.0.0/8 ::1

# Namespace 限制
RestrictNamespaces=true

# TPM 设备访问 (有 TPM 时取消注释)
# DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable clawlet
sudo systemctl start clawlet
sudo systemctl status clawlet

# 查看日志
sudo journalctl -u clawlet -f
```

验证安全配置评分：

```bash
# systemd 内置安全分析（越低越好，8 分以下合格）
systemd-analyze security clawlet
```

## 5. 强制访问控制（MAC）

### 5.1 AppArmor（Ubuntu / Debian）

创建 `/etc/apparmor.d/usr.local.bin.clawlet`：

```
#include <tunables/global>

/usr/local/bin/clawlet {
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # 只读自己的二进制
    /usr/local/bin/clawlet          mr,

    # 数据目录：完整读写
    /home/clawlet/.clawlet/         r,
    /home/clawlet/.clawlet/**       rwk,

    # 共享库
    /usr/lib/**                     mr,
    /lib/**                         mr,
    /lib/x86_64-linux-gnu/**        mr,

    # proc/sys (基本运行需要)
    /proc/self/**                   r,
    /sys/devices/system/cpu/**      r,

    # 网络 — 只允许 TCP stream
    network inet stream,
    network inet6 stream,
    network unix stream,
    deny network inet dgram,
    deny network raw,

    # 禁止执行其他程序
    deny /bin/**                    x,
    deny /usr/bin/**                x,
    deny /usr/sbin/**               x,
    deny /usr/local/bin/*           x,
    /usr/local/bin/clawlet          ix,

    # TPM 设备（有 TPM 时取消注释）
    # /dev/tpm0                     rw,
    # /dev/tpmrm0                   rw,

    # 禁止访问其他用户数据
    deny /home/*/                   r,
    deny /root/                     r,
    deny /etc/shadow                r,
}
```

加载 profile：

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.clawlet
sudo aa-enforce /usr/local/bin/clawlet

# 验证
sudo aa-status | grep clawlet
```

> 调试期间可用 `aa-complain` 切换为宽容模式（只记录不拒绝），稳定后切回 `aa-enforce`。

### 5.2 SELinux（RHEL / CentOS）

创建自定义策略模块：

```bash
mkdir -p /tmp/clawlet-selinux && cd /tmp/clawlet-selinux
```

`clawlet.te`（Type Enforcement）：

```
policy_module(clawlet, 1.0)

require {
    type init_t;
    type node_t;
    type unreserved_port_t;
    class tcp_socket { bind listen accept connect };
    class dir { read write search add_name remove_name };
    class file { read write create unlink open lock append getattr };
}

# 类型声明
type clawlet_t;
type clawlet_exec_t;
type clawlet_data_t;
type clawlet_port_t;

# 进程入口：systemd 启动时自动转换到 clawlet_t
init_daemon_domain(clawlet_t, clawlet_exec_t)

# 文件访问：只允许 clawlet_data_t
allow clawlet_t clawlet_data_t:dir { read write search add_name remove_name };
allow clawlet_t clawlet_data_t:file { read write create unlink open lock append getattr };

# 网络：只允许绑定指定端口
allow clawlet_t clawlet_port_t:tcp_socket { bind listen accept };

# 日志
logging_send_syslog_msg(clawlet_t)
```

`clawlet.fc`（File Context）：

```
/usr/local/bin/clawlet              -- gen_context(system_u:object_r:clawlet_exec_t,s0)
/home/clawlet/.clawlet(/.*)?           gen_context(system_u:object_r:clawlet_data_t,s0)
```

编译和安装：

```bash
# 编译
make -f /usr/share/selinux/devel/Makefile clawlet.pp

# 安装模块
sudo semodule -i clawlet.pp

# 标记端口
sudo semanage port -a -t clawlet_port_t -p tcp 9100

# 恢复文件 context
sudo restorecon -Rv /usr/local/bin/clawlet
sudo restorecon -Rv /home/clawlet/.clawlet/

# 验证
ps -eZ | grep clawlet   # 应显示 clawlet_t
ls -Z /home/clawlet/.clawlet/  # 应显示 clawlet_data_t
```

## 6. Unix Domain Socket（可选增强）

用 Unix socket 替代 TCP，可以用文件权限控制谁能连接：

```yaml
# config.yaml
rpc_bind: "unix:///run/clawlet/clawlet.sock"
```

配置 socket 权限：

```bash
# 创建运行目录
sudo mkdir -p /run/clawlet
sudo chown clawlet:clawlet-agents /run/clawlet
sudo chmod 750 /run/clawlet

# socket 创建后权限：
# srw-rw----  clawlet:clawlet-agents  /run/clawlet/clawlet.sock
# 只有 clawlet 用户和 clawlet-agents 组能连接
```

对比 TCP 方式：

| 维度 | TCP 127.0.0.1:9100 | Unix Socket |
|------|--------------------|--------------------------------------------|
| 访问控制 | 任何本地进程都能连 | 只有指定用户组能连 |
| 身份识别 | 只能靠 Bearer token | `SO_PEERCRED` 获取对端 UID/PID/GID |
| 审计 | 记录 token | 记录 token + 进程 UID/PID |
| 性能 | 经过 TCP/IP 协议栈 | 更快（跳过网络层） |
| 兼容性 | 所有 HTTP 客户端 | 需要客户端支持 Unix socket |

## 7. Daemon 自动重启流程

### 有 TPM（硬件模式）

```
系统启动
  │
  ▼
systemd 启动 clawlet.service
  │
  ▼
检测 V2 keystore（TPM 模式）
  │
  ▼
TPM2_Unseal → 获取 KEK
  │  (绑定 PCR 值，无需密码)
  ▼
KEK 解密私钥到内存
  │
  ▼
RPC Server 就绪
  │
  ▼
[如果崩溃] → systemd Restart=on-failure → 回到启动
```

**无需人工交互**，系统重启后全自动恢复。

### 无 TPM（软件模式）

```
系统启动
  │
  ▼
systemd 启动 clawlet.service
  │
  ▼
检测 V1/V2 keystore（软件模式）
  │
  ▼
需要密码解密 → 从哪里获取?
  │
  ├─ 方案 A: systemd-creds (推荐)
  │   加密凭据绑定 machine-id，开机自动解密
  │
  ├─ 方案 B: Linux Kernel Keyring
  │   首次手动输入后存入内核 keyring，重启后需重新输入
  │
  └─ 方案 C: 密码文件 (最简单，安全性最低)
     chmod 600 的文件，clawlet 启动时读取
```

**systemd-creds 方案详解**（推荐的无 TPM 方案）：

```bash
# 加密凭据（绑定本机 machine-id，可选绑定 TPM PCR）
sudo systemd-creds encrypt --name=clawlet-password /dev/stdin /etc/credstore.encrypted/clawlet-password <<< "your-password"

# 在 service 文件中引用
# [Service]
# LoadCredentialEncrypted=clawlet-password:/etc/credstore.encrypted/clawlet-password
#
# clawlet 从 $CREDENTIALS_DIRECTORY/clawlet-password 读取密码
```

## 8. 安全清单

### 用户隔离

- [ ] 创建了 `clawlet` 系统用户（`/usr/sbin/nologin`）
- [ ] 创建了 `clawlet-agents` 用户组
- [ ] Agent 用户不能读 `~clawlet/.clawlet/` 下任何文件
- [ ] Keystore 目录 `chmod 700`，文件 `chmod 600`

### 硬件保护（有 TPM 时）

- [ ] 使用 `clawlet init --tpm` 初始化
- [ ] 确认 TPM sealed storage 正常工作
- [ ] 验证 daemon 可无密码自动重启
- [ ] 助记词已离线备份

### systemd 加固

- [ ] 基础安全选项已启用（NoNewPrivileges, ProtectSystem 等）
- [ ] `SystemCallFilter` 已配置
- [ ] `CapabilityBoundingSet` 已限制
- [ ] `RestrictAddressFamilies` 已限制
- [ ] `systemd-analyze security clawlet` 评分 < 8

### 强制访问控制

- [ ] AppArmor profile 或 SELinux policy 已安装并 enforce
- [ ] 验证 clawlet 进程不能执行外部程序
- [ ] 验证 clawlet 进程不能写入数据目录之外

### 网络

- [ ] RPC 绑定 `127.0.0.1`（不是 `0.0.0.0`）
- [ ] 防火墙阻止外部访问 9100 端口（`ufw deny 9100` 或 `firewall-cmd`）
- [ ] 如果使用 Unix socket，权限配置正确

### 认证与审计

- [ ] Bearer token 足够随机（>= 32 bytes）
- [ ] Admin 密码强度足够
- [ ] 审计日志已启用
- [ ] logrotate 已配置（防止日志撑满磁盘）
- [ ] Policy 限额设置合理

### 备份

- [ ] 助记词离线安全存储
- [ ] Keystore 文件备份到加密存储
- [ ] 恢复流程已文档化并测试

## 9. Quick Start

```bash
# 1. 创建系统用户和组
sudo useradd --system --create-home --shell /usr/sbin/nologin clawlet
sudo groupadd clawlet-agents

# 2. 安装
cargo build --release -p clawlet-cli
sudo cp target/release/clawlet /usr/local/bin/clawlet
sudo chmod 755 /usr/local/bin/clawlet

# 3. 初始化（有 TPM 则加 --tpm）
sudo -u clawlet clawlet init

# 4. 配置
sudo -u clawlet bash -c 'cat >> ~/.clawlet/config.yaml << EOF
chain_rpc_urls:
  8453: "https://mainnet.base.org"
EOF'

# 5. 锁定权限
sudo chmod -R go-rwx ~clawlet/.clawlet

# 6. 安装 systemd service
sudo cp docs/clawlet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clawlet

# 7. (可选) 安装 AppArmor / SELinux 策略
# Ubuntu/Debian:
sudo cp docs/clawlet.apparmor /etc/apparmor.d/usr.local.bin.clawlet
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.clawlet
# RHEL/CentOS:
# sudo semodule -i docs/clawlet.pp

# 8. 验证
curl -s http://127.0.0.1:9100/health
sudo systemctl status clawlet
systemd-analyze security clawlet
```
