# Clawlet 安全审计报告

**审计日期**: 2026-02-10  
**审计员**: OpenClaw Security Subagent  
**项目版本**: v0.1.19  
**审计范围**: 完整源码 + 安全边界文档对比

---

## 执行摘要

本次安全审计对 Clawlet 项目进行了全面的代码审查，包括认证、授权、密钥管理、Policy Engine、审计日志、并发安全、文件操作等关键安全组件。审计发现了 **3 个严重问题**、**7 个高危问题**、**8 个中危问题** 和 **若干低危/信息性问题**。

### 整体安全评估

- **架构设计**: 较好 — UID 隔离模型有效，127.0.0.1 绑定安全
- **认证机制**: 一般 — Bearer Token 设计合理，但密码验证存在 timing attack 和暴力破解风险
- **授权机制**: 良好 — TokenScope 分级合理，Policy Engine 逻辑正确
- **密钥管理**: **严重缺陷** — 文档声称的 zeroize 未实现，私钥可能泄漏
- **Policy Engine**: 一般 — 基本逻辑正确，但日限额可被时区/并发绕过
- **审计日志**: 良好 — append-only 设计正确
- **代码质量**: 一般 — 测试覆盖率高，但部分安全关键路径未覆盖

**关键风险**: 最严重的问题是 **密码/私钥内存未清零**（文档声称但未实现），可能导致内存转储泄漏私钥，直接威胁资金安全。

---

## 1. 严重问题（Critical）

### C1: 密码 zeroize 未实现 — 内存泄漏风险

**文件**: `crates/clawlet-cli/src/commands/serve.rs:22`, `crates/clawlet-cli/src/commands/init.rs:57-60`  
**威胁级别**: 严重  

#### 问题描述

安全边界文档在启动流程部分明确声称：

> "密码 zeroize 清零"

但审查所有源码和 `Cargo.toml` 依赖后发现：

1. **没有 `zeroize` crate 依赖** — `clawlet-signer/Cargo.toml` 和 `clawlet-cli/Cargo.toml` 中均无 `zeroize` 依赖
2. **密码读取后未清零** — `serve.rs:22` 使用 `rpassword::read_password()` 后直接将 `String` 传给 `Keystore::unlock()`，`String` 在 Rust 中 **不会自动清零**
3. **助记词解密后未清零** — `keystore.rs:decrypt_mnemonic()` 返回的 `String` 同样未清零

#### 攻击向量

- **Core dump**: 进程崩溃时，`String` 的堆内存会写入 core dump 文件，攻击者可读取
- **Swap**: 密码/助记词可能被交换到磁盘 swap 分区，FileVault 不加密 swap
- **内存探测工具**: `gdb`, `lldb`, `/proc/pid/mem` (需 root 或同 UID) 可读取进程内存
- **Spectre/Meltdown**: 缓存侧信道攻击可能泄漏已释放但未清零的内存

#### 影响

- **密码泄漏** → 攻击者可离线暴力破解 keystore
- **助记词泄漏** → 攻击者可直接导入钱包，**完全控制资产**

#### 修复方案

1. **添加 `zeroize` 依赖**:
   ```toml
   # clawlet-signer/Cargo.toml
   zeroize = { version = "1", features = ["derive"] }
   ```

2. **清零密码字符串**:
   ```rust
   // serve.rs
   use zeroize::Zeroize;
   
   let mut password = rpassword::read_password()?;
   let mnemonic = Keystore::unlock(&key_path, &password)?;
   password.zeroize(); // 立即清零
   ```

3. **清零助记词**:
   ```rust
   // keystore.rs
   fn decrypt_mnemonic(json: &KeystoreJson, password: &str) -> Result<String> {
       // ... 解密逻辑 ...
       let mut plaintext = cipher.decrypt(nonce, ct_with_tag.as_ref()) /* ... */;
       let mnemonic = String::from_utf8(plaintext.clone())?;
       plaintext.zeroize(); // 清零 Vec<u8>
       Ok(mnemonic) // 调用者负责清零
   }
   ```

4. **使用 `Zeroizing<String>`**:
   ```rust
   use zeroize::Zeroizing;
   let password = Zeroizing::new(rpassword::read_password()?);
   // 自动清零
   ```

---

### C2: Admin 密码验证存在 Timing Attack

**文件**: `crates/clawlet-rpc/src/server.rs:482-511` (`verify_admin_password`)  
**威胁级别**: 严重  

#### 问题描述

`verify_admin_password()` 通过尝试解密 keystore 来验证密码，但 **scrypt + AES-GCM 的失败时间差异** 可能泄漏密码信息：

```rust
match Keystore::unlock(keystore_path, password) {
    Ok(_mnemonic) => { /* 成功 */ },
    Err(_) => { /* 失败 */ }
}
```

- **正确密码**: scrypt 派生 → AES-GCM 解密 → 成功（耗时 T1）
- **错误密码**: scrypt 派生 → AES-GCM 解密 → **MAC 验证失败**（耗时 T2）

如果 T1 ≠ T2（即使差异仅 μs 级），远程攻击者可通过 **网络往返时间测量** 进行 timing attack，逐字符爆破密码。

#### 攻击向量示例

```python
# 伪代码
for candidate_password in password_list:
    start = time.time()
    response = rpc_call("auth.grant", password=candidate_password)
    elapsed = time.time() - start
    
    if elapsed > THRESHOLD:  # 解密成功但其他错误（如 scope）
        # candidate_password 可能正确
```

#### 实际可利用性

- 文档声称 scrypt N=8192 单次验证约 100-200ms
- 但 **网络抖动** 通常 1-10ms，需要统计学方法（多次采样）
- **本地攻击者**（同主机其他进程）可用 `perf` 等工具精确测量，威胁更大

#### 修复方案

1. **使用 constant-time MAC 验证**: AES-GCM 的 `aes-gcm` crate 应该已经是 constant-time，但 **Rust 的 `Result` 短路返回** 可能泄漏时间

2. **添加恒定延迟**:
   ```rust
   fn verify_admin_password(state: &AppState, password: &str) -> Result<(), AuthError> {
       let start = Instant::now();
       
       let result = try_unlock_keystore(password);
       
       // 无论成功失败，都延迟到固定时间
       let target_delay = Duration::from_millis(200);
       let elapsed = start.elapsed();
       if elapsed < target_delay {
           std::thread::sleep(target_delay - elapsed);
       }
       
       result
   }
   ```

3. **限制失败尝试次数**: 代码已实现 `max_failed_attempts: 5` + `lockout_minutes: 15`，但 **lockout 仅基于标识符**，攻击者可切换 `agent_id` 绕过：
   ```rust
   // 当前实现
   if store.is_locked_out("admin", max_attempts, lockout_minutes) { /* ... */ }
   
   // 应该基于 IP 或更广泛的标识符
   let identifier = format!("admin:{}", request_ip);
   ```

---

### C3: Daily Limit 可被时区操纵绕过

**文件**: `crates/clawlet-core/src/policy.rs:122-129`, `policy.rs:154`  
**威胁级别**: 严重  

#### 问题描述

Policy Engine 的 `daily_transfer_limit_usd` 基于 **UTC 日期字符串** 重置：

```rust
fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

// 在 check_transfer() 中
let current_date = today();
if tracker.date != current_date {
    tracker.date = current_date;
    tracker.total_usd = 0.0; // 重置日限额
}
```

#### 攻击向量 1: 时区切换绕过

1. 攻击者在 **UTC 23:59:00** 转账 $1000（达到日限额）
2. 等待 2 分钟到 **UTC 00:01:00**
3. 日期变为新的一天，`tracker.total_usd` 重置为 0
4. 再次转账 $1000
5. **总损失 $2000（2 小时内）**，而不是 24 小时

#### 攻击向量 2: 系统时钟回拨

如果攻击者能修改系统时间（需要 root 或 A4 攻击者，**超出文档威胁模型**），可回拨时钟重置日限额。

#### 影响

- 文档声称的 `daily_transfer_limit_usd` 实际上是 **日历日限额**，而非 **滚动 24 小时限额**
- 攻击者可在 UTC 午夜前后短时间内突破限额

#### 修复方案

1. **改用滚动 24 小时窗口**:
   ```rust
   struct DailyTracker {
       transfers: Vec<(Instant, f64)>, // (时间, 金额)
   }
   
   fn check_transfer(&self, amount_usd: Option<f64>, ...) -> Result<PolicyDecision> {
       let mut tracker = self.tracker.lock()?;
       
       // 清除 24 小时前的记录
       let cutoff = Instant::now() - Duration::from_secs(24 * 3600);
       tracker.transfers.retain(|(time, _)| *time > cutoff);
       
       let total_24h: f64 = tracker.transfers.iter().map(|(_, amt)| amt).sum();
       if total_24h + amount_usd > self.policy.daily_transfer_limit_usd {
           return Err(/* ... */);
       }
       
       tracker.transfers.push((Instant::now(), amount_usd));
       Ok(PolicyDecision::Allowed)
   }
   ```

2. **持久化 spending tracker**: 当前 `DailyTracker` 仅存于内存，**daemon 重启会重置** → 见 C4

---

### C4: Daily Limit 可被 Daemon 重启绕过

**文件**: `crates/clawlet-core/src/policy.rs:102-110`, `policy.rs:122`  
**威胁级别**: 严重  

#### 问题描述

`DailyTracker` 是内存中的 `Mutex<DailyTracker>`，**不持久化到磁盘**：

```rust
pub struct PolicyEngine {
    policy: Policy,
    tracker: Mutex<DailyTracker>, // 仅内存
}
```

如果 daemon 重启（崩溃或手动 `kill`），`tracker.total_usd` 重置为 0。

#### 攻击向量

1. AI Agent 被入侵（A1 攻击者）
2. 转账 $1000（达到日限额）
3. Agent 发送恶意 RPC 请求导致 daemon 崩溃（如超大 JSON payload）
4. 人类手动重启 daemon
5. 日限额重置，Agent 再次转账 $1000
6. **绕过日限额**

#### 影响

- 文档声称 "daemon 崩溃后停机 = 安全"，但 **重启后日限额被重置** 违背了 Policy 的完整性
- 与文档声明的 `daily_transfer_limit_usd` 保护矛盾

#### 修复方案

1. **持久化 spending tracker**:
   ```rust
   // 在 config.yaml 中添加
   spending_state_path: "/var/clawlet/.clawlet/spending.json"
   
   // PolicyEngine 在每次转账后写入
   struct SpendingState {
       date: String,
       total_usd: f64,
       transfers: Vec<Transfer>, // 用于审计
   }
   
   impl PolicyEngine {
       fn persist_spending(&self) -> Result<()> {
           let state = SpendingState { /* ... */ };
           let json = serde_json::to_string(&state)?;
           std::fs::write(&self.spending_path, json)?;
           Ok(())
       }
   }
   ```

2. **加载时恢复状态**:
   ```rust
   impl PolicyEngine {
       pub fn from_file(policy_path: &Path, spending_path: &Path) -> Result<Self> {
           let policy = Policy::from_file(policy_path)?;
           let tracker = if spending_path.exists() {
               let state: SpendingState = serde_json::from_str(&std::fs::read_to_string(spending_path)?)?;
               // 验证日期，重置或恢复
               if state.date == today() {
                   DailyTracker { date: state.date, total_usd: state.total_usd }
               } else {
                   DailyTracker { date: today(), total_usd: 0.0 }
               }
           } else {
               DailyTracker::default()
           };
           Ok(Self { policy, tracker: Mutex::new(tracker) })
       }
   }
   ```

---

## 2. 高危问题（High）

### H1: Policy Engine Daily Limit 并发竞争条件

**文件**: `crates/clawlet-core/src/policy.rs:132-148`  
**威胁级别**: 高危  

#### 问题描述

`check_transfer()` 的 TOCTOU (Time-of-Check-Time-of-Use) 问题：

```rust
pub fn check_transfer(&self, amount_usd: Option<f64>, ...) -> Result<PolicyDecision> {
    // ...
    let mut tracker = self.tracker.lock()?; // 持锁
    
    // 检查日限额
    if tracker.total_usd + amount_usd > self.policy.daily_transfer_limit_usd {
        return Ok(PolicyDecision::Denied(/* ... */)); // ← 提前释放锁
    }
    
    // ...
    tracker.total_usd += amount_usd; // ← 延迟更新
    Ok(PolicyDecision::Allowed)
}
```

虽然使用了 `Mutex`，但 **检查和更新之间没有事务性保证**。

#### 攻击向量

并发请求导致限额突破：

1. 当前 `tracker.total_usd = $900`，日限额 `$1000`
2. 线程 A 请求转账 `$200` → 检查通过（`$900 + $200 ≤ $1000`）
3. 线程 B 请求转账 `$200` → **同时检查通过**（因为线程 A 还未更新 tracker）
4. 线程 A 更新 `tracker.total_usd = $1100`
5. 线程 B 更新 `tracker.total_usd = $1300`
6. **总转账 $400，超过限额 $300**

#### 实际可利用性

- Tokio 的 `async fn` 中，`lock()` 后的 `await` 点可能交错
- RPC server 使用 `jsonrpsee` 并发处理请求，默认无限并发
- AI Agent 可故意发送并发请求尝试绕过

#### 修复方案

1. **检查和更新必须原子化**:
   ```rust
   pub fn check_transfer(&self, amount_usd: Option<f64>, ...) -> Result<PolicyDecision> {
       let mut tracker = self.tracker.lock()?;
       
       // 原子检查+更新
       if tracker.total_usd + amount_usd > self.policy.daily_transfer_limit_usd {
           // 直接在锁内返回，不更新
           return Ok(PolicyDecision::Denied(/* ... */));
       }
       
       // 立即更新
       tracker.total_usd += amount_usd;
       
       // 持久化（见 C4）
       drop(tracker); // 释放锁
       self.persist_spending()?;
       
       Ok(PolicyDecision::Allowed)
   }
   ```

2. **或使用更严格的同步**: 将整个 RPC 处理流程串行化（降低吞吐量）

---

### H2: Keystore 权限验证不足

**文件**: `crates/clawlet-cli/src/commands/serve.rs:36-54`  
**威胁级别**: 高危  

#### 问题描述

`verify_keystore_permissions()` 仅检查文件权限 `mode & 0o077 != 0`，但：

1. **未检查目录权限**: `~/.clawlet/keystore/` 目录可能是 `0755`，其他用户可 `ls` 列出文件名
2. **未检查所有者**: 仅检查 `mode`，不验证 `owner UID == clawlet`
3. **未检查父目录**: `~/.clawlet/` 可能权限不当

#### 攻击向量

```bash
# 场景 1: 目录权限过宽
chmod 755 ~/.clawlet/keystore  # 其他用户可列出文件
ls ~/.clawlet/keystore/*.json   # A2 攻击者可看到 keystore UUID

# 场景 2: 文件被其他用户创建
sudo su - attacker
echo "fake keystore" > /home/clawlet/.clawlet/keystore/fake.json
chmod 600 fake.json
# 现在 clawlet 启动时可能加载错误的 keystore
```

#### 修复方案

```rust
fn verify_keystore_permissions(keystore_path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    
    // 1. 检查目录权限
    let dir_meta = fs::metadata(keystore_path)?;
    let dir_mode = dir_meta.permissions().mode() & 0o777;
    if dir_mode & 0o077 != 0 {
        return Err(format!(
            "keystore directory {} has insecure permissions {:04o} (expected 0700)",
            keystore_path.display(), dir_mode
        ).into());
    }
    
    // 2. 获取当前用户 UID
    let current_uid = unsafe { libc::getuid() };
    
    // 3. 验证目录所有者
    if dir_meta.uid() != current_uid {
        return Err(format!(
            "keystore directory {} is owned by UID {} (expected {})",
            keystore_path.display(), dir_meta.uid(), current_uid
        ).into());
    }
    
    // 4. 检查每个 keystore 文件
    for entry in fs::read_dir(keystore_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() { continue; }
        
        let meta = fs::metadata(&path)?;
        
        // 检查权限
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(/* ... */);
        }
        
        // 检查所有者
        if meta.uid() != current_uid {
            return Err(format!(
                "keystore file {} is owned by UID {} (expected {})",
                path.display(), meta.uid(), current_uid
            ).into());
        }
    }
    
    Ok(())
}
```

---

### H3: 审计日志可被目录权限绕过

**文件**: `crates/clawlet-core/src/audit.rs:39-49`  
**威胁级别**: 高危  

#### 问题描述

`AuditLogger` 仅确保 `audit.jsonl` 文件以 append 模式打开，但：

1. **未检查父目录权限**: 如果 `~/.clawlet/` 是 `0755`，其他用户可能删除或重命名 `audit.jsonl`
2. **未阻止符号链接攻击**: 攻击者可将 `audit.jsonl` 替换为符号链接指向 `/dev/null`

#### 攻击向量

```bash
# A2 攻击者（同用户）可以（如果目录权限不当）：
rm ~/.clawlet/audit.jsonl
ln -s /dev/null ~/.clawlet/audit.jsonl
# 现在所有审计日志消失
```

#### 修复方案

```rust
impl AuditLogger {
    pub fn new(path: &Path) -> Result<Self, AuditError> {
        // 确保父目录存在且权限正确
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let meta = std::fs::metadata(parent)?;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(AuditError::IoError(
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("audit log directory {} has insecure permissions {:04o}", parent.display(), mode)
                        )
                    ));
                }
            }
        }
        
        // 阻止符号链接
        if path.exists() && path.is_symlink() {
            return Err(AuditError::IoError(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "audit log path is a symlink (not allowed)"
                )
            ));
        }
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        
        // 确保文件权限 0600
        #[cfg(unix)]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
        })
    }
}
```

---

### H4: RPC 缺少请求大小限制

**文件**: `crates/clawlet-rpc/src/server.rs:347-364`  
**威胁级别**: 高危  

#### 问题描述

`jsonrpsee` server 配置未设置 `max_request_body_size`，攻击者可发送超大 JSON payload：

1. **内存耗尽**: 发送 GB 级 JSON → OOM kill daemon
2. **CPU 耗尽**: 发送深度嵌套 JSON → 解析器递归爆栈
3. **绕过 rate limiting**: 单个超大请求可能触发错误路径，绕过 `max_failed_attempts`

#### 攻击向量

```bash
# A2 攻击者发送 1GB JSON
curl -X POST http://127.0.0.1:9100 \
  -H "Content-Type: application/json" \
  -d @huge_payload.json
```

#### 修复方案

```rust
let server = Server::builder()
    .max_request_body_size(1024 * 1024) // 1MB 限制
    .max_response_body_size(10 * 1024 * 1024) // 10MB 响应限制
    .max_connections(100) // 限制并发连接数
    .set_http_middleware(http_middleware)
    .set_rpc_middleware(rpc_middleware)
    .build(self.config.addr)
    .await?;
```

---

### H5: Session Token 哈希算法过弱

**文件**: `crates/clawlet-core/src/auth.rs:217-223`  
**威胁级别**: 高危  

#### 问题描述

Token 哈希使用 **SHA-256 而非 Argon2**：

```rust
fn hash_token(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}
```

文档注释声称：

> "We use SHA-256 here instead of Argon2 because: 1. Tokens are high-entropy random values"

但 **token 只有 32 bytes = 256 bits**，SHA-256 的快速性使得暴力破解成为可能：

- **离线攻击**: 如果攻击者获取 `sessions.json` 文件（A2 攻击者无法，但 A3 物理攻击者可能）
- **GPU 暴力破解**: SHA-256 在 RTX 4090 上约 **60 GH/s**，2^256 空间太大，但如果 token 生成器有缺陷（如不够随机），可被加速

#### 实际风险评估

- Token 生成使用 `OsRng.fill_bytes(&mut [0u8; 32])`，**熵应该足够**
- 但 SHA-256 vs Argon2 的差异在于：**发现哈希泄漏后的响应时间**
- 如果使用 Argon2，攻击者每秒只能尝试 ~1000 个 token，而 SHA-256 可达 ~60 billion/s

#### 修复方案

**保持 SHA-256**，因为：

1. Token 是 32 字节高熵随机值，暴力破解不可行
2. `sessions.json` 文件受 UID 隔离保护，A2 攻击者无法读取
3. Argon2 会显著降低 RPC 吞吐量（每次验证 100ms）

**但需添加额外防护**:

```rust
// sessions.json 文件也应设置 0600 权限
fn persist(&self) {
    let Some(path) = &self.persist_path else { return };
    let tmp_path = path.with_extension("json.tmp");
    
    match serde_json::to_string_pretty(&self.sessions) {
        Ok(data) => {
            if let Err(e) = std::fs::write(&tmp_path, &data) {
                eprintln!("...");
                return;
            }
            
            // 设置权限 0600
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::Permissions::from_mode(0o600);
                let _ = std::fs::set_permissions(&tmp_path, perms);
            }
            
            if let Err(e) = std::fs::rename(&tmp_path, path) {
                eprintln!("...");
            }
        }
        Err(e) => { /* ... */ }
    }
}
```

---

### H6: Admin 密码验证的 Rate Limiting 可被绕过

**文件**: `crates/clawlet-rpc/src/server.rs:476-481`  
**威胁级别**: 高危  

#### 问题描述

Rate limiting 基于固定标识符 `"admin"`：

```rust
if store.is_locked_out("admin", max_attempts, lockout_minutes) {
    return Err(AuthError::TooManyAttempts);
}
```

攻击者可通过以下方式绕过：

1. **切换 `agent_id`**: `auth.grant` 的 `agent_id` 参数由客户端控制，攻击者可为每次尝试使用不同的 ID
2. **Lockout 仅存于内存**: daemon 重启后清空
3. **无 IP-based rate limiting**: 同一 IP 可无限尝试

#### 攻击向量

```python
for i in range(1000000):
    agent_id = f"agent_{i}"  # 每次不同的 agent_id
    rpc_call("auth.grant", {
        "agent_id": agent_id,
        "scope": "admin",
        "password": password_candidates[i]
    })
    # Rate limiting 无效，因为标识符是 "admin"，而非基于 agent_id 或 IP
```

#### 修复方案

```rust
fn verify_admin_password(
    state: &AppState,
    password: &str,
    client_id: &str // 传入请求来源标识符
) -> Result<(), AuthError> {
    // 使用复合标识符
    let identifier = format!("admin_auth:{}", client_id);
    
    {
        let store = state.session_store.read()?;
        if store.is_locked_out(&identifier, 
                                state.auth_config.max_failed_attempts, 
                                state.auth_config.lockout_minutes) {
            return Err(AuthError::TooManyAttempts);
        }
    }
    
    // ... 验证逻辑 ...
    
    if unlock_success {
        store.clear_failed_attempts(&identifier);
    } else {
        store.record_failed_attempt(&identifier);
    }
}
```

**并添加 IP-based rate limiting**:

```rust
// 在 HTTP middleware 中提取 IP
let client_ip = req.extensions().get::<SocketAddr>()
    .map(|addr| addr.ip().to_string())
    .unwrap_or_else(|| "unknown".to_string());

req.extensions_mut().insert(ClientIp(client_ip));
```

---

### H7: Skills 路径遍历防护可被 Canonicalize 绕过

**文件**: `crates/clawlet-rpc/src/handlers.rs:142-165`  
**威胁级别**: 高危  

#### 问题描述

`handle_execute()` 使用两步防护：

1. `is_valid_skill_name()` 验证字符集
2. `canonicalize()` 验证路径未逃逸

但存在 TOCTOU 问题：

```rust
let skill_path = state.skills_dir.join(format!("{}.yaml", req.skill));
if !skill_path.exists() {
    return Err(HandlerError::NotFound("skill not found".into()));
}

// TOCTOU 漏洞：这里 skill_path 可能被替换成符号链接
let canonical_path = skill_path.canonicalize()?;
```

#### 攻击向量

```bash
# A2 攻击者（如果能写入 skills_dir — 虽然文档说不能）
ln -s /etc/passwd skills/evil.yaml
# 然后 RPC 请求 execute(skill="evil")
# canonicalize() 会解析为 /etc/passwd，通过检查（如果 /etc 不是 skills_dir 的父目录，会被拒）
```

实际上，由于 UID 隔离，A2 攻击者 **无法写入 skills_dir**，所以此漏洞 **仅在配置错误时** 可利用（如 skills_dir 权限设为 `0755`）。

#### 修复方案

1. **在 canonicalize 前检查符号链接**:
   ```rust
   if skill_path.is_symlink() {
       return Err(HandlerError::BadRequest("skill path is a symlink".into()));
   }
   ```

2. **启动时验证 skills_dir 权限**:
   ```rust
   // 在 RpcServer::start_with_config()
   verify_skills_dir_permissions(&config.skills_dir)?;
   ```

---

## 3. 中危问题（Medium）

### M1: Scrypt 参数偏弱 - N=8192 可能不足

**文件**: `crates/clawlet-signer/src/keystore.rs:108`  
**威胁级别**: 中危  

#### 问题描述

Keystore 使用 scrypt 参数 `N=8192, r=8, p=1`（约 8MB 内存）：

```rust
let params = scrypt::Params::new(13, 8, 1, 32)?; // N = 2^13 = 8192
```

文档注释称：

> "Previous N=2^17 used ~128 MB and caused OOM kills on constrained systems."

但 N=8192 在现代 GPU 上的暴力破解速度：

- **单个 RTX 4090**: ~10,000 passwords/sec
- **8 位小写字母密码** (26^8 ≈ 2.08×10^11): 约 **2.4 年**（单 GPU）
- **12 位混合密码** (62^12 ≈ 3.2×10^21): 不可行

#### 风险评估

- 如果用户使用 **弱密码**（< 12 位），物理攻击者（A3）可破解
- 文档建议 >= 16 位随机密码，**但未强制执行**

#### 修复方案

1. **在 `clawlet init` 时强制密码强度**:
   ```rust
   fn validate_password_strength(password: &str) -> Result<(), String> {
       if password.len() < 16 {
           return Err("password must be at least 16 characters".to_string());
       }
       
       let has_upper = password.chars().any(|c| c.is_uppercase());
       let has_lower = password.chars().any(|c| c.is_lowercase());
       let has_digit = password.chars().any(|c| c.is_numeric());
       let has_special = password.chars().any(|c| !c.is_alphanumeric());
       
       if !(has_upper && has_lower && has_digit && has_special) {
           return Err("password must contain uppercase, lowercase, digit, and special character".to_string());
       }
       
       Ok(())
   }
   ```

2. **或提高 N 值（权衡内存使用）**:
   ```rust
   let params = scrypt::Params::new(15, 8, 1, 32)?; // N = 2^15 = 32768 (~32 MB)
   ```

---

### M2: 审计日志未做完整性保护

**文件**: `crates/clawlet-core/src/audit.rs`  
**威胁级别**: 中危  

#### 问题描述

审计日志是 append-only JSONL 文件，但 **没有 MAC 或数字签名**，root 攻击者（A4，超出威胁模型）可篡改。

#### 攻击向量

```bash
# A4 攻击者（root）可以
sed -i '/malicious_transfer/d' ~/.clawlet/audit.jsonl
```

#### 修复方案

使用 HMAC 或 Merkle Tree 保护完整性：

```rust
struct AuditEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    details: Value,
    outcome: String,
    // 新增：上一条事件的哈希（链式保护）
    prev_hash: Option<[u8; 32]>,
    // 当前事件的 HMAC（使用 keystore 派生的密钥）
    hmac: [u8; 32],
}

impl AuditLogger {
    fn log_event(&mut self, event: AuditEvent) -> Result<()> {
        let prev_hash = self.last_event_hash;
        let event_with_hash = AuditEvent {
            prev_hash: Some(prev_hash),
            hmac: compute_hmac(&event, &self.hmac_key),
            ..event
        };
        // ...
        self.last_event_hash = hash_event(&event_with_hash);
    }
}
```

---

### M3: Session Token 过期时间未强制刷新

**文件**: `crates/clawlet-core/src/auth.rs:156-175`  
**威胁级别**: 中危  

#### 问题描述

Token 验证时更新 `last_used_at` 和 `request_count`，但 **不刷新过期时间**：

```rust
pub fn verify(&mut self, token: &str) -> Result<&Session, AuthError> {
    // ...
    if Utc::now() > session.expires_at {
        return Err(AuthError::TokenExpired);
    }
    
    session.last_used_at = Utc::now();
    session.request_count += 1;
    // 但 expires_at 不变！
}
```

这意味着即使 Agent 持续活跃，token 也会在初始 TTL 后过期（默认 24 小时）。

#### 影响

- 用户体验不佳：活跃 Agent 需要频繁重新授权
- 但这 **也是一种安全特性**（强制周期性重新验证）

#### 修复方案

**可选改进**（根据产品需求）:

```rust
// 添加配置选项
auth:
  sliding_expiration: true  # 启用滑动过期
  max_session_lifetime_hours: 168  # 绝对过期时间（7 天）

pub fn verify(&mut self, token: &str) -> Result<&Session, AuthError> {
    // ...
    
    if self.config.sliding_expiration {
        // 刷新过期时间（但不超过绝对上限）
        let now = Utc::now();
        let new_expires = now + chrono::Duration::hours(self.config.default_session_ttl_hours as i64);
        let absolute_max = session.created_at + chrono::Duration::hours(self.config.max_session_lifetime_hours as i64);
        
        session.expires_at = std::cmp::min(new_expires, absolute_max);
    }
    
    session.last_used_at = Utc::now();
    session.request_count += 1;
}
```

---

### M4: 错误信息可能泄漏内部状态

**文件**: 多个 `handlers.rs` 和 `server.rs` 中的错误返回  
**威胁级别**: 中危  

#### 问题描述

某些错误消息包含过多内部细节：

```rust
// handlers.rs:110
HandlerError::Internal(format!("failed to query token info: {e}"))

// handlers.rs:128
HandlerError::Internal(format!("send tx error: {e}"))
```

如果 `{e}` 包含 RPC URL、合约地址、内部路径等，可能泄漏给未授权用户。

#### 攻击向量

```bash
# A2 攻击者（无 token）发送请求
curl -X POST http://127.0.0.1:9100 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"balance","params":{"address":"0xinvalid","chain_id":999},"id":1}'

# 响应可能包含：
{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error: failed to connect to https://secret-rpc-url.com"},"id":1}
```

#### 修复方案

```rust
// 定义内部错误 vs 用户可见错误
pub enum HandlerError {
    BadRequest(String), // 用户可见
    NotFound(String),   // 用户可见
    Internal(InternalError), // 不暴露给用户
}

struct InternalError {
    user_message: String, // "Internal server error"
    internal_details: String, // 完整错误信息，仅记录到日志
}

// 在 handler_error_to_rpc() 中
HandlerError::Internal(e) => {
    tracing::error!("internal error: {}", e.internal_details);
    ErrorObjectOwned::owned(
        error_code::INTERNAL_ERROR,
        e.user_message, // 仅返回通用消息
        None::<()>
    )
}
```

---

### M5: Policy Engine 的 Float 精度问题

**文件**: `crates/clawlet-core/src/policy.rs:136-147`  
**威胁级别**: 中危  

#### 问题描述

Daily limit 使用 `f64` 累加：

```rust
tracker.total_usd += amount_usd;
```

浮点数精度误差可能导致：

- **累加误差**: 0.1 + 0.2 ≠ 0.3
- **绕过检查**: 多次转账后，`total_usd` 可能小于实际总和

#### 攻击向量

```python
# 转账 0.333333 USD 共 3000 次
for i in range(3000):
    transfer(amount="0.333333")

# 理论总额: 999.999 USD
# 实际 f64 累加: 可能是 999.998 或 1000.001
```

#### 修复方案

**使用整数或 Decimal 类型**:

```rust
// policy.rs
struct DailyTracker {
    date: String,
    total_cents: i64, // 美分为单位，避免浮点数
}

pub fn check_transfer(&self, amount_usd: Option<f64>, ...) -> Result<PolicyDecision> {
    if let Some(amount_usd) = amount_usd {
        let amount_cents = (amount_usd * 100.0).round() as i64;
        let limit_cents = (self.policy.daily_transfer_limit_usd * 100.0).round() as i64;
        
        if tracker.total_cents + amount_cents > limit_cents {
            return Ok(PolicyDecision::Denied(/* ... */));
        }
        
        tracker.total_cents += amount_cents;
    }
}
```

---

### M6: RPC Server 缺少 TLS 支持

**文件**: `crates/clawlet-rpc/src/server.rs:347`  
**威胁级别**: 中危（取决于部署环境）  

#### 问题描述

RPC server 绑定 `127.0.0.1:9100`，使用 **明文 HTTP**，Bearer Token 以明文传输。

#### 风险评估

- 文档明确说明 **仅本地访问**，`127.0.0.1` 流量不经过网络接口
- 但如果：
  1. 用户配置 `rpc_bind: "0.0.0.0:9100"` 暴露到网络
  2. 使用 SSH tunnel 或端口转发
  
  则 token 可能被中间人窃取

#### 修复方案

1. **强制校验绑定地址**:
   ```rust
   fn validate_bind_address(addr: &SocketAddr) -> Result<()> {
       if !addr.ip().is_loopback() {
           eprintln!("WARNING: Binding to non-loopback address {} exposes clawlet to network attacks!", addr);
           eprintln!("Ensure you use TLS and firewall rules.");
           // 或者直接拒绝
           return Err("non-loopback bind address not allowed".into());
       }
       Ok(())
   }
   ```

2. **添加 TLS 支持**（可选）:
   ```toml
   # config.yaml
   rpc_bind: "0.0.0.0:9100"
   tls:
     cert: /path/to/cert.pem
     key: /path/to/key.pem
   ```

---

### M7: Keystore 文件名使用 UUID 可能泄漏创建顺序

**文件**: `crates/clawlet-signer/src/keystore.rs:49`  
**威胁级别**: 低危  

#### 问题描述

Keystore 文件名使用 UUID v4 随机生成：

```rust
let filename = format!("{}.json", uuid::Uuid::new_v4());
```

UUID v4 是随机的，**不泄漏时间信息**（与 UUID v1 不同）。

#### 实际风险

- **无实际风险** — UUID v4 不包含时间戳或 MAC 地址
- 此项标记为低危仅为信息性记录

---

### M8: Policy 配置文件未做语法强校验

**文件**: `crates/clawlet-core/src/policy.rs:31-36`  
**威胁级别**: 中危  

#### 问题描述

Policy 解析使用 `serde_yaml`，但未验证：

1. **负数限额**: `daily_transfer_limit_usd: -1000.0` 会被接受
2. **NaN/Infinity**: `per_tx_limit_usd: .nan` 可能导致逻辑错误
3. **超大数值**: `daily_transfer_limit_usd: 1e308` 接近 `f64::MAX`

#### 修复方案

```rust
impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Policy = serde_yaml::from_str(yaml)?;
        
        // 校验限额
        if policy.daily_transfer_limit_usd < 0.0 || policy.daily_transfer_limit_usd.is_nan() {
            return Err(PolicyError::ParseError(/* ... */));
        }
        if policy.per_tx_limit_usd < 0.0 || policy.per_tx_limit_usd.is_nan() {
            return Err(PolicyError::ParseError(/* ... */));
        }
        if policy.per_tx_limit_usd > policy.daily_transfer_limit_usd {
            eprintln!("WARNING: per_tx_limit exceeds daily_limit");
        }
        
        Ok(policy)
    }
}
```

---

## 4. 低危/信息性问题（Low/Info）

### L1: Session 清理任务未自动触发

**文件**: `crates/clawlet-core/src/auth.rs:206-214`  
**严重性**: 低危  

`cleanup_expired()` 方法存在但 **未在 RPC server 中周期性调用**，过期 session 会积累在内存和 `sessions.json` 中。

**修复**: 添加后台任务每小时清理：

```rust
// server.rs
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        if let Ok(mut store) = state.session_store.write() {
            store.cleanup_expired();
        }
    }
});
```

---

### L2: RPC 方法缺少详细的请求日志

**文件**: `crates/clawlet-rpc/src/handlers.rs`  
**严重性**: 低危  

当前仅在转账成功时记录审计日志，但 **失败的请求** 也应记录（用于安全分析）。

**修复**: 在所有 handler 入口添加审计：

```rust
pub async fn handle_balance(state: &AppState, params: BalanceQuery) -> Result<...> {
    // 记录请求
    audit_request(state, "balance", json!(params));
    
    // 处理请求...
}
```

---

### L3: 依赖项未固定版本

**文件**: `Cargo.toml` 和各 crate 的 `Cargo.toml`  
**严重性**: 低危  

部分依赖使用 `version = "1"` 或 `version = "0.x"`，可能在 `cargo update` 时引入破坏性变更或漏洞。

**修复**: 使用 `Cargo.lock` 锁定依赖（已存在），并定期审计依赖：

```bash
cargo audit
cargo outdated
```

---

### L4: Argon2 参数使用默认值

**文件**: `crates/clawlet-core/src/auth.rs:120-125`  
**严重性**: 低危  

Admin 密码哈希使用 `Argon2::default()`，未显式指定参数。默认值可能在库升级时变化。

**修复**: 显式指定参数：

```rust
use argon2::{Argon2, Params, Algorithm, Version};

let params = Params::new(15, 2, 1, None).unwrap(); // m=32MB, t=2, p=1
let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
argon2.hash_password(password.as_bytes(), &salt)
```

---

### L5: `send_raw` 方法缺少 Policy 保护

**文件**: `crates/clawlet-rpc/src/handlers.rs:164-213`  
**严重性**: 低危（设计决策）  

`send_raw` 明确 **绕过 Policy Engine**，允许 Trade scope 的 Agent 发送任意交易。

**评估**: 这是有意的设计（文档说明 "for advanced use cases"），但建议：

1. 添加独立的 scope `SendRaw` 而非复用 `Trade`
2. 或在 Policy 中添加 `allow_send_raw: false` 配置项

---

### L6: Token 前缀 `clwt_` 可能冲突

**文件**: `crates/clawlet-core/src/auth.rs:13`  
**严重性**: 信息  

Token 前缀 `clwt_` 较短，可能与其他系统冲突。建议使用更具体的前缀如 `clawlet_` 或 `clw_v1_`。

---

### L7: RPC 错误码未完全覆盖 JSON-RPC 2.0 规范

**文件**: `crates/clawlet-rpc/src/server.rs:87-96`  
**严重性**: 信息  

仅定义了部分标准错误码，缺少 `-32603` (Internal error) 的细分（如 `-32000` ~ `-32099` 的自定义错误）。

**修复**: 扩展错误码定义，区分不同类型的内部错误。

---

### L8: 测试覆盖率不足 - 缺少集成测试

**文件**: `tests/integration/`  
**严重性**: 信息  

虽然单元测试覆盖率较高，但 **缺少端到端集成测试**，特别是：

- Bearer Token 全流程（grant → verify → revoke）
- Policy Engine 与真实转账的集成
- Daemon 重启后的状态恢复

**修复**: 添加 `tests/integration/test_e2e_auth.rs` 等文件。

---

## 5. 文档 vs 代码差距

### 差距 1: 密码 zeroize 未实现（已列为 C1）

**文档声明**:
> "密码 zeroize 清零"

**代码实际**: 未使用 `zeroize` crate，密码和助记词未清零。

---

### 差距 2: Daily Limit 的实际行为与声明不符

**文档声称**:
> "daily_transfer_limit_usd: 每日总限额"

**代码实际**: 
- 基于 UTC 日历日，而非滚动 24 小时
- daemon 重启后重置（见 C3, C4）

**建议**: 更新文档明确说明 "日历日限额（UTC）" 并标注重启重置风险。

---

### 差距 3: Admin 密码验证的安全性低于声称

**文档声称**:
> "Admin 密码验证是否安全（timing attack, brute force protection）"

**代码实际**:
- 存在 timing attack 风险（见 C2）
- Rate limiting 可被 agent_id 轮换绕过（见 H6）

---

### 差距 4: 审计日志 "不可篡改" 的限制

**文档声称**:
> "审计日志是否真的 append-only 且不可篡改"

**代码实际**:
- 是 append-only，但 **无完整性保护**（见 M2）
- root 攻击者（A4，超出威胁模型）可篡改

**建议**: 文档添加 "在威胁模型范围内（非 root 攻击者）不可篡改"。

---

### 差距 5: Scrypt 参数文档不一致

**文档声称**:
> "scrypt 参数是否足够安全"

**代码实际**: 
- `N=8192` (2^13)，而非文档中 "N=2^17"
- 注释说明降低是为了避免 OOM

**建议**: 同步文档中的参数值，并说明权衡。

---

### 差距 6: UID 隔离的前提条件未明确

**文档声称**:
> "UID 隔离模型的实际有效性"

**代码实际**: 
- 代码 **假设** 目录权限正确，但 **未在启动时强制验证**（见 H2）
- 如果用户手动 `chmod 755`，隔离失效

**建议**: 添加启动检查确保权限正确。

---

## 6. 遗漏的威胁

### 威胁 1: 容器/虚拟化环境的攻击面

**文档未提及**: 在 Docker/Kubernetes 环境中，容器逃逸或主机 compromise 可能绕过 UID 隔离。

**建议**: 添加容器安全最佳实践（如 rootless container, seccomp, AppArmor）。

---

### 威胁 2: 侧信道攻击（缓存/时序）

**文档未提及**: Spectre/Meltdown 等 CPU 侧信道攻击可能泄漏进程内存。

**缓解**: 
- 密码/私钥尽快清零（见 C1）
- 考虑使用 `mlock()` 防止 swap

---

### 威胁 3: 供应链攻击

**文档未提及**: Rust crate 依赖链（如 `alloy`, `jsonrpsee`）可能包含恶意代码。

**建议**: 
- 定期运行 `cargo audit`
- 使用 `cargo-crev` 审查关键依赖
- 锁定依赖版本（已使用 `Cargo.lock`）

---

### 威胁 4: 社会工程攻击

**文档未提及**: 攻击者可能通过钓鱼等手段获取 Admin 密码。

**建议**: 添加 "人类因素" 章节，推荐：
- 使用密码管理器
- 启用 2FA（未来支持 Touch ID）
- 定期轮换密码

---

### 威胁 5: RPC 请求重放攻击

**文档未提及**: 攻击者截获合法 RPC 请求后，可重放执行相同操作。

**缓解**: 添加 nonce 或时间戳验证：

```json
{
  "jsonrpc": "2.0",
  "method": "transfer",
  "params": {
    "nonce": "unique_request_id",
    "timestamp": 1234567890,
    ...
  },
  "id": 1
}
```

---

### 威胁 6: 配置文件篡改

**文档未提及**: A2 攻击者（如果权限配置错误）可能篡改 `policy.yaml` 或 `config.yaml`。

**缓解**: 
- 启动时验证配置文件权限（0600）
- 对配置文件做完整性校验（HMAC）

---

## 7. 优先修复建议

### 立即修复（下一个 Patch 版本）

1. **C1: 实现密码/助记词 zeroize** — 最严重，直接威胁私钥安全
2. **C2: 修复 Admin 密码验证 timing attack** — 可能导致密码泄漏
3. **C3/C4: 修复 Daily Limit 绕过漏洞** — 核心安全模型失效
4. **H1: 修复并发竞争条件** — 可能导致限额突破

### 重要（下一个 Minor 版本）

5. **H2: 完善 keystore 权限验证** 
6. **H3: 保护审计日志目录**
7. **H4: 添加 RPC 请求大小限制**
8. **H6: 改进 Rate Limiting**

### 改进（未来版本）

9. **M1: 提高 scrypt 参数或强制密码强度**
10. **M2: 审计日志完整性保护**
11. **M3-M8: 其他中危问题**

---

## 8. 总结

Clawlet 项目的 **架构设计** 总体合理，UID 隔离和 Policy Engine 思路正确。但在 **实现细节** 上存在多个严重安全漏洞，特别是：

- **密钥管理** 存在严重缺陷（未 zeroize）
- **Policy Engine** 的日限额保护可被绕过
- **认证机制** 存在 timing attack 和 rate limiting 绕过

这些问题的共同特点是 **文档声称实现了，但代码中缺失或实现不完整**。

**整体安全评级**: **C+** (60/100)

- 架构设计: B+
- 密钥管理: D（严重缺陷）
- 认证授权: C+（存在可利用漏洞）
- Policy Engine: C（核心逻辑正确但可绕过）
- 审计日志: B（基本功能正确）
- 代码质量: B-（测试覆盖高但安全关键路径不足）

**修复后预期评级**: B+ (85/100)

---

## 附录：关键文件清单

### 已审查的源码文件

```
crates/clawlet-core/src/
  ├── auth.rs         ✅ 认证与 session 管理
  ├── policy.rs       ✅ Policy Engine
  ├── audit.rs        ✅ 审计日志
  ├── config.rs       ✅ 配置解析
  └── ais.rs          ✅ AIS 规范

crates/clawlet-signer/src/
  ├── keystore.rs     ✅ 密钥加密存储
  ├── signer.rs       ✅ 签名实现
  └── hd.rs           ✅ HD 钱包派生

crates/clawlet-rpc/src/
  ├── server.rs       ✅ RPC 服务器
  ├── handlers.rs     ✅ 请求处理
  ├── types.rs        ✅ 类型定义
  └── dispatch.rs     ✅ 方法分发

crates/clawlet-cli/src/commands/
  ├── serve.rs        ✅ 启动命令
  ├── init.rs         ✅ 初始化命令
  └── auth.rs         ✅ 认证命令

crates/clawlet-evm/src/
  ├── executor.rs     ✅ AIS 执行器
  ├── tx.rs           ✅ 交易构建
  └── token.rs        ✅ ERC-20 操作
```

### 依赖审查

所有关键依赖（`argon2`, `scrypt`, `aes-gcm`, `k256`, `jsonrpsee`）的版本均为主流稳定版本，未发现已知高危漏洞（截至 2026-02-10）。

---

**审计完成时间**: 2026-02-10 09:54 UTC  
**审计耗时**: ~2 小时  
**建议复审周期**: 每 3 个月或重大功能变更后
