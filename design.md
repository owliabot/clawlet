# Clawlet

> Agent-native wallet engine for OpenClaw — 给本地 agent 用的链上操作引擎

---

## 🚀 Heartbeat 执行流程

**模式：自主持续推进**

- 默认自主执行，遇到以下情况暂停并 @ zhixian：
  - 架构决策 / 安全模型变更 / 对外发布
  - 有多个方案且影响产品方向
  - 任何拿不准的情况（宁可多问）

**当 heartbeat 触发且 Clawlet 在活跃项目列表时，按以下步骤执行：**

### 1. 开场
向 Discord #clawlet (1467542077020705014) 发送：「让我看看 Clawlet 需要做什么」

### 2. 确认任务
- 读取本文件的「里程碑状态」，找到当前阶段
- 读取对应的计划文件
- 确认下一个未完成的 task

### 3. 执行
- **简单任务**：直接执行
- **复杂任务**：spawn subagent，任务末尾必须包含：
  ```
  **完成时必须**:
  1. 更新计划文件状态（⏳→✅）
  2. 向 Discord #clawlet (1467542077020705014) 发送完成消息
  ```

### 4. 收尾
- 向频道发送本次进度总结
- 如果里程碑完成，更新本文件的「里程碑状态」表格

---

## 基本信息

- **代码路径**：`repos/clawlet`
- **语言**：Rust
- **EVM 库**：alloy
- **Registry 链**：Base (eip155:8453)
- **AIS 标准**：参考 ais-spec
- **设计文档**：`memory/projects/clawlet.md`

---

## 里程碑状态

| 阶段 | 内容 | 状态 |
|------|------|------|
| M0 | 项目初始化 + 品牌 | ✅ 完成 |
| M1 | Wallet Engine MVP（只读 + 转账） | ⏳ 待开始 |
| M2 | DeFi 操作（Swap + 借贷） | ⏳ 待开始 |
| M3 | AIS Registry 合约 | ⏳ 待开始 |
| M4 | 多链支持 | ⏳ 待开始 |
| M5 | OpenClaw Skill 集成 | ⏳ 待开始 |

---

## ⏳ M0: 项目初始化

### 任务清单
- [x] M0-1: 创建 Rust 项目骨架（cargo workspace）
- [x] M0-2: 项目结构设计（crates 划分）
- [x] M0-3: README + LICENSE
- [x] M0-4: GitHub repo 创建
- [x] M0-5: CI 基础配置（cargo test + clippy）

---

## ⏳ M1: Wallet Engine MVP

### 目标
最小可用：查余额 + 转账 + Policy 限制

### 任务清单
- [ ] M1-1: clawlet-core — Policy engine (YAML 解析 + 规则检查)
- [ ] M1-2: clawlet-core — Audit logger (append-only JSONL)
- [ ] M1-3: clawlet-signer — Keystore 创建/解锁/签名
- [ ] M1-4: clawlet-signer — BIP-44 HD 派生（EVM 路径）
- [ ] M1-5: clawlet-evm — 余额查询（ETH + ERC-20）
- [ ] M1-6: clawlet-evm — 转账构建 + 签名 + 广播
- [ ] M1-7: clawlet-rpc — HTTP server (axum) + auth middleware
- [ ] M1-8: clawlet-rpc — Routes: GET /balance, POST /transfer
- [ ] M1-9: clawlet-cli — `clawlet init` (生成 keystore + policy)
- [ ] M1-10: clawlet-cli — `clawlet serve` (启动 RPC server)
- [ ] M1-11: 集成测试（Anvil local fork）
- [ ] M1-12: OS 用户隔离部署文档

### 验收标准
- [ ] `clawlet init` 生成加密 keystore + 默认 policy
- [ ] `clawlet serve` 启动 RPC server 在 127.0.0.1:9100
- [ ] GET /balance 返回 ETH + ERC-20 余额
- [ ] POST /transfer 在 policy 范围内执行转账
- [ ] POST /transfer 超出 policy 限额时拒绝
- [ ] 所有操作写入 audit log

---

## ⏳ M2: DeFi 操作

### 目标
支持 Swap + 借贷，AIS spec 驱动

### 任务清单
- [ ] M2-1: AIS spec 解析器（YAML → Rust 类型）
- [ ] M2-2: AIS execution engine — evm_call 执行
- [ ] M2-3: AIS execution engine — composite（多步骤）执行
- [ ] M2-4: Token approve 管理
- [ ] M2-5: Routes: GET /skills, POST /execute
- [ ] M2-6: 集成测试：Uniswap V3 swap (fork mainnet)
- [ ] M2-7: 集成测试：Aave V3 supply/withdraw (fork mainnet)

---

## ⏳ M3: AIS Registry 合约

### 目标
Base 上部署 Skill Registry，Phase A（中心化管理）

### 任务清单
- [ ] M3-1: Solidity 合约开发（AISRegistry.sol）
- [ ] M3-2: Foundry 测试
- [ ] M3-3: Base Sepolia 测试部署
- [ ] M3-4: 注册 Top 10 协议的 AIS spec
- [ ] M3-5: clawlet-evm — Registry 读取 + spec 缓存
- [ ] M3-6: Base mainnet 部署
- [ ] M3-7: AIS spec repo 公开发布

---

## ⏳ M4: 多链支持

- [ ] M4-1: clawlet-solana crate
- [ ] M4-2: AIS solana_instruction 执行引擎
- [ ] M4-3: 统一 portfolio 视图（多链余额汇总）
- [ ] M4-4: 跨链 token 地址解析（从 AIS spec）

---

## ⏳ M5: OpenClaw Skill 集成

- [ ] M5-1: OpenClaw skill 编写（SKILL.md + CLI wrapper）
- [ ] M5-2: 自然语言 → RPC 调用映射
- [ ] M5-3: 通知集成（大额审批推送到 Discord/Telegram）
- [ ] M5-4: 文档 + 使用指南

---

## 技术决策记录

| 日期 | 决策 | 理由 |
|------|------|------|
| 2026-02-01 | Rust | 内存安全，适合密钥处理 |
| 2026-02-01 | alloy | Paradigm 出品，ethers-rs 后继，Foundry 生态 |
| 2026-02-01 | Base | Registry 部署链，gas 低 + EVM 兼容 |
| 2026-02-01 | AIS 标准 | 链上可验证的协议交互规范 |
| 2026-02-01 | OS 用户隔离 | 私钥保护，agent 不可读 keystore |
| 2026-02-01 | 人类保管私钥 | Agent MPC 暂不成熟，等 TEE+DID |
| 2026-02-02 | 命名 Clawlet | claw + wallet，OpenClaw 生态定位 |
