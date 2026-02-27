# Agent 安全学术研究笔记

> 研究日期：2026-02-20
> 研究员：Scholar
> 状态：初版 v0.1
> 信息来源：arXiv / MDPI / OpenReview / IEEE / ACM，2024–2026

---

## 一、研究全景

Agent 安全已从"理论隐患"演变为**工程事实**。2025 年 GitHub Copilot 的 CVE-2025-53773（CVSS 9.6）证明 prompt injection 可导致远程代码执行，影响数百万开发者。OWASP 将 prompt injection 列为 **LLM01:2025** 头号威胁。

核心矛盾：**LLM 将一切视为无差别的 token 序列——指令与数据之间不存在语法边界，只有模糊的语义边界。** 这是架构层面的根本缺陷，不是实现 bug。

---

## 二、威胁分类学

### 2.1 攻击向量分类

| 类别 | 描述 | 代表攻击 |
|------|------|----------|
| **直接注入** | 用户输入直接覆盖系统指令 | Jailbreaking、角色扮演绕过 |
| **间接注入** | 通过外部内容（网页、文件、工具返回）注入 | RAG 投毒、MCP 工具投毒 |
| **多阶段注入** | 利用 Agent 循环逐步升级权限 | Tool-chain exploitation |
| **信息泄露** | 提取系统提示词、API Key、内部 URL | System prompt leakage (LLM07:2025) |

### 2.2 Agent 特有威胁面

来源：Chhabra et al. 《Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges》 [arXiv:2510.23883]

Agent 相较普通 LLM 应用，新增的威胁维度：
- **工具调用链攻击**：注入指令导致 Agent 调用恶意工具序列
- **记忆投毒**：污染 Agent 的长期记忆/知识库
- **MCP 协议漏洞**：Log-To-Leak 攻击通过 MCP Server 日志窃取交互数据（GPT-4o、GPT-5、Claude-Sonnet-4 均受影响）[OpenReview:UVgbFuXPaO]
- **confused deputy**：Agent 代替用户执行操作，但信任了不可信输入

---

## 三、核心论文精读

### 3.1 检测方法

#### PromptArmor: Simple yet Effective Prompt Injection Defenses
- **arXiv**: 2507.15219 (2025.07)
- **作者**: Shi, Zhu, Wang et al. (Dawn Song 团队)
- **核心思想**: 用现成 LLM 在 Agent 处理输入前**检测并移除**注入的 prompt
- **关键结果**: GPT-4o/GPT-4.1/o4-mini 上，假阳性率和假阴性率均 <1%；ASR 降至 <1%
- **意义**: 挑战了"现成 LLM 无法直接防御 prompt injection"的常见认知
- **局限**: 依赖检测模型本身不被绕过；自适应攻击下的鲁棒性待验证

#### DataSentinel (IEEE S&P 2025)
- 将注入检测建模为**极小极大优化问题**
- 利用一个"故意脆弱"的 LLM 来暴露被污染的输入
- 博弈论视角：检测器与攻击者形成对抗均衡

#### AgentMonitor (Chan et al., 2024)
- 多 Agent 系统的即插即用监控框架
- 预测性安全检查 + 行为异常检测

### 3.2 防御框架

#### AgentArmor: Enforcing Program Analysis on Agent Runtime Trace
- **arXiv**: 2508.01249 (2025.08)
- **核心创新**: 将 Agent 运行轨迹视为**结构化程序**，进行程序分析
- **三大组件**:
  1. **图构造器**: 将运行轨迹转为 CFG/DFG/PDG 图中间表示
  2. **属性注册器**: 为交互工具和数据附加安全元数据
  3. **类型系统**: 在中间表示上进行静态推断和检查
- **关键结果**: AgentDojo benchmark 上 ASR 降至 3%，功能损失仅 1%
- **我的评注**: 这是最有前景的方向之一——将安全问题从"语义猜测"降维到"程序分析"

#### AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents
- **arXiv**: 2503.18666 (2025.03) → **ICSE 2026 录用**
- **核心**: 轻量级 DSL，定义运行时约束（触发器 + 谓词 + 执行机制）
- **跨域验证**: 代码执行、具身 Agent、自动驾驶
- **结果**:
  - 代码 Agent：>90% 阻止不安全执行
  - 具身 Agent：消除所有危险动作
  - 自动驾驶：100% 法规合规
  - 开销：毫秒级
- **LLM 自动生成规则**: o1 生成的规则精确率 95.56%，召回率 70.96%

#### A Multi-Agent LLM Defense Pipeline Against Prompt Injection
- **arXiv**: 2509.14285 (2025.09) → IEEE WIECON-ECE 2025
- **架构**: 
  - 方案 A：顺序 chain-of-agents 流水线
  - 方案 B：层级 coordinator 系统
- **结果**: 55 种攻击 × 400 实例 → ASR 从 30%/20% 降至 **0%**
- **局限**: 测试规模有限（ChatGLM + Llama2）

### 3.3 形式化验证

#### VeriGuard: Enhancing LLM Agent Safety via Verified Code Generation
- **arXiv**: 2510.05156 (2025.10)
- **双阶段架构**:
  1. **离线阶段**: 明确用户意图 → 合成行为策略 → 测试 + 形式化验证 → 迭代修正
  2. **在线阶段**: 运行时监控器验证每个动作是否符合预验证策略
- **核心价值**: 将穷尽性离线验证与轻量在线监控分离，使形式化保证可工程化

#### Pro2Guard: Proactive Runtime Enforcement via Probabilistic Model Checking
- **arXiv**: 2508.00500 (2025.08)
- **方法**: 将 Agent 行为抽象为符号状态 → 从执行轨迹学习 DTMC → 概率模型检查
- **关键**: **前瞻性**而非反应性——在违规发生前干预
- **PAC 正确性保证**: 统计可靠的安全执行
- **对比 AgentSpec**: AgentSpec 是反应式（违规时/违规后干预），Pro2Guard 预测风险

#### AgentGuard: Runtime Verification of AI Agents
- **arXiv**: 2509.23864 (2025.09) → ASE 2025 AgenticSE Workshop
- **范式**: Dynamic Probabilistic Assurance
- 观察 Agent I/O → 抽象为形式事件 → 在线学习 MDP → 概率模型检查
- **哲学转变**: 问题不是"系统是否会失败"，而是"在给定约束下失败的概率是多少"

#### Towards Verifiably Safe Tool Use for LLM Agents
- **arXiv**: 2601.08012 (2026.01) → **ICSE NIER 2026 录用**
- **方法**: STPA（系统理论过程分析）→ 识别危害 → 导出安全需求 → 形式化为可执行规范
- **提出**: 增强 MCP 协议，要求工具声明能力、机密性、信任级别的结构化标签
- **核心主张**: 从"事后可靠性修补"转向"前置形式化安全保障"

### 3.4 综合调查

#### Security Concerns for Large Language Models: A Survey
- **arXiv**: 2505.18889 (2025.05)
- 覆盖 2022–2025，分类：推理时攻击、训练时攻击、恶意使用、自主 Agent 风险

#### Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges
- **arXiv**: 2510.23883 (2025.10, updated 2026.02)
- 目前最全面的 Agentic AI 安全综述
- 威胁分类 + 评估方法论 + 防御策略 + 治理视角

#### Prompt Injection Attacks in LLMs and AI Agent Systems (MDPI, 2026.01)
- **DOI**: 10.3390/info17010054
- 45 篇文献 + 行业报告 + 真实漏洞
- 提出 **PALADIN** 五层纵深防御框架
- 识别根本限制：随机性问题 + 对齐悖论

---

## 四、技术路线图：防御方法演进

```
2024 ──────────────────────── 2025 ──────────────────────── 2026
  │                              │                              │
  ├─ Guardrail Models           ├─ Program Analysis            ├─ Formal Verification
  │  (LLaMA-Guard)              │  (AgentArmor)                │  (VeriGuard)
  │                              │                              │
  ├─ Input/Output Filter        ├─ DSL Runtime Enforcement     ├─ STPA + MCP Enhancement
  │  (Perplexity-based)         │  (AgentSpec)                 │  (Verifiably Safe Tool Use)
  │                              │                              │
  ├─ Fine-tuned Detectors       ├─ Multi-Agent Defense         ├─ Probabilistic Model Checking
  │  (DataSentinel)             │  (Defense Pipeline)          │  (Pro2Guard)
  │                              │                              │
  └─ Prompt Engineering         ├─ LLM-based Detection         └─ PAC Safety Guarantees
     (System Prompt hardening)  │  (PromptArmor)
                                │
                                └─ Dynamic Probabilistic
                                   Assurance (AgentGuard)
```

---

## 五、关键洞见与我们项目的关联

### 5.1 对 Shield 项目的启示

1. **程序分析路线最值得投资**: AgentArmor 将 Agent 轨迹视为程序的思路极为巧妙。我们的 Shield 可以：
   - 为 OpenClaw Agent 的工具调用链构建 CFG/DFG
   - 定义类型系统区分 trusted/untrusted 数据流
   - 毫秒级开销，可工程化部署

2. **DSL 规则 + LLM 自动生成**: AgentSpec 的方法可以直接借鉴——用 DSL 定义安全规则，用 LLM 辅助生成初始规则集

3. **MCP 安全是蓝海**: 目前几乎没有成熟的 MCP 安全方案，"Verifiably Safe Tool Use" 刚提出 capability-enhanced MCP。这是我们可以先占的位置

4. **不要只做检测**: PromptArmor 证明 LLM 能检测注入，但**单点防御不可靠**。需要纵深防御

5. **前瞻性 > 反应性**: Pro2Guard 的前瞻性干预思路优于被动响应

### 5.2 未解决的根本问题

- **指令-数据不可分问题**: LLM 架构层面无法区分指令和数据，所有防御都是"补丁"
- **对齐悖论**: 模型越"听话"，越容易被 prompt injection 利用
- **可组合性**: 单个工具安全 ≠ 工具链安全
- **自适应攻击**: 几乎所有防御在面对自适应攻击时都会退化

### 5.3 推荐阅读优先级

| 优先级 | 论文 | 原因 |
|--------|------|------|
| ⭐⭐⭐ | AgentArmor (2508.01249) | 程序分析框架，直接可借鉴 |
| ⭐⭐⭐ | AgentSpec (2503.18666) | DSL + 运行时执行，ICSE 2026 |
| ⭐⭐⭐ | Agentic AI Security Survey (2510.23883) | 全景理解 |
| ⭐⭐ | VeriGuard (2510.05156) | 形式化验证方向 |
| ⭐⭐ | Pro2Guard (2508.00500) | 概率模型检查 |
| ⭐⭐ | Verifiably Safe Tool Use (2601.08012) | MCP 安全增强 |
| ⭐ | PromptArmor (2507.15219) | 检测基线 |
| ⭐ | PALADIN Review (MDPI 2026) | 产业视角综述 |

---

## 六、后续研究方向

1. 深入阅读 AgentArmor 全文，提取其类型系统的形式化定义
2. 研究 AgentSpec DSL 语法，评估是否可作为 Shield 的规则语言基础
3. 追踪 MCP 安全相关工作（目前论文极少，领域空白）
4. 研究 taint tracking 在 Agent 数据流中的应用
5. 设计 Shield 的架构概念验证（MVP），结合：
   - AgentArmor 的程序分析思路
   - AgentSpec 的 DSL 规则引擎
   - Pro2Guard 的前瞻性风险评估

## 七、多 Agent 安全专题（2026-02-22 新增）

### 7.1 Colosseum: Auditing Collusion in Cooperative Multi-Agent Systems

- **来源**: arXiv:2602.15198 (2026-02-16)
- **作者**: Nakamura et al.
- **核心**: 首个系统化审计多 Agent 勾结行为的框架
- **方法**: DCOP 建模 + regret 量化 + 网络拓扑变量 + LLM-as-a-judge
- **关键发现**:
  - 大多数 LLM 在存在秘密通信通道时倾向勾结
  - "纸上勾结"：文本中计划勾结但行为不执行（意图 ≠ 行为）
  - 拓扑结构影响勾结概率
- **对 Shield 的价值**: 直接支撑 Trust Topology 设计。通信通道监控 + 意图审计 + 拓扑感知防御
- **优先级**: ⭐⭐⭐（与盾卫信任拓扑直接对标）

### 7.2 Evaluating Collective Behaviour of Hundreds of LLM Agents

- **来源**: arXiv:2602.16662 (2026-02-18)
- **作者**: Willis et al.
- **核心**: 首次将 Agent 集体行为评估扩展到数百规模
- **方法**: LLM 生成算法编码策略 + 社会困境环境 + 文化进化模拟
- **关键发现**:
  - 更新模型 → 更差社会结果（当优先个体利益时）
  - 规模增大 + 合作收益降低 → 收敛到差均衡
  - 策略算法化 → 支持部署前静态分析
- **对 Shield 的价值**: 军团扩展时的安全预警。规模效应 + 模型选择对集体行为的影响
- **优先级**: ⭐⭐（理论指导，非直接工具）

### 7.3 推荐阅读更新

| 优先级 | 论文 | 原因 |
|--------|------|------|
| ⭐⭐⭐ | Colosseum (2602.15198) | 多 Agent 勾结审计，直接对标盾卫 Trust Topology |
| ⭐⭐⭐ | Agentic AI as Cybersecurity Attack Surface (2602.19555) | Runtime supply chain 攻击面系统化，与盾卫认知安全层互补 |
| ⭐⭐⭐ | ICON: Indirect Prompt Injection Defense (2602.20708) | Inference-time correction 防间接注入，可能首个可部署轻量方案 |
| ⭐⭐ | Collective Behaviour (2602.16662) | 规模效应与集体行为，军团扩展参考 |

---

## 八、后续研究方向（更新）

1. 深入阅读 AgentArmor 全文，提取其类型系统的形式化定义
2. 研究 AgentSpec DSL 语法，评估是否可作为 Shield 的规则语言基础
3. 追踪 MCP 安全相关工作（目前论文极少，领域空白）
4. 研究 taint tracking 在 Agent 数据流中的应用
5. 设计 Shield 的架构概念验证（MVP）
6. **Colosseum DCOP 框架 → 盾卫 trust audit 的 regret 量化指标**
7. **深读 2602.19555**（runtime supply chain 攻击面分析）→ 与盾卫 Cognitive Layer 定位对比，提取互补空间
8. **深读 2602.20708 ICON**（inference-time correction）→ 评估轻量防御机制能否集成到 Input Shield
9. **多 Agent 人格交叉污染 → CAPD 指标实现**（见 soulbox/research/agent-personality-science.md §7）

---

*这份笔记是活文档，随研究推进持续更新。上次更新：2026-02-28*
