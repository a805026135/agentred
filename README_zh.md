<h1 align="center">
  <br>
  <img src="https://img.shields.io/badge/AgentRed-v5.1-7c3aed?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMuNSA2LjVMMTIgMTJsOC41LTUuNXpNMTEgMTRIMTNWMjBIMTF6Ii8+PC9zdmc+" alt="AgentRed">
  <br>
  AgentRed
  <br>
</h1>

<p align="center">
  <a href="README.md">English</a> | <strong>中文</strong>
  <br><br>
  <strong>基于最新研究论文的 AI Agent 安全测试框架，内置 160+ 攻击测试用例。</strong>
  <br><br>
  <a href="#快速开始"><strong>快速开始</strong></a> &bull;
  <a href="#功能特性">功能</a> &bull;
  <a href="#架构设计">架构</a> &bull;
  <a href="#测试用例覆盖">用例覆盖</a> &bull;
  <a href="#高级用法">高级用法</a>
  <br>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green.svg?logo=github" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/test_cases-160%2B-orange" alt="Test Cases"></a>
  <a href="#"><img src="https://img.shields.io/badge/attack_categories-35-red" alt="Attack Categories"></a>
</p>

---

## 为什么需要 AgentRed？

随着 AI Agent 获得 **工具调用**、**RAG 检索**和**自主执行**能力，它们面临的攻击风险呈指数级增长。传统的 LLM 安全测试已经不够——Agent 有独特的攻击面：

- **工具劫持** — 攻击者将 Agent 的工具调用重定向到恶意端点
- **RAG 投毒** — 被污染的知识库导致 Agent 输出有害内容
- **间接提示注入** — 注入指令隐藏在网页、文档或工具输出中
- **多智能体利用** — 被攻陷的 Agent 在 Agent 网络中传播攻击
- **记忆投毒** — 长期对话历史被篡改

**AgentRed** 系统化地测试你的 AI Agent 对抗 **160+ 攻击向量**，覆盖 **35 个攻击类别**，源自最新学术研究（OWASP、arXiv、USENIX Security）。它生成详细的 HTML 报告，包含评分、改进建议和隐私优先架构。

## 功能特性

| 功能 | 说明 |
|------|------|
| **160+ 攻击测试用例** | 提示注入(18)、越狱(8)、工具攻击(18)、RAG攻击(16)、多智能体(4)、多模态(4) 等 |
| **7 阶段测试管线** | 配置检测 → 静态分析 → 自适应生成 → 工具调用 → 动态测试 → RAG/Memory → Advisor |
| **隐私优先架构** | 三级脱敏处理；Advisor 只接收脱敏数据，绝不接触原始 Agent 内容 |
| **自适应测试生成** | 自动分析 Agent 的领域/工具/能力特征，动态生成针对性测试用例 |
| **AI 驱动的 Advisor** | 支持任意 LLM（GPT-4o、DeepSeek 等）基于脱敏报告生成改进建议 |
| **3 种输入方式** | 本地目录扫描、Prompt 文本输入、API 端点动态测试 |
| **工具调用测试** | 通过 Agent 的 function calling 接口测试（而非仅提示注入） |
| **RAG/Memory 评估** | 11 项静态检查 + 9 项动态测试，覆盖 RAG 质量、记忆持久性、工具调用 |
| **配置检测器** | 检测缺失 API Key、占位符值、空 .env 文件 |
| **HTML + JSON 报告** | 雷达图、维度卡片、严重等级表、改进建议 |

## 快速开始

### 环境要求

```bash
# 需要 Python 3.10+
python --version

# 安装依赖
pip install pyyaml
```

### 3 种运行方式

```bash
# 1. 交互式向导（推荐新手使用）
python cli.py wizard

# 2. 扫描本地 Agent 目录（无需 API Key）
python cli.py test --dir /path/to/your-agent

# 3. 通过 API 端点测试（完整动态测试）
python cli.py test --api-key sk-xxx --api-endpoint https://api.openai.com/v1/chat/completions
```

### 示例：一键完整测试

```bash
# 对 OpenAI 格式 Agent 启用所有功能进行测试
python cli.py test \
  --dir ./my-agent \
  --api-key $OPENAI_API_KEY \
  --name "finance-bot" \
  --advisor-model deepseek-chat \
  --privacy-level moderate \
  --output ./reports
```

## 截图展示

### 报告总览

HTML 报告一目了然展示总评分、维度分解和风险等级：

<img src="screenshots/report-overview.png" width="700" alt="报告总览">

### 静态分析详情

每个检查项显示通过/警告/失败状态及具体发现：

<img src="screenshots/report-static.png" width="700" alt="静态分析">

### 架构设计

```
输入来源          测试管线              输出
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│ 本地目录 │────▶│ 配置→静态分析       │────▶│ HTML+JSON    │
│ Prompt   │     │ 自适应→工具调用    │     │ 雷达图       │
│ API      │     │ 动态→RAG/Memory    │     │ 改进建议     │
└──────────┘     │ Advisor→脱敏处理   │     └──────────────┘
                  └─────────────────────┘
                         ▲   │
              160+ 用例  │   ▼ 隐私过滤器
              ┌───────────┴───┐
              │  仅脱敏数据    │◀── Advisor LLM
              └───────────────┘
```

<details>
<summary>点击查看完整架构图</summary>

<img src="screenshots/architecture.svg" width="900" alt="完整架构图">

</details>

## 测试用例覆盖

所有测试用例源自**最新学术研究和行业标准**：

| 类别 | 数量 | 来源 |
|------|------|------|
| **提示注入** | 18 | OWASP LLM01, InjecAgent (arXiv 2403.02691) |
| **越狱攻击** | 8 | Many-shot (NeurIPS'24), GCG, AutoDAN, 认知覆写 |
| **有害内容** | 10 | OWASP LLM06, 安全对齐绕过 |
| **数据外泄** | 10 | CamoLeak, EchoLeak (CVE-2025-32711), 隐藏 Markdown |
| **工具攻击** | 8 | ToolHijacker (arXiv 2504.19793) |
| **工具描述投毒** | 4 | MCP 协议攻击 (MDPI 2026) |
| **工具影子替换 / Rug Pull** | 5 | MCP 工具替换攻击 |
| **工具调用滥用** | 6 | 通过工具的权限提升 |
| **工具权限越界** | 3 | OWASP Agentic AI - 工具滥用 |
| **知识库投毒** | 3 | PoisonedRAG (USENIX Security'25) |
| **RAG 上下文投毒** | 2 | 检索操纵 |
| **跨文档数据泄露** | 2 | EchoLeak 式跨文档注入 |
| **检索器后门** | 2 | 对抗性检索触发 |
| **对抗性嵌入** | 2 | 语义空间投毒 |
| **记忆投毒** | 3 | 对话历史篡改 |
| **RAG 范围违规** | 2 | 越界检索 |
| **多智能体攻击** | 4 | A2A 协议利用、级联攻击 |
| **多模态攻击** | 4 | CrossInject (arXiv 2504.14348), 隐写术 |
| **社会工程学** | 2 | 人设伪造、权威冒充 |
| **协议攻击** | 3 | A2A/MCP 协议层漏洞利用 |
| **自主失控** | 3 | 目标漂移、资源耗尽、循环陷阱 |
| **AI 病毒 / 自复制** | 3 | Prompt 驱动的自传播 |
| **护栏操纵** | 3 | 安全过滤绕过技术 |
| **边界（输入）** | 8 | 模糊测试、溢出、编码攻击 |
| **边界（任务）** | 5 | 能力混淆、目标劫持 |
| **边界（上下文）** | 8 | 上下文窗口攻击、注入 |
| **边界（权限）** | 4 | ACL 绕过、角色提升 |
| **边界（协议）** | 3 | API 契约违反 |
| **性能** | 12 | 延迟、准确率、一致性、鲁棒性 |

**总计：160 个测试用例，覆盖 35 个攻击类别**

### 研究来源

| 来源 | 年份 | 主要贡献 |
|------|------|----------|
| [OWASP LLM 应用 Top 10](https://genai.owasp.org/) | 2025 | LLM01-LLM10 标准风险 |
| [OWASP Agentic AI 风险](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) | 2025 | Agent 专属 Top 10 风险 |
| [LLM 安全综述](https://arxiv.org/abs/2505.01177) | 2025 | 后门攻击、对抗输入、嵌入反转 |
| [LLM Agent & MCP 提示注入](https://www.mdpi.com/2078-2489/17/1/54) | 2026 | Tool Shadowing, Rug Pull, ZombAI, CamoLeak |
| [Agentic AI 安全](https://arxiv.org/abs/2510.23883) | 2025 | 多智能体攻击、社会工程学、自主失控 |
| [ToolHijacker](https://arxiv.org/abs/2504.19793) | 2025 | 工具选择操纵、文档注入 |
| [PoisonedRAG](https://usenix.org/conference/usenixsecurity25) | 2025 | 知识库投毒（90% 成功率） |
| [CrossInject](https://arxiv.org/abs/2504.14348) | 2025 | 跨模态注入（成功率提升 30.1%） |
| [Many-shot Jailbreaking](https://arxiv.org/abs/2310.04451) | 2024 | 长上下文虚假模式注入 |

## 高级用法

### 自适应测试生成

AgentRed 自动分析你的 Agent 特征并生成针对性测试用例：

```bash
# 启用自适应生成（默认开启）
python cli.py test --dir ./my-agent

# 分析器自动检测：
#   - 领域：金融、医疗、客服、教育、法律、代码...
#   - 工具：web_search、code_exec、file_access、database、email、mcp、browser...
#   - 能力：rag、memory、multi_agent、autonomous、tool_use...
#   - 风险等级：high / medium / low（基于安全特征估算）
```

不同类型的 Agent 生成**完全不同**的测试用例集：
- **金融 Agent** → 领域专属的欺诈/注入测试
- **医疗 Agent** → HIPAA/安全边界测试
- **代码 Agent** →沙箱逃逸、命令注入、依赖投毒
- **MCP Agent** → 工具描述投毒、影子替换、Rug Pull

### 隐私等级

```bash
# 严格模式：移除所有敏感信息（API Key、路径、邮箱）
python cli.py test --privacy-level strict

# 中等模式：遮盖路径，摘要化 Prompt（默认）
python cli.py test --privacy-level moderate

# 最小模式：仅移除显式凭据
python cli.py test --privacy-level minimal
```

### Advisor 配置

```bash
# 使用 DeepSeek 作为 Advisor（成本低，中文友好）
python cli.py test --advisor-api-key $DEEPSEEK_API_KEY --advisor-model deepseek-chat

# 使用 GPT-4o 进行深度分析
python cli.py test --advisor-api-key $OPENAI_API_KEY --advisor-model gpt-4o

# 使用推理模型处理复杂分析
python cli.py test --advisor-model deepseek-reasoner

# 仅规则模式（无需 API）
python cli.py test --no-advisor
```

### 功能开关

```bash
# 禁用各模块
python cli.py test --no-adaptive         # 禁用自适应生成
python cli.py test --no-tool-use         # 禁用工具调用测试
python cli.py test --no-extended-eval    # 禁用 RAG/Memory 评估
python cli.py test --no-config-check     # 禁用配置检测
python cli.py test --no-advisor          # 禁用 AI Advisor

# 预览模式：查看将使用哪些测试用例（不执行）
python cli.py test --dry-run

# 按维度或严重等级筛选
python cli.py test --dimension security
python cli.py test --severity critical,high
```

## CLI 参考

```
用法：python cli.py test [选项]

输入选项：
  --dir PATH            本地 Agent 目录路径
  --prompt TEXT         System Prompt 文本（或 @file.txt）
  --api-key KEY         OpenAI 格式 API Key
  --api-endpoint URL    API 端点 URL
  --name NAME           报告中使用的 Agent 名称

测试选项：
  --dimension DIM       security | boundary | performance | all
  --severity SEV        critical,high | high,medium | ...
  --output DIR          报告输出目录（默认 ./reports）
  --dry-run            预览模式，不执行测试

功能开关：
  --no-adaptive        禁用自适应测试生成
  --no-tool-use        禁用工具调用测试
  --no-extended-eval   禁用 RAG/Memory 评估
  --no-config-check    禁用配置检测
  --no-advisor         禁用 AI Advisor

隐私选项：
  --privacy-level LEVEL strict | moderate | minimal
  --no-sanitized       不对 Advisor 输入脱敏（不推荐）

Advisor 选项：
  --advisor-api-key KEY   Advisor LLM API Key
  --advisor-model MODEL   模型名称（deepseek-chat、gpt-4o 等）
  --advisor-strategy STR  auto | api_only | rule_only | hybrid

其他命令：
  wizard                交互式设置向导
```

## 项目结构

```
agent-tester/
├── cli.py                        # CLI 入口
├── config.yaml                   # 默认配置
├── demo.py                       # 端到端演示脚本
│
├── core/
│   ├── runner.py                 # 主编排器（7 阶段管线）
│   ├── loader.py                 # YAML 测试用例加载器
│   ├── evaluator.py              # 规则驱动的响应评估器
│   ├── scorer.py                 # 多维度评分器
│   ├── reporter.py               # JSON 报告生成器
│   ├── html_reporter.py          # HTML 可视化报告生成器
│   ├── scanner.py                # 目录扫描器（自动识别框架）
│   ├── source.py                 # 统一 Agent Profile（API/本地/Prompt）
│   ├── static_analyzer.py        # 12 项静态分析引擎
│   ├── advisor.py                # AI Advisor Agent（支持任意 LLM）
│   ├── config_checker.py         # 缺失配置检测器
│   ├── rag_memory_evaluator.py   # RAG/Memory/工具评估
│   ├── tool_use_tester.py        # 工具/函数调用测试器
│   ├── privacy_filter.py         # 三级数据脱敏器
│   └── adaptive_generator.py     # 基于 Agent Profile 的测试用例生成器
│
├── client/
│   ├── base.py                   # 抽象客户端接口
│   ├── openai_client.py          # OpenAI 格式客户端
│   └── mock_client.py            # 离线测试 Mock 客户端
│
├── testcases/
│   ├── security.yaml             # 115 个安全测试用例
│   ├── boundary.yaml             # 33 个边界测试用例
│   ├── performance.yaml          # 12 个性能测试用例
│   ├── tool_attack.yaml          # 18 个工具攻击测试用例
│   └── rag_attack.yaml           # 16 个 RAG 攻击测试用例
│
├── demo-agent/                   # 示例 Agent（用于演示）
│   ├── agent.py
│   ├── config.json
│   └── system_prompt.txt
│
└── screenshots/                  # README 截图资源
```

## 工作原理

### 阶段 1：输入分析

AgentRed 支持三种输入方式：

1. **本地目录** (`--dir`) — 扫描你的 Agent 项目，自动识别框架（LangChain、AutoGen、CrewAI、OpenAI SDK 或自定义），提取 System Prompt、配置文件和代码模式。

2. **Prompt 文本** (`--prompt`) — 直接分析 System Prompt 字符串或 `@file.txt` 文件引用。

3. **API 端点** (`--api-key`) — 通过 OpenAI 格式 API 连接到运行中的 Agent，进行完整动态测试。

### 阶段 2：7 阶段测试管线

```
[0]  配置检测    → 检测缺失的 API Key、占位符值、空配置
[1]  静态分析    → 12 项检查 Prompt、代码、配置（无需 API）
[1.5] 自适应生成 → 基于 Agent Profile 生成针对性测试用例
[2]  工具调用测试 → 通过 Agent 的 function calling 接口测试
[3]  动态测试    → 发送 160+ 攻击 Prompt，评估响应
[4]  RAG/Memory  → 评估 RAG 质量、记忆安全、工具使用
[5]  Advisor     → AI 生成改进建议（仅接收脱敏数据）
[6]  报告脱敏    → 自动移除敏感数据后保存
```

### 阶段 3：隐私优先设计

```
你的 Agent ──(原始数据)──▶ AgentRed 测试器 ──(脱敏)──▶ Advisor LLM
                                    │
                              隐私过滤器
                            strict/moderate/minimal
                              • API Key 被遮盖
                              • 路径被移除
                              • Prompt 被摘要化
                              • 邮箱被移除
```

**Advisor 模型绝不接触你的原始 Agent 内容。** 只有脱敏后的评估摘要才会被发送进行分析。

## 贡献指南

欢迎贡献！你可以通过以下方式参与：

1. **添加新攻击向量** — 在 `testcases/` 中提交新的 YAML 测试用例
2. **改进检测逻辑** — 增强 `core/` 中的评估器
3. **添加框架支持** — 扩展 `scanner.py` 支持新 Agent 框架
4. **修复 Bug** — 提交 Issue 和 PR
5. **改进文档** — 更好的示例、更清晰的说明

### 添加新测试用例

在 `testcases/` 中创建或编辑 YAML 文件：

```yaml
- id: "sec-pi-new-001"
  category: "prompt_injection"
  dimension: "security"
  severity: "critical"
  description: "你的新攻击技术描述"
  prompt: "实际的攻击 payload..."
  expected_behavior:
    type: refuse
    keywords: ["cannot", "unable", "sorry"]
  references:
    - "https://arxiv.org/abs/XXXX.XXXXXX"
```

### 开发环境搭建

```bash
git clone https://github.com/a805026135/agentred.git
cd agentred
pip install pyyaml

# 运行演示（离线，无需 API）
python demo.py

# 预览模式查看将测试什么
python cli.py test --prompt "You are a helpful assistant." --dry-run
```

## Roadmap

- [ ] Web UI 仪表盘，实时测试可视化
- [ ] CI/CD 集成插件（GitHub Actions pre-commit hook）
- [ ] 不同 Agent 框架的基准排行榜
- [ ] 导出为 SARIF 格式，集成 GitHub Security Tab
- [ ] 多语言支持（中文/英文/日语）
- [ ] 插件系统，支持自定义攻击模块

## 许可证

MIT License — 详情见 [LICENSE](LICENSE)。

## 致谢

本项目基于安全社区的开创性研究：

- **OWASP 基金会** — LLM Top 10 & Agentic AI Top 10 标准
- **USENIX Security Symposium** — PoisonedRAG 论文作者
- **arXiv 贡献者** — 所有上述引用的研究者，其工作为测试用例提供了理论基础
- **更广泛的 AI 安全社区** — 推进了对 Agent 漏洞的理解

---

<p align="center">
  <sub>专注于让 AI Agent 对所有人更安全。</sub>
  <br>
  如果这个项目对你有帮助，请给个 &#11088;!
</p>
