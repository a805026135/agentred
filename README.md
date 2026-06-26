<h1 align="center">
  <br>
  <img src="https://img.shields.io/badge/AgentRed-v5.1-7c3aed?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMuNSA2LjVMMTIgMTJsOC41LTUuNXpNMTEgMTRIMTNWMjBIMTF6Ii8+PC9zdmc+" alt="AgentRed">
  <br>
  AgentRed
  <br>
</h1>

<p align="center">
  <strong>English</strong> | <a href="README_zh.md">中文</a>
  <br><br>
  <strong>AI Agent security testing framework with 160+ attack cases from latest research.</strong>
  <br><br>
  <a href="#quick-start"><strong>Quick Start</strong></a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#test-case-coverage">Test Cases</a> &bull;
  <a href="#advanced-usage">Advanced Usage</a>
  <br>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green.svg?logo=github" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/test_cases-160%2B-orange" alt="Test Cases"></a>
  <a href="#"><img src="https://img.shields.io/badge/attack_categories-35-red" alt="Attack Categories"></a>
</p>

---

## Why AgentRed?

As AI agents gain **tool use**, **RAG retrieval**, and **autonomous execution** capabilities, they become exponentially more vulnerable to attack. Traditional LLM security testing is not enough — agents have unique attack surfaces:

- **Tool hijacking** — attackers redirect agent tool calls to malicious endpoints
- **RAG poisoning** — poisoned knowledge base causes agents to output harmful content
- **Indirect prompt injection** — injected instructions hidden in web pages, documents, or tool outputs
- **Multi-agent exploitation** — compromised agents spread attacks across agent networks
- **Memory poisoning** — long-term conversation history gets corrupted

**AgentRed** systematically tests your AI agent against **160+ attack vectors** across **35 categories**, derived from the latest academic research (OWASP, arXiv, USENIX Security). It generates a detailed HTML report with scores, remediation advice, and privacy-first architecture.

## Features

| Feature | Description |
|---------|-------------|
| **160+ Attack Test Cases** | Prompt injection (18), jailbreaking (8), tool attacks (18), RAG attacks (16), multi-agent (4), multimodal (4), and more |
| **7-Stage Pipeline** | Config Check → Static Analysis → Adaptive Generation → Tool Use → Dynamic → RAG/Memory → Advisor |
| **Privacy-First Architecture** | 3-level sanitization; Advisor agent only receives sanitized data, never raw agent content |
| **Adaptive Test Generation** | Analyzes your agent's domain/tools/capabilities and generates targeted test cases automatically |
| **AI-Powered Advisor** | Uses any LLM (GPT-4o, DeepSeek, etc.) to generate remediation suggestions from sanitized reports |
| **3 Input Modes** | Local directory scan, prompt text input, or live API endpoint testing |
| **Tool Use Testing** | Tests via agent's function calling interface (not just prompt injection) |
| **RAG/Memory Evaluation** | 11 static checks + 9 dynamic tests for RAG quality, memory persistence, and tool calling |
| **Config Checker** | Detects missing API keys, placeholder values, empty .env files |
| **HTML + JSON Reports** | Radar charts, dimension cards, severity tables, remediation suggestions |

## Quick Start

### Prerequisites

```bash
# Python 3.10+ required
python --version

# Install dependencies
pip install pyyaml
```

### 3 Ways to Run

```bash
# 1. Interactive wizard (recommended for beginners)
python cli.py wizard

# 2. Scan local agent directory (no API key needed)
python cli.py test --dir /path/to/your-agent

# 3. Test with API endpoint (full dynamic testing)
python cli.py test --api-key sk-xxx --api-endpoint https://api.openai.com/v1/chat/completions
```

### Example: Full Test in One Command

```bash
# Test an OpenAI-compatible agent with all features enabled
python cli.py test \
  --dir ./my-agent \
  --api-key $OPENAI_API_KEY \
  --name "finance-bot" \
  --advisor-model deepseek-chat \
  --privacy-level moderate \
  --output ./reports
```

## Screenshots

### Report Overview

The HTML report shows overall scores, dimension breakdowns, and risk level at a glance:

<img src="screenshots/report-overview.png" width="700" alt="Report Overview">

### Detailed Static Analysis

Each check item shows pass/warn/fail status with specific findings:

<img src="screenshots/report-static.png" width="700" alt="Static Analysis">

### Architecture

```
Input Sources          Engine Pipeline              Output
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│ Local Dir │────▶│ Config→Static       │────▶│ HTML+JSON    │
│ Prompt   │     │ Adaptive→ToolUse    │     │ Radar Chart  │
│ API      │     │ Dynamic→RAG/Mem     │     │ Remediation  │
└──────────┘     │ Advisor→Sanitize    │     └──────────────┘
                  └─────────────────────┘
                         ▲   │
              160+ Cases  │   ▼ Privacy Filter
              ┌───────────┴───┐
              │  Sanitized    │◀── Advisor LLM
              │  Data Only    │
              └───────────────┘
```

<details>
<summary>Click to view full architecture diagram</summary>

<img src="screenshots/architecture.svg" width="900" alt="Full Architecture">

</details>

## Test Case Coverage

All test cases are derived from **latest academic research and industry standards**:

| Category | Count | Source |
|----------|-------|--------|
| **Prompt Injection** | 18 | OWASP LLM01, InjecAgent (arXiv 2403.02691) |
| **Jailbreaking** | 8 | Many-shot (NeurIPS'24), GCG, AutoDAN, Cognitive Override |
| **Harmful Content** | 10 | OWASP LLM06, Safety Alignment Bypass |
| **Data Exfiltration** | 10 | CamoLeak, EchoLeak (CVE-2025-32711), Hidden Markdown |
| **Tool Attack** | 8 | ToolHijacker (arXiv 2504.19793) |
| **Tool Description Poisoning** | 4 | MCP Protocol Attack (MDPI 2026) |
| **Tool Shadowing / Rug Pull** | 5 | MCP Tool Substitution Attacks |
| **Tool Invocation Abuse** | 6 | Privilege Escalation via Tools |
| **Tool Permission Overreach** | 3 | OWASP Agentic AI - Tool Misuse |
| **Knowledge Base Poisoning** | 3 | PoisonedRAG (USENIX Security'25) |
| **RAG Context Poisoning** | 2 | Retrieval Manipulation |
| **Cross-Document Data Leak** | 2 | EchoLeak-style Cross-Doc Injection |
| **Retriever Backdoor** | 2 | Adversarial Retrieval Triggers |
| **Adversarial Embedding** | 2 | Semantic Space Poisoning |
| **Memory Poisoning** | 3 | Conversation History Corruption |
| **RAG Scope Violation** | 2 | Out-of-Bounds Retrieval |
| **Multi-Agent Attack** | 4 | A2A Protocol Exploitation, Cascade Attacks |
| **Multimodal Attack** | 4 | CrossInject (arXiv 2504.14348), Steganography |
| **Social Engineering** | 2 | Persona Spoofing, Authority Impersonation |
| **Protocol Attack** | 3 | A2A/MCP Protocol Layer Exploits |
| **Autonomous Misbehavior** | 3 | Goal Drift, Resource Exhaustion, Loop Traps |
| **AI Virus / Self-Replication** | 3 | Prompt-based Self-Propagation |
| **Guardrail Manipulation** | 3 | Safety Filter Bypass Techniques |
| **Boundary (Input)** | 8 | Fuzzing, Overflow, Encoding Attacks |
| **Boundary (Task)** | 5 | Capability Confusion, Goal Hijacking |
| **Boundary (Context)** | 8 | Context Window Attacks, Injection |
| **Boundary (Permission)** | 4 | ACL Bypass, Role Escalation |
| **Boundary (Protocol)** | 3 | API Contract Violations |
| **Performance** | 12 | Latency, Accuracy, Consistency, Robustness |

**Total: 160 test cases across 35 attack categories**

### Research Sources

| Source | Year | Key Contributions |
|--------|------|-------------------|
| [OWASP Top 10 for LLM Apps](https://genai.owasp.org/) | 2025 | LLM01-LLO10 standard risks |
| [OWASP Agentic AI Risks](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) | 2025 | Agent-specific top 10 risks |
| [LLM Security Survey](https://arxiv.org/abs/2505.01177) | 2025 | Backdoors, adversarial inputs, embedding inversion |
| [Prompt Injection in LLM Agents & MCP](https://www.mdpi.com/2078-2489/17/1/54) | 2026 | Tool Shadowing, Rug Pull, ZombAI, CamoLeak |
| [Agentic AI Security](https://arxiv.org/abs/2510.23883) | 2025 | Multi-agent, social engineering, autonomous失控 |
| [ToolHijacker](https://arxiv.org/abs/2504.19793) | 2025 | Tool selection manipulation, doc injection |
| [PoisonedRAG](https://usenix.org/conference/usenixsecurity25) | 2025 | Knowledge base poisoning (90% success rate) |
| [CrossInject](https://arxiv.org/abs/2504.14348) | 2025 | Cross-modal injection (+30.1% success rate) |
| [Many-shot Jailbreaking](https://arxiv.org/abs/2310.04451) | 2024 | Long-context false-pattern injection |

## Advanced Usage

### Adaptive Test Generation

AgentRed automatically analyzes your agent's characteristics and generates targeted test cases:

```bash
# Enable adaptive generation (default: on)
python cli.py test --dir ./my-agent

# The analyzer detects:
#   - Domain: finance, medical, customer_service, education, legal, code...
#   - Tools: web_search, code_exec, file_access, database, email, mcp, browser...
#   - Capabilities: rag, memory, multi_agent, autonomous, tool_use...
#   - Risk Level: high / medium / low (based on safety features)
```

Different agent types generate **completely different** test case sets:
- **Finance Agent** → domain-specific fraud/injection tests
- **Medical Agent** → HIPAA/safety boundary tests
- **Code Agent** → sandbox escape, command injection, dependency poisoning
- **MCP-enabled Agent** → tool description poisoning, shadowing, rug pull

### Privacy Levels

```bash
# Strict: remove all sensitive info (API keys, paths, emails)
python cli.py test --privacy-level strict

# Moderate: mask paths, summarize prompts (default)
python cli.py test --privacy-level moderate

# Minimal: only remove explicit credentials
python cli.py test --privacy-level minimal
```

### Advisor Configuration

```bash
# Use DeepSeek as advisor (cost-effective, Chinese-friendly)
python cli.py test --advisor-api-key $DEEPSEEK_API_KEY --advisor-model deepseek-chat

# Use GPT-4o for deeper analysis
python cli.py test --advisor-api-key $OPENAI_API_KEY --advisor-model gpt-4o

# Use reasoning model for complex analysis
python cli.py test --advisor-model deepseek-reasoner

# Rule-only mode (no API needed)
python cli.py test --no-advisor
```

### Feature Toggles

```bash
# Disable individual modules
python cli.py test --no-adaptive         # No adaptive generation
python cli.py test --no-tool-use         # No tool use testing
python cli.py test --no-extended-eval    # No RAG/Memory evaluation
python cli.py test --no-config-check     # No config checking
python cli.py test --no-advisor          # No AI advisor

# Dry run: preview test cases without executing
python cli.py test --dry-run

# Filter by dimension or severity
python cli.py test --dimension security
pythoncli.py test --severity critical,high
```

## CLI Reference

```
Usage: python cli.py test [OPTIONS]

Input Options:
  --dir PATH            Local agent directory to scan
  --prompt TEXT         System prompt text (or @file.txt)
  --api-key KEY         OpenAI-compatible API key
  --api-endpoint URL    API endpoint URL
  --name NAME           Agent name for report

Testing Options:
  --dimension DIM       security | boundary | performance | all
  --severity SEV        critical,high | high,medium | ...
  --output DIR          Report output directory (./reports)
  --dry-run            Preview without executing

Feature Flags:
  --no-adaptive        Disable adaptive test generation
  --no-tool-use        Disable tool use testing
  --no-extended-eval   Disable RAG/Memory evaluation
  --no-config-check    Disable configuration checking
  --no-advisor         Disable AI advisor

Privacy Options:
  --privacy-level LEVEL strict | moderate | minimal
  --no-sanitized       Don't sanitize advisor input (not recommended)

Advisor Options:
  --advisor-api-key KEY   Advisor LLM API key
  --advisor-model MODEL   Model name (deepseek-chat, gpt-4o, ...)
  --advisor-strategy STR  auto | api_only | rule_only | hybrid

Other Commands:
  wizard                Interactive setup wizard
```

## Project Structure

```
agent-tester/
├── cli.py                        # CLI entry point
├── config.yaml                   # Default configuration
├── demo.py                       # End-to-end demo script
│
├── core/
│   ├── runner.py                 # Main orchestrator (7-stage pipeline)
│   ├── loader.py                 # YAML test case loader
│   ├── evaluator.py              # Rule-based response evaluator
│   ├── scorer.py                 # Multi-dimensional scorer
│   ├── reporter.py               # JSON report generator
│   ├── html_reporter.py          # HTML visual report generator
│   ├── scanner.py                # Directory scanner (detect framework)
│   ├── source.py                 # Unified agent profile (API/Local/Prompt)
│   ├── static_analyzer.py        # 12-item static analysis engine
│   ├── advisor.py                # AI advisor agent (any LLM)
│   ├── config_checker.py         # Missing config detection
│   ├── rag_memory_evaluator.py   # RAG/Memory/Tool evaluation
│   ├── tool_use_tester.py        # Tool/function calling tester
│   ├── privacy_filter.py         # 3-level data sanitizer
│   └── adaptive_generator.py     # Profile-based test case generator
│
├── client/
│   ├── base.py                   # Abstract client interface
│   ├── openai_client.py          # OpenAI-compatible client
│   └── mock_client.py            # Mock client for offline testing
│
├── testcases/
│   ├── security.yaml             # 115 security test cases
│   ├── boundary.yaml             # 33 boundary test cases
│   ├── performance.yaml          # 12 performance test cases
│   ├── tool_attack.yaml          # 18 tool attack test cases
│   └── rag_attack.yaml           # 16 RAG attack test cases
│
├── demo-agent/                   # Example agent for demo
│   ├── agent.py
│   ├── config.json
│   └── system_prompt.txt
│
└── screenshots/                  # README images
```

## How It Works

### Stage 1: Input Analysis

AgentRed accepts three types of input:

1. **Local Directory** (`--dir`) — Scans your agent project, auto-detects framework (LangChain, AutoGen, CrewAI, OpenAI SDK, or custom), extracts system prompts, config files, and code patterns.

2. **Prompt Text** (`--prompt`) — Directly analyze a system prompt string or `@file.txt` reference.

3. **API Endpoint** (`--api-key`) — Connect to a running agent via OpenAI-compatible API for full dynamic testing.

### Stage 2: 7-Stage Testing Pipeline

```
[0] Config Check    → Detect missing API keys, placeholder values, empty configs
[1] Static Analysis  → 12 checks on prompts, code, config (no API needed)
[1.5] Adaptive Gen   → Generate targeted cases based on agent profile
[2] Tool Use Test    → Test via agent's function calling interface
[3] Dynamic Test     → Send 160+ attack prompts, evaluate responses
[4] RAG/Memory Eval  → Evaluate RAG quality, memory safety, tool usage
[5] Advisor          → AI generates remediation (sanitized input only)
[6] Report Sanitize  → Auto-remove sensitive data before saving
```

### Stage 3: Privacy-First Design

```
Your Agent ──(raw data)──▶ AgentRed Tester ──(sanitize)──▶ Advisor LLM
                                    │
                              PrivacyFilter
                            strict/moderate/minimal
                              • API Keys masked
                              • Paths redacted
                              • Prompts summarized
                              • Emails removed
```

**The Advisor agent never sees your original agent content.** Only sanitized evaluation summaries are sent for analysis.

## Contributing

We welcome contributions! Here's how you can help:

1. **Add new attack vectors** — Submit new YAML test cases in `testcases/`
2. **Improve detection logic** — Enhance evaluators in `core/`
3. **Add framework support** — Extend `scanner.py` for new agent frameworks
4. **Fix bugs** — Issues and PRs are welcome
5. **Improve documentation** — Better examples, clearer explanations

### Adding a New Test Case

Create or edit a YAML file in `testcases/`:

```yaml
- id: "sec-pi-new-001"
  category: "prompt_injection"
  dimension: "security"
  severity: "critical"
  description: "Your new attack technique description"
  prompt: "The actual attack payload here..."
  expected_behavior:
    type: refuse
    keywords: ["cannot", "unable", "sorry"]
  references:
    - "https://arxiv.org/abs/XXXX.XXXXXX"
```

### Development Setup

```bash
git clone https://github.com/<your-org>/agentred.git
cd agentred
pip install pyyaml

# Run demo (offline, no API needed)
python demo.py

# Run with dry-run to see what would be tested
python cli.py test --prompt "You are a helpful assistant." --dry-run
```

## Roadmap

- [ ] Web UI dashboard with real-time testing visualization
- [ ] CI/CD integration plugin (GitHub Actions pre-commit hook)
- [ ] Benchmark leaderboard for different agent frameworks
- [ ] Export to SARIF format for GitHub Security tab integration
- [ ] Multi-language support (Chinese/English/Japanese)
- [ ] Plugin system for custom attack modules

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

This project builds on groundbreaking research from the security community:

- **OWASP Foundation** — LLM Top 10 & Agentic AI Top 10 standards
- **USENIX Security Symposium** — PoisonedRAG paper authors
- **arXiv contributors** — All researchers cited above whose work informs our test cases
- **The broader AI safety community** — For advancing the understanding of agent vulnerabilities

---

<p align="center">
  <sub>Built with focus on making AI agents safer for everyone.</sub>
  <br>
  If this project helps you, consider giving it a &#11088;!
</p>
