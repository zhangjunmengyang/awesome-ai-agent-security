# Awesome AI Agent Security

A learning-oriented project for AI agent security — attack payloads, defense references, and research.

> Not a product. Not a framework. A place to study how AI agents get attacked, and how defenses work (or don't).

[![CI](https://github.com/zhangjunmengyang/awesome-ai-agent-security/actions/workflows/ci.yml/badge.svg)](https://github.com/zhangjunmengyang/awesome-ai-agent-security/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Why This Exists

AI agents now have shell access, file I/O, network access, and persistent memory. Real attacks are happening:

| Attack | Year | What Happened |
|--------|------|---------------|
| Moltbook | 2026 | 1,000+ agents hijacked via prompt injection disguised as audit reports |
| EchoLeak (CVE-2025-32711) | 2025 | Zero-click data exfil through Microsoft 365 Copilot |
| SpAIware | 2024 | Cross-session memory poisoning in ChatGPT that survives restarts |
| ZombieAgent | 2026 | Zero-click agent takeover with worm-like propagation |
| CurXecute (CVE-2025-54135) | 2025 | MCP auto-start → arbitrary code execution in Cursor IDE |

OWASP ranks prompt injection as the #1 LLM risk. There are plenty of awesome-lists collecting links, but few projects that let you actually run attacks against defenses and see what happens.

This project tries to fill that gap — think [OWASP WebGoat](https://owasp.org/www-project-webgoat/) but for AI agents.

## Project Structure

```
awesome-ai-agent-security/
├── shield/          # Defense — reference implementations (4 of 6 shields built)
├── attacks/         # Offense — payload generators and red team runner
├── research/        # Knowledge — threat intel, theory, philosophy (~2,450 lines)
├── tests/           # 52 tests, all passing
└── examples/        # Demo script
```

## Defense

Reference implementations of defense-in-depth for AI agents. For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Shield Status

| Shield | Status | Method | What It Does |
|--------|--------|--------|-------------|
| **Input Shield** | Implemented | Regex + keyword co-occurrence | Scans incoming text against ~70 injection patterns (bilingual). L2 detects internal file references + instruction markers co-occurring. |
| **Action Shield** | Implemented | URL whitelist + pattern matching | Domain whitelist, command safety scoring, frequency rate-limiting, file access control, session log audit. |
| **Soul Shield** | Implemented | SHA-256 hash + chmod + versioning | File integrity baseline, OS-level write protection, version history, change request workflow. |
| **Memory Shield** | Implemented | Regex + canary tokens + source tagging | Poison pattern detection (false authority, behavior directives, privilege escalation), canary token injection/leak detection, source trust levels. |
| **Persona Shield** | Design only | Needs LLM | Persona drift detection over long conversations. Interface designed, not implemented. |
| **Supply Shield** | Design only | Static analysis | Supply chain audit for external skills/plugins. Interface designed, not implemented. |

> **Note**: All implemented detection is pattern-based (regex/heuristics). There is no LLM-based semantic analysis in the current codebase — the L3 semantic layer in Input Shield is a stub.

### Key Defense Features

| Feature | Shield | Description |
|---------|--------|-------------|
| Injection pattern matching | Input | ~70 compiled regex patterns, English + Chinese |
| File-ref + instruction co-detection | Input | Flags external content referencing SOUL.md etc. with imperative markers |
| Domain whitelist | Action | Pre-approved domain list; non-whitelisted URLs flagged |
| Command safety scoring | Action | Pattern-based dangerous command detection (rm -rf, curl\|sh, etc.) |
| Frequency limiting | Action | Sliding-window rate limits on external requests, file writes, commands |
| SHA-256 integrity baseline | Soul | Hash all protected files, detect unauthorized changes |
| OS write protection | Soul | `chmod 444` on critical personality files |
| Version management + rollback | Soul | Historical versions of protected files |
| Canary tokens | Memory | Inject unique tokens into memory; detect exfiltration if they appear in output |
| Source trust model | Memory | Tag memory entries by provenance (owner=1.0, tool=0.7, external=0.3, unknown=0.1) |
| Contradiction detection | Memory | Keyword-based consistency check between new and existing memory |

## Offense

Payload generators for testing defenses. All payloads are derived from real CVEs and published research.

### Generators

| Module | Techniques | Payloads |
|--------|-----------|----------|
| **Prompt Injection** | Direct override, indirect (embedded), obfuscated (Base64/Unicode), crescendo, authority spoofing | EN + ZH |
| **Memory Poisoning** | False authority claims, behavior modification, identity corruption, persistent backdoors | EN + ZH |
| **Tool Abuse** | Data exfiltration, command injection, privilege escalation, supply chain | EN |

### Red Team Runner

Runs automated attack campaigns against a shield configuration and generates detection rate reports:

```bash
python -m attacks.cli run --shields shield.yaml --output report.json
```

## Research

Original analysis — ~2,450 lines across 6 documents:

| Document | Lines | Covers |
|----------|-------|--------|
| [Threat Landscape](research/threat-landscape.md) | 376 | 5 attack categories, 20+ CVEs, major incidents 2023–2026 |
| [Attack Playbook](research/attack-playbook.md) | 769 | Attacker's perspective: recon → entry → persistence → exfil. 10 scenarios |
| [Security Taxonomy](research/security-taxonomy.md) | 295 | 3D classification (vector × target × defense), OWASP 2025 mapping |
| [Theory Foundations](research/security-theory-foundations.md) | 464 | Saltzer & Schroeder (1975) → OWASP 2025 |
| [Philosophy](research/philosophy-of-agent-security.md) | 284 | Locke, Parfit, Wang Yangming, Zhuangzi → agent identity & security |
| [Paper Index](research/agent-security-papers.md) | 262 | Curated academic papers on agent security, 2024–2026 |

## Quick Start

```bash
git clone https://github.com/zhangjunmengyang/awesome-ai-agent-security
cd awesome-ai-agent-security
pip install -e .

# Run the defense demo
python examples/demo.py

# Run all tests
python -m pytest tests/ -v
# → 52 passed, 136 subtests passed in 0.48s

# Initialize shields for a workspace
shield init --workspace /path/to/workspace
shield audit
shield check
```

## Where This Fits

| Layer | Protects | Examples |
|-------|----------|---------|
| Code Security | Source code vulnerabilities | Claude Code Security, Snyk, Semgrep |
| Cognitive Security | Agent identity, memory, persona | **This project** |

These layers are complementary. A code scanner won't catch narrative-disguised prompt injection (the payload is natural language). A gateway audit won't catch memory poisoning (the data looks normal). This project explores the cognitive layer with pattern-based methods — real semantic defense would need LLM-in-the-loop, which isn't built yet.

## Limitations

- All detection is regex/keyword-based — novel phrasings bypass it. Studying *why* is the point.
- Persona Shield and Supply Shield are design-only (not implemented).
- No live agent integration — shields run standalone or in tests.
- Attack payloads go stale as defenses evolve.

## Related Projects

- [OpenClaw](https://github.com/openclaw/openclaw) — AI agent platform this research targets

## Contributing

Contributions welcome — attack payloads, defense improvements, bypass reports, research, CVE analysis, tests.

## License

MIT

---

*[MorpheusZ](https://github.com/zhangjunmengyang) — [OpenClaw](https://github.com/openclaw/openclaw) contributor*
