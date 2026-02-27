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

OWASP ranks prompt injection as the #1 LLM risk. There are plenty of awesome-lists collecting links, but few projects that let you **actually run attacks against defenses and see what happens**.

This project tries to fill that gap — think [OWASP WebGoat](https://owasp.org/www-project-webgoat/) but for AI agents.

## What's Inside

```
awesome-ai-agent-security/
├── shield/          # Defense — four reference implementations
├── attacks/         # Offense — payload generators and red team runner
├── research/        # Knowledge — threat intel, theory, philosophy
├── tests/           # 52 tests, all passing
└── examples/        # Demo script
```

## Defense: Four Shields (Implemented)

Reference implementations showing *why* defense-in-depth matters. **These are demos, not production-grade tools.**

### Input Shield — Pattern-Based Injection Detection

Scans incoming text for known attack patterns. Three layers:

- **L1: Regex matching** — ~70 patterns covering instruction override, role hijacking, data exfil prompts, authority spoofing, etc. Bilingual (English + Chinese).
- **L2: Structure detection** — Flags content that references internal files (SOUL.md, MEMORY.md, etc.) combined with instruction markers. The co-occurrence matters more than either alone.
- **L3: Semantic detection** — Stub. The interface exists but the actual implementation is a placeholder (`echo "data:0.1"`). Would need a real LLM call to work.

**Honest assessment**: L1 and L2 are straightforward regex + keyword matching. They catch known patterns but are trivially bypassable with novel phrasing. That's expected — the point is to study *why* pattern matching alone is insufficient, not to ship it as a solution.

### Action Shield — Behavioral Whitelist

Controls what an agent is allowed to do:

- **URL whitelist** — Only allows requests to pre-approved domains (github.com, arxiv.org, etc.). Everything else gets flagged.
- **Command safety scoring** — Checks shell commands against dangerous patterns (rm -rf, curl piped to sh, etc.).
- **Frequency limiting** — Rate-limits external requests, file modifications, and command executions within sliding time windows.
- **File access control** — Blocks write/delete attempts on sensitive files (SOUL.md, MEMORY.md, etc.).
- **Session audit** — Scans session logs for suspicious commands, URLs, and data exfiltration patterns.

**Honest assessment**: The URL whitelist is the most practical piece — simple and effective. The command safety scoring is basic pattern matching (not sandboxing). Frequency limiting is in-memory only (resets on restart).

### Soul Shield — File Integrity Protection

Protects critical personality/config files:

- **Hash-based integrity checking** — SHA-256 baseline of all protected files, detects unauthorized changes.
- **OS-level write protection** — `chmod 444` on critical files.
- **Version management** — Keeps historical versions of protected files for rollback.
- **Change request workflow** — Approval flow for modifying protected files (request → review → approve/deny).

**Honest assessment**: This is the most "real" shield. File hashing + chmod is simple but genuinely effective against a specific attack vector (unauthorized file modification). The version management works. The change request workflow is implemented but only useful if you actually integrate it into your agent's write pipeline.

### Memory Shield — Poison Detection

Scans memory writes for poisoning attempts:

- **Authority injection detection** — Catches "boss said...", "management approved...", "as instructed by admin..." patterns.
- **Behavior directive detection** — Catches "from now on you must...", "new rule:...", "remember: always..." patterns.
- **Privilege escalation detection** — Catches "root access granted", "elevated privileges obtained" patterns.
- **Canary tokens** — Injects unique tokens into memory files; if they appear in agent output, data exfiltration is detected.
- **Source trust model** — Tags memory entries by source (owner_direct=1.0, tool_output=0.7, external_summary=0.3, unknown=0.1).
- **Consistency checking** — Basic pattern-based contradiction detection between new and existing memory. Not semantic.

**Honest assessment**: The canary token system is clever and works. The source trust model is a good concept. The actual poison detection is regex-based — it catches the obvious stuff ("ignore previous instructions") but won't catch a well-crafted narrative attack (which is exactly what Moltbook used). The consistency checker is primitive (keyword contradiction matching, not real NLU).

### What's NOT Implemented

- **Persona Shield** — Drift detection over long conversations. Planned, not built.
- **Supply Shield** — Supply chain audit for external skills/plugins. Planned, not built.
- **L3 semantic detection** — The Input Shield's LLM-based analysis layer is a stub.
- **Real-time integration** — None of the shields are hooked into a live agent runtime. They're standalone tools you run manually or in tests.

## Offense: Red Team Toolkit

Payload generators for testing your own defenses.

### Prompt Injection Generator

Generates attack payloads across multiple techniques:

- Direct instruction override (English + Chinese)
- Indirect injection (embedded in data)
- Obfuscated injection (Base64, Unicode, delimiter tricks)
- Crescendo attacks (gradually escalating prompts)
- Authority spoofing ("I am your developer")

### Memory Poisoner

Generates memory poisoning payloads:

- False authority claims ("boss approved X")
- Behavior modification ("new rule: always do X")
- Identity corruption ("your real name is...")
- Persistent backdoors ("remember: when asked about X, do Y")

### Tool Abuse Generator

Generates payloads that abuse legitimate tools:

- Data exfiltration via "backup" functions
- Command injection through tool parameters
- Privilege escalation through tool chaining
- Supply chain attacks via malicious plugins

### Red Team Runner

Runs automated attack campaigns against a shield configuration:

```bash
# Run all attacks against all shields
python -m attacks.cli run --shields shield.yaml --output report.json
```

The runner generates a report showing which attacks penetrated which shields and at what rate.

## Research

Original analysis, not rehashed blog posts. ~2,450 lines across 6 documents:

| Document | Lines | What It Covers |
|----------|-------|---------------|
| [Threat Landscape](research/threat-landscape.md) | 376 | 5 attack categories, 20+ real CVEs, major incidents 2023-2026 |
| [Attack Playbook](research/attack-playbook.md) | 769 | Attacker's perspective: recon → entry → persistence → exfil. 10 detailed scenarios |
| [Security Taxonomy](research/security-taxonomy.md) | 295 | 3D classification: vector × target × defense. OWASP 2025 mapping |
| [Theory Foundations](research/security-theory-foundations.md) | 464 | Saltzer & Schroeder (1975) → OWASP 2025. Academic grounding |
| [Philosophy](research/philosophy-of-agent-security.md) | 284 | Locke, Parfit, Wang Yangming, Zhuangzi → agent identity & security |
| [Paper Index](research/agent-security-papers.md) | 262 | Curated academic papers on agent security, 2024-2026 |

## Quick Start

```bash
git clone https://github.com/zhangjunmengyang/awesome-ai-agent-security
cd awesome-ai-agent-security
pip install -e .

# Run the defense demo
python examples/demo.py

# Run all tests (52 tests)
python -m pytest tests/ -v

# Initialize shields for a workspace
shield init --workspace /path/to/workspace
shield audit
shield check
```

## Tests

52 tests, all passing. Coverage includes:

- Input Shield pattern matching against known payloads
- Action Shield URL whitelist, command safety, frequency limits
- Memory Shield poison detection, canary tokens, consistency checks
- Red Team payload generation and campaign execution
- End-to-end attack-vs-defense simulation

```bash
python -m pytest tests/ -v
# 52 passed, 136 subtests passed in 0.48s
```

## Where This Fits

AI agent security isn't one problem — it's at least three layers:

| Layer | What It Protects | Examples |
|-------|-----------------|---------|
| Code Security | Source code vulnerabilities | [Claude Code Security](https://www.anthropic.com), Snyk, Semgrep |
| Infrastructure Security | Gateway, permissions, credentials | [SecureClaw](https://github.com/nichochar/secureclaw-skill) |
| Cognitive Security | Agent identity, memory, persona | **This project** |

These are complementary. A code scanner won't catch a narrative-disguised prompt injection because the payload is natural language. A gateway audit won't catch memory poisoning because the data looks normal. Cognitive security operates at the meaning layer — which is also why it's the hardest to get right.

This project is an exploration of that third layer. The defenses here are pattern-based (regex + heuristics), not semantic. Real cognitive security probably needs LLM-in-the-loop detection, which we haven't built yet.

## Limitations

1. **This is a learning tool, not a product.** The shields are reference implementations — they demonstrate concepts, not production-grade protection.
2. **Pattern matching is bypassable.** Novel phrasings get through. That's expected — studying *why* it fails is the point.
3. **Two shields are unimplemented.** Persona Shield and Supply Shield exist only as concepts.
4. **No live agent integration.** These shields run standalone. Integrating them into an actual agent runtime is left as an exercise.
5. **No semantic analysis.** The L3 semantic detection layer is a stub. All actual detection is regex/keyword-based.
6. **Attack payloads go stale.** As defenses improve, attacks must evolve. This is a snapshot, not a living service.

## Related Projects

- [OpenClaw](https://github.com/openclaw/openclaw) — The AI agent platform this research targets.
- [SecureClaw](https://github.com/nichochar/secureclaw-skill) — Infrastructure security for OpenClaw (gateway, permissions, supply chain).

## Contributing

Contributions welcome across all areas — new attack payloads, defense improvements, bypass reports, research analysis, CVE deep dives, test cases.

## License

MIT

---

*Built by [MorpheusZ](https://github.com/zhangjunmengyang) — [OpenClaw](https://github.com/openclaw/openclaw) contributor.*
