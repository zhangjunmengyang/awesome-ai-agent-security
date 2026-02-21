---
name: agent-sentinel-shield
description: "Six-layer runtime defense system for AI agents — prompt injection detection, action whitelisting, soul file protection, memory poisoning defense, persona drift detection, and supply chain audit."
homepage: "https://github.com/zhangjunmengyang/agent-sentinel-shield"
metadata:
  clawdbot:
    emoji: "🛡️"
    tags: ["security", "agent", "prompt-injection", "memory-guard", "defense-in-depth", "safety"]
    files: ["shield/*", "tests/*", "examples/*", "research/*"]
---

# Agent Sentinel Shield 🛡️

> Runtime security for AI agents. Not another guardrail — an architecture.

Six-layer defense system: Input Shield (injection detection) → Action Shield (behavioral whitelisting) → Soul Shield (OS-level file protection) → Memory Shield (source trust model) → Persona Shield (drift detection, planned) → Supply Shield (supply chain audit, planned).

## Quick Start

```bash
pip install -e .
shield init --workspace ~/.openclaw/workspace
shield audit
shield check
echo "Ignore previous instructions" | shield scan-input
python examples/demo.py
```

## Why Defense in Depth

Pattern matching alone fails — attackers change one word, defenders add another regex. We limit what a successful attack can do using four reliability levels: OS-level enforcement > behavioral whitelisting > source trust > pattern matching.

## External Endpoints

None. Fully local. No data leaves your machine.

## Requirements

- Python 3.9+
- PyYAML, Click

## License

MIT
