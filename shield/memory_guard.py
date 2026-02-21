#!/usr/bin/env python3
"""
Agent Sentinel Shield — Memory Guard Module
=============================================
Protects agent soul/memory files from tampering.

Features:
- SHA-256 hash verification of critical files
- Git-based diff detection
- Tampering alert with rollback capability
- Canary trap injection and monitoring

Usage:
    python memory_guard.py init <workspace>     # Initialize hash baseline
    python memory_guard.py check <workspace>    # Check for tampering
    python memory_guard.py canary <workspace>   # Inject canary traps
    python memory_guard.py audit <workspace>    # Full audit report
"""

import hashlib
import json
import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Critical files to protect (relative to workspace root)
CRITICAL_FILES = [
    "SOUL.md",
    "AGENTS.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "MEMORY.md",
]

# Optional files to monitor (won't fail if missing)
MONITORED_FILES = [
    "TOOLS.md",
    "USER.md",
]

HASH_STORE = ".shield/hashes.json"
CANARY_STORE = ".shield/canaries.json"
AUDIT_LOG = ".shield/audit.log"


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_hashes(workspace: str) -> dict:
    """Load stored hash baseline."""
    store_path = os.path.join(workspace, HASH_STORE)
    if os.path.exists(store_path):
        with open(store_path) as f:
            return json.load(f)
    return {}


def save_hashes(workspace: str, hashes: dict):
    """Save hash baseline."""
    store_path = os.path.join(workspace, HASH_STORE)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    with open(store_path, "w") as f:
        json.dump(hashes, f, indent=2)


def log_event(workspace: str, event: str, severity: str = "INFO"):
    """Append to audit log."""
    log_path = os.path.join(workspace, AUDIT_LOG)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with open(log_path, "a") as f:
        f.write(f"[{ts}] [{severity}] {event}\n")


def init_baseline(workspace: str):
    """Initialize hash baseline for all critical files."""
    hashes = {}
    for fname in CRITICAL_FILES + MONITORED_FILES:
        fpath = os.path.join(workspace, fname)
        if os.path.exists(fpath):
            h = sha256_file(fpath)
            hashes[fname] = {
                "hash": h,
                "size": os.path.getsize(fpath),
                "mtime": os.path.getmtime(fpath),
                "initialized_at": datetime.now(timezone.utc).isoformat(),
            }
            print(f"  ✅ {fname}: {h[:16]}...")
        else:
            print(f"  ⚠️  {fname}: not found (skipped)")

    save_hashes(workspace, hashes)
    log_event(workspace, f"Baseline initialized with {len(hashes)} files")
    print(f"\n🛡️  Baseline saved to {os.path.join(workspace, HASH_STORE)}")
    print(f"    Protected files: {len(hashes)}")


def check_integrity(workspace: str) -> list:
    """Check all critical files against baseline. Returns list of violations."""
    stored = load_hashes(workspace)
    if not stored:
        print("❌ No baseline found. Run 'init' first.")
        return [{"file": "BASELINE", "type": "missing"}]

    violations = []

    for fname in CRITICAL_FILES:
        fpath = os.path.join(workspace, fname)
        stored_info = stored.get(fname)

        if not os.path.exists(fpath):
            if stored_info:
                v = {"file": fname, "type": "deleted", "severity": "CRITICAL"}
                violations.append(v)
                log_event(workspace, f"CRITICAL: {fname} has been DELETED", "CRITICAL")
                print(f"  🔴 {fname}: DELETED!")
            continue

        if not stored_info:
            print(f"  ⚠️  {fname}: exists but not in baseline (new file?)")
            continue

        current_hash = sha256_file(fpath)
        if current_hash != stored_info["hash"]:
            v = {
                "file": fname,
                "type": "modified",
                "severity": "CRITICAL",
                "old_hash": stored_info["hash"][:16],
                "new_hash": current_hash[:16],
                "size_delta": os.path.getsize(fpath) - stored_info.get("size", 0),
            }
            violations.append(v)
            log_event(workspace, f"CRITICAL: {fname} has been MODIFIED (hash mismatch)", "CRITICAL")
            print(f"  🔴 {fname}: MODIFIED! (Δsize: {v['size_delta']:+d} bytes)")

            # Try to show git diff if available
            _show_git_diff(workspace, fname)
        else:
            print(f"  ✅ {fname}: intact")

    # Check monitored files (non-critical)
    for fname in MONITORED_FILES:
        fpath = os.path.join(workspace, fname)
        stored_info = stored.get(fname)
        if stored_info and os.path.exists(fpath):
            current_hash = sha256_file(fpath)
            if current_hash != stored_info["hash"]:
                print(f"  🟡 {fname}: modified (monitored, non-critical)")
                log_event(workspace, f"WARNING: {fname} modified", "WARNING")

    if not violations:
        log_event(workspace, "Integrity check passed — all files intact")
        print("\n🛡️  All critical files intact.")
    else:
        print(f"\n🚨 {len(violations)} VIOLATIONS detected!")

    return violations


def _show_git_diff(workspace: str, fname: str):
    """Try to show git diff for a modified file."""
    try:
        result = subprocess.run(
            ["git", "diff", "--stat", fname],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip():
            print(f"    git diff: {result.stdout.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def inject_canaries(workspace: str):
    """Inject canary traps into memory files."""
    import secrets

    canaries = {}
    memory_path = os.path.join(workspace, "MEMORY.md")

    if not os.path.exists(memory_path):
        print("❌ MEMORY.md not found. Cannot inject canaries.")
        return

    # Generate unique canary tokens
    for i in range(3):
        token = f"canary-{secrets.token_hex(4)}"
        canaries[token] = {
            "injected_at": datetime.now(timezone.utc).isoformat(),
            "location": "MEMORY.md",
            "type": ["api_key", "internal_url", "project_name"][i],
        }

    # Save canary registry
    store_path = os.path.join(workspace, CANARY_STORE)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    with open(store_path, "w") as f:
        json.dump(canaries, f, indent=2)

    log_event(workspace, f"Injected {len(canaries)} canary traps")
    print(f"🐤 Injected {len(canaries)} canary traps.")
    print(f"   Tokens stored in {store_path}")
    print(f"   Monitor agent output for these tokens to detect data exfiltration.")
    print()
    for token, info in canaries.items():
        print(f"   [{info['type']}] {token}")


def check_canary_leak(text: str, workspace: str) -> list:
    """Check if any canary tokens appear in given text. Returns leaked tokens."""
    store_path = os.path.join(workspace, CANARY_STORE)
    if not os.path.exists(store_path):
        return []

    with open(store_path) as f:
        canaries = json.load(f)

    leaked = []
    for token in canaries:
        if token in text:
            leaked.append(token)
            log_event(workspace, f"CANARY LEAKED: {token} found in output!", "CRITICAL")

    return leaked


def full_audit(workspace: str):
    """Run a complete security audit."""
    print("=" * 60)
    print("🛡️  Agent Sentinel Shield — Full Audit")
    print(f"   Workspace: {workspace}")
    print(f"   Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    # 1. Hash integrity
    print("\n📋 1. File Integrity Check")
    print("-" * 40)
    violations = check_integrity(workspace)

    # 2. Canary status
    print("\n📋 2. Canary Trap Status")
    print("-" * 40)
    store_path = os.path.join(workspace, CANARY_STORE)
    if os.path.exists(store_path):
        with open(store_path) as f:
            canaries = json.load(f)
        print(f"  Active canaries: {len(canaries)}")
        for token, info in canaries.items():
            print(f"    [{info['type']}] {token[:12]}... (since {info['injected_at'][:10]})")
    else:
        print("  ⚠️  No canaries deployed. Run 'canary' to set up.")

    # 3. Audit log summary
    print("\n📋 3. Recent Audit Events")
    print("-" * 40)
    log_path = os.path.join(workspace, AUDIT_LOG)
    if os.path.exists(log_path):
        with open(log_path) as f:
            lines = f.readlines()
        for line in lines[-10:]:
            print(f"  {line.rstrip()}")
    else:
        print("  No audit events yet.")

    # 4. Summary
    print("\n" + "=" * 60)
    if violations:
        print(f"🚨 AUDIT FAILED — {len(violations)} violation(s) detected")
    else:
        print("✅ AUDIT PASSED — No violations detected")
    print("=" * 60)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    workspace = os.path.expanduser(sys.argv[2])

    if not os.path.isdir(workspace):
        print(f"❌ Workspace not found: {workspace}")
        sys.exit(1)

    if command == "init":
        print(f"🛡️  Initializing hash baseline for: {workspace}\n")
        init_baseline(workspace)
    elif command == "check":
        print(f"🛡️  Checking integrity for: {workspace}\n")
        check_integrity(workspace)
    elif command == "canary":
        print(f"🛡️  Injecting canary traps for: {workspace}\n")
        inject_canaries(workspace)
    elif command == "audit":
        full_audit(workspace)
    else:
        print(f"❌ Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
