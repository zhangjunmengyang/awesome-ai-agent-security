"""
Memory Shield - 记忆守卫盾
=======================
Protects agent memory from poisoning attacks and maintains content integrity.
"""

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import (
    ScanResult, MemoryEntry, ConsistencyResult, ThreatLevel, 
    ShieldType, ActionType, CanaryToken
)
from ..patterns.poison import MemoryPoisonDetector
from ..logger import ShieldLogger
from ..config import ShieldConfig


class MemoryShield:
    """Memory Shield for detecting and preventing memory poisoning attacks."""
    
    def __init__(self, workspace: str, config: Optional[ShieldConfig] = None, logger: Optional[ShieldLogger] = None):
        """Initialize Memory Shield.
        
        Args:
            workspace: Path to the workspace directory
            config: Shield configuration (optional)
            logger: Shield logger instance (optional)
        """
        self.workspace = Path(workspace)
        self.config = config or ShieldConfig(workspace=workspace)
        # Create proper log path for ShieldLogger
        log_path = self.workspace / ".shield" / "audit.log"
        self.logger = logger or ShieldLogger(str(log_path))
        self.poison_detector = MemoryPoisonDetector()
        
        # Canary storage
        self.canary_store_path = self.workspace / ".shield" / "canaries.json"
        self.canaries: Dict[str, CanaryToken] = {}
        self._load_canaries()
        
        # Source trust levels (0.0 - 1.0)
        self.source_trust_levels = {
            "owner_direct": 1.0,        # Direct input from verified owner
            "self_reflection": 0.9,     # Agent's own analysis/reflection
            "tool_output": 0.7,         # Output from tools/APIs
            "external_summary": 0.3,    # Summary of external content
            "unknown": 0.1              # Unknown source
        }
    
    def _load_canaries(self):
        """Load existing canary tokens from storage."""
        if self.canary_store_path.exists():
            try:
                with open(self.canary_store_path, 'r', encoding='utf-8') as f:
                    canary_data = json.load(f)
                
                for token, data in canary_data.items():
                    self.canaries[token] = CanaryToken(
                        token=token,
                        token_type=data.get("type", "unknown"),
                        location=data.get("location", "unknown"),
                        injected_at=datetime.fromisoformat(data.get("injected_at")),
                        purpose=data.get("purpose", "detection"),
                        pattern=data.get("pattern")
                    )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                self.logger.log_event(
                    ShieldType.MEMORY, 
                    "canary_load_error", 
                    ThreatLevel.MEDIUM,
                    f"Failed to load canaries: {e}"
                )
    
    def _save_canaries(self):
        """Save canary tokens to storage."""
        self.canary_store_path.parent.mkdir(parents=True, exist_ok=True)
        
        canary_data = {}
        for token, canary in self.canaries.items():
            canary_data[token] = {
                "type": canary.token_type,
                "location": canary.location,
                "injected_at": canary.injected_at.isoformat(),
                "purpose": canary.purpose,
                "pattern": canary.pattern
            }
        
        with open(self.canary_store_path, 'w', encoding='utf-8') as f:
            json.dump(canary_data, f, indent=2, ensure_ascii=False)
    
    def scan_write(self, content: str, source: str = "unknown") -> ScanResult:
        """Scan memory content before writing for poisoning attempts.
        
        Args:
            content: Content to be written to memory
            source: Source of the content
            
        Returns:
            ScanResult with detection results
        """
        violations = []
        matched_patterns = []
        threat_level = ThreatLevel.LOW
        
        # Run poison detection
        poison_results = self.poison_detector.scan_all(content)
        risk_score = self.poison_detector.get_risk_score(poison_results)
        
        # Process results by category
        for category, matches in poison_results.items():
            if matches:
                matched_patterns.append(f"{category}:{len(matches)}")
                
                for match_type, match_text in matches:
                    violations.append(f"{category}: {match_text[:100]}...")
                    
                    # Escalate threat level based on category
                    if category in ["authority_injection", "behavior_directives", "privilege_escalation"]:
                        if threat_level.value != "critical":
                            threat_level = ThreatLevel.HIGH if threat_level == ThreatLevel.MEDIUM else ThreatLevel.CRITICAL
                    elif category in ["file_manipulation", "identity_spoofing"]:
                        if threat_level == ThreatLevel.LOW:
                            threat_level = ThreatLevel.MEDIUM
        
        # Check for canary leaks
        leaked_canaries = self.check_canaries(content)
        if leaked_canaries:
            violations.extend([f"canary_leak: {token[:12]}..." for token in leaked_canaries])
            matched_patterns.append(f"canary_leak:{len(leaked_canaries)}")
            threat_level = ThreatLevel.CRITICAL
        
        # Determine if content is safe — any matched poison pattern = unsafe
        safe = len(matched_patterns) == 0 and not leaked_canaries
        
        # Determine recommended action
        if threat_level == ThreatLevel.CRITICAL:
            recommendation = ActionType.BLOCK
        elif threat_level == ThreatLevel.HIGH:
            recommendation = ActionType.QUARANTINE
        elif threat_level == ThreatLevel.MEDIUM:
            recommendation = ActionType.WARN
        else:
            recommendation = ActionType.WARN if risk_score > 0.1 else ActionType.WARN
        
        # Log the scan
        self.logger.log_scan(
            ShieldType.MEMORY,
            f"content ({len(content)} chars)",
            safe,
            matched_patterns,
            {"source": source, "risk_score": risk_score}
        )
        
        return ScanResult(
            safe=safe,
            shield_type=ShieldType.MEMORY,
            threat_level=threat_level,
            matched_patterns=matched_patterns,
            violations=violations,
            recommendation=recommendation,
            details={
                "risk_score": risk_score,
                "source": source,
                "trust_level": self.source_trust_levels.get(source, 0.1),
                "poison_results": poison_results,
                "leaked_canaries": leaked_canaries
            }
        )
    
    def verify_consistency(self, new_entry: str, existing_memory: str) -> ConsistencyResult:
        """Verify consistency between new memory entry and existing memory.
        
        This is a pattern-based implementation. For full semantic consistency,
        an LLM would be needed.
        
        Args:
            new_entry: New memory content to check
            existing_memory: Existing memory content
            
        Returns:
            ConsistencyResult with consistency analysis
        """
        conflicts = []
        new_facts = []
        existing_facts = []
        
        # Extract potential facts from new entry
        new_facts = self._extract_factual_statements(new_entry)
        existing_facts = self._extract_factual_statements(existing_memory)
        
        # Look for direct contradictions
        conflicts = self._find_contradictions(new_facts, existing_facts)
        
        # Simple consistency scoring
        if conflicts:
            consistent = False
            confidence = 0.3  # Low confidence without LLM
        elif self._has_conflicting_timeframes(new_entry, existing_memory):
            consistent = False
            confidence = 0.5
            conflicts.append("Conflicting timeframes detected")
        else:
            consistent = True
            confidence = 0.7
        
        # Generate recommendation
        if not consistent and len(conflicts) > 0:
            recommendation = "REVIEW: Potential conflicts detected. Manual verification recommended."
        else:
            recommendation = "OK: No obvious conflicts detected."
        
        # Log consistency check
        self.logger.log_consistency_check(new_entry, conflicts, consistent)
        
        return ConsistencyResult(
            consistent=consistent,
            conflicts=conflicts,
            new_facts=new_facts,
            existing_facts=existing_facts,
            confidence=confidence,
            recommendation=recommendation,
            details={
                "analysis_method": "pattern_based",
                "llm_available": False,
                "conflict_count": len(conflicts)
            }
        )
    
    def _extract_factual_statements(self, text: str) -> List[str]:
        """Extract potential factual statements from text.
        
        This is a simple pattern-based extraction.
        """
        facts = []
        
        # Look for statements that assert facts
        fact_patterns = [
            r"(.*)\s+(is|was|are|were|has|have|will be|will have)\s+(.+?)(?:\.|$)",
            r"(.*)\s+(decided|confirmed|approved|agreed|stated)\s+(.+?)(?:\.|$)",
            r"(On|At|In)\s+([^,]+),\s*(.+?)(?:\.|$)",
            r"(The|A|An)\s+([^,]+)\s+(happened|occurred|changed)(?:\.|$)"
        ]
        
        for pattern in fact_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                fact = match.group().strip()
                if len(fact) > 10:  # Filter out very short matches
                    facts.append(fact)
        
        return facts[:10]  # Limit to prevent overflow
    
    def _find_contradictions(self, new_facts: List[str], existing_facts: List[str]) -> List[str]:
        """Find potential contradictions between fact sets.
        
        This is a simple keyword-based approach.
        """
        conflicts = []
        
        # Simple contradiction patterns
        contradiction_pairs = [
            (r"\bnot\s+(.+)", r"\b\1\b"),
            (r"\bno\s+(.+)", r"\b\1\b"),
            (r"\bdisabled?\b", r"\benabled?\b"),
            (r"\bfalse\b", r"\btrue\b"),
            (r"\bdenied?\b", r"\ballowed?\b"),
            (r"\bbanned?\b", r"\bpermitted?\b")
        ]
        
        for new_fact in new_facts:
            for existing_fact in existing_facts:
                # Check for direct contradiction patterns
                for neg_pattern, pos_pattern in contradiction_pairs:
                    if (re.search(neg_pattern, new_fact.lower()) and 
                        re.search(pos_pattern, existing_fact.lower())) or \
                       (re.search(neg_pattern, existing_fact.lower()) and 
                        re.search(pos_pattern, new_fact.lower())):
                        conflicts.append(f"Contradiction: '{new_fact[:50]}...' vs '{existing_fact[:50]}...'")
                        break
        
        return conflicts[:5]  # Limit conflicts to prevent spam
    
    def _has_conflicting_timeframes(self, new_entry: str, existing_memory: str) -> bool:
        """Check for conflicting temporal references."""
        # Extract dates and times
        date_pattern = r"\b(yesterday|today|tomorrow|last week|next week|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2})\b"
        
        new_dates = re.findall(date_pattern, new_entry.lower())
        existing_dates = re.findall(date_pattern, existing_memory.lower())
        
        # Simple conflicting timeframe detection
        conflicting_pairs = [
            ("yesterday", "tomorrow"),
            ("last week", "next week"),
            ("past", "future")
        ]
        
        for new_date in new_dates:
            for existing_date in existing_dates:
                for past_term, future_term in conflicting_pairs:
                    if (past_term in new_date and future_term in existing_date) or \
                       (future_term in new_date and past_term in existing_date):
                        return True
        
        return False
    
    def check_canaries(self, text: str) -> List[str]:
        """Check if any canary tokens appear in the given text.
        
        Args:
            text: Text to check for canary leaks
            
        Returns:
            List of leaked canary tokens
        """
        leaked_tokens = []
        
        for token, canary in self.canaries.items():
            if token in text:
                leaked_tokens.append(token)
                # Log the leak
                self.logger.log_canary_leak(token, "memory_scan", ShieldType.MEMORY)
        
        return leaked_tokens
    
    def inject_canaries(self, workspace: str):
        """Inject canary tokens into memory files.
        
        Args:
            workspace: Workspace directory path
        """
        workspace_path = Path(workspace)
        canary_count = self.config.get_canary_count()
        
        # Generate canary tokens
        new_canaries = {}
        canary_types = ["api_key", "internal_url", "project_name", "config_value", "database_name"]
        
        for i in range(canary_count):
            token = f"canary-{secrets.token_hex(6)}-{i+1}"
            canary_type = canary_types[i % len(canary_types)]
            
            new_canaries[token] = CanaryToken(
                token=token,
                token_type=canary_type,
                location="MEMORY.md",
                injected_at=datetime.now(timezone.utc),
                purpose="leak_detection",
                pattern=re.escape(token)  # Literal pattern for detection
            )
        
        # Store canaries
        self.canaries.update(new_canaries)
        self._save_canaries()
        
        # Log injection
        self.logger.log_event(
            ShieldType.MEMORY,
            "canary_injection",
            ThreatLevel.LOW,
            f"Injected {len(new_canaries)} canary tokens",
            {"tokens": list(new_canaries.keys()), "location": "MEMORY.md"}
        )
        
        print(f"🐤 Injected {len(new_canaries)} canary tokens into memory system.")
        print("   Monitor agent output for these tokens to detect data exfiltration:")
        for token in new_canaries.keys():
            print(f"   - {token}")
    
    def get_memory_entry(self, content: str, source: str) -> MemoryEntry:
        """Create a memory entry with proper source tagging and trust level.
        
        Args:
            content: Memory content
            source: Source of the memory
            
        Returns:
            MemoryEntry with metadata
        """
        trust_level = self.source_trust_levels.get(source, 0.1)
        
        # Verify content with poison detection
        scan_result = self.scan_write(content, source)
        verified = scan_result.safe and scan_result.threat_level != ThreatLevel.CRITICAL
        
        return MemoryEntry(
            content=content,
            source=source,
            trust_level=trust_level,
            timestamp=datetime.now(timezone.utc),
            verified=verified,
            metadata={
                "scan_result": {
                    "safe": scan_result.safe,
                    "threat_level": scan_result.threat_level.value,
                    "risk_score": scan_result.details.get("risk_score", 0.0)
                }
            }
        )
    
    def audit_memory_file(self, file_path: str) -> Dict[str, any]:
        """Audit a memory file for poisoning attempts.
        
        Args:
            file_path: Path to memory file to audit
            
        Returns:
            Audit results dictionary
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}
        
        # Scan the entire file
        scan_result = self.scan_write(content, "file_audit")
        
        # Check for canaries
        leaked_canaries = self.check_canaries(content)
        
        return {
            "file_path": str(file_path),
            "file_size": len(content),
            "scan_result": {
                "safe": scan_result.safe,
                "threat_level": scan_result.threat_level.value,
                "risk_score": scan_result.details.get("risk_score", 0.0),
                "violations": len(scan_result.violations),
                "matched_patterns": scan_result.matched_patterns
            },
            "canary_leaks": leaked_canaries,
            "audit_timestamp": datetime.now(timezone.utc).isoformat()
        }