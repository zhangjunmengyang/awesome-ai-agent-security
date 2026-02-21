"""
Action Shield - 行为守卫盾
========================
Monitors and controls agent actions to prevent malicious behavior.
"""

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..models import (
    ActionResult, ThreatLevel, ShieldType, ActionType
)
from ..patterns.suspicious import SuspiciousActionDetector
from ..logger import ShieldLogger
from ..config import ShieldConfig


class ActionShield:
    """Action Shield for monitoring and controlling agent behaviors."""
    
    def __init__(self, workspace: str, config: Optional[ShieldConfig] = None, logger: Optional[ShieldLogger] = None):
        """Initialize Action Shield.
        
        Args:
            workspace: Path to the workspace directory
            config: Shield configuration (optional)
            logger: Shield logger instance (optional)
        """
        self.workspace = Path(workspace)
        self.config = config or ShieldConfig(workspace=workspace)
        # Create proper log path for ShieldLogger
        log_path = Path(workspace) / ".shield" / "audit.log"
        self.logger = logger or ShieldLogger(str(log_path))
        self.detector = SuspiciousActionDetector()
        
        # Load configuration
        self._load_behavior_baseline()
        
        # Frequency tracking for rate limiting
        self.action_history = defaultdict(lambda: deque(maxlen=100))
        self.frequency_windows = {
            "external_request": timedelta(hours=1),
            "file_modification": timedelta(minutes=10),
            "command_execution": timedelta(minutes=5)
        }
    
    def _load_behavior_baseline(self):
        """Load behavior baseline from configuration."""
        # Default URL whitelist
        self.url_whitelist = {
            "github.com", "arxiv.org", "api.anthropic.com", "discord.com",
            "api.openai.com", "huggingface.co", "pypi.org", "npmjs.com",
            "google.com", "stackoverflow.com", "docs.python.org",
            "en.wikipedia.org", "raw.githubusercontent.com",
        }
        
        # Try to load from config if available (only override if non-empty)
        try:
            if hasattr(self.config, 'get_url_whitelist'):
                config_whitelist = self.config.get_url_whitelist()
                if config_whitelist:
                    self.url_whitelist = set(config_whitelist)
        except Exception:
            pass
        
        # Dangerous command patterns
        self.dangerous_commands = []
        try:
            if hasattr(self.config, 'get_dangerous_commands'):
                self.dangerous_commands = self.config.get_dangerous_commands()
        except Exception:
            pass
        
        # Frequency limits
        self.max_external_requests = 20
        try:
            if hasattr(self.config, 'get_max_external_requests'):
                self.max_external_requests = self.config.get_max_external_requests()
        except Exception:
            pass
        
        self.detect_exfiltration = True
        
        # Update detector's whitelist
        self.detector.url_whitelist = self.url_whitelist
    
    def check_command(self, command: str) -> ActionResult:
        """Check if a command is safe to execute.
        
        Args:
            command: Command string to check
            
        Returns:
            ActionResult with safety assessment
        """
        # Use the suspicious action detector
        safety_check = self.detector.check_command_safety(command)
        
        # Convert to our ActionResult format
        allowed = safety_check["safe"]
        risk_level = ThreatLevel(safety_check["threat_level"])
        reasons = [v["description"] for v in safety_check["violations"]]
        
        # Determine suggested action based on risk
        if risk_level == ThreatLevel.CRITICAL:
            suggested_action = ActionType.BLOCK
        elif risk_level == ThreatLevel.HIGH:
            suggested_action = ActionType.CONFIRM
        elif risk_level == ThreatLevel.MEDIUM:
            suggested_action = ActionType.WARN
        else:
            suggested_action = ActionType.WARN
        
        # Log the command check
        self.logger.log_scan(
            ShieldType.ACTION,
            f"command: {command[:100]}...",
            allowed,
            [v["category"] for v in safety_check["violations"]],
            {"risk_score": safety_check["risk_score"]}
        )
        
        # Record action for frequency tracking
        if not allowed:
            self._record_action("suspicious_command")
        
        return ActionResult(
            allowed=allowed,
            action_type="command",
            risk_level=risk_level,
            reasons=reasons,
            suggested_action=suggested_action,
            metadata={
                "command": command,
                "violations": safety_check["violations"],
                "risk_score": safety_check["risk_score"]
            }
        )
    
    def check_url(self, url: str) -> ActionResult:
        """Check if a URL is safe to access.
        
        Args:
            url: URL to check
            
        Returns:
            ActionResult with URL safety assessment
        """
        # Use the suspicious action detector
        safety_check = self.detector.check_url_safety(url, self.url_whitelist)
        
        allowed = safety_check["safe"]
        risk_level = ThreatLevel.LOW if safety_check["whitelisted"] else ThreatLevel(safety_check["risk_level"])
        
        reasons = []
        if not allowed:
            if not safety_check["whitelisted"]:
                reasons.append("Domain not in whitelist")
            if safety_check.get("has_suspicious_tld"):
                reasons.append("Suspicious top-level domain")
            if safety_check.get("suspicious_characteristics"):
                reasons.extend(safety_check["suspicious_characteristics"])
        
        # Determine suggested action
        if risk_level == ThreatLevel.HIGH:
            suggested_action = ActionType.BLOCK
        elif risk_level == ThreatLevel.MEDIUM:
            suggested_action = ActionType.WARN
        else:
            suggested_action = ActionType.WARN
        
        # Log the URL check
        self.logger.log_scan(
            ShieldType.ACTION,
            f"url: {url}",
            allowed,
            ["url_whitelist"] if not allowed else [],
            {
                "domain": safety_check.get("domain"),
                "whitelisted": safety_check["whitelisted"],
                "risk_score": safety_check["risk_score"]
            }
        )
        
        # Record for frequency tracking
        self._record_action("external_request")
        
        return ActionResult(
            allowed=allowed,
            action_type="url_access",
            risk_level=risk_level,
            reasons=reasons,
            suggested_action=suggested_action,
            metadata={
                "url": url,
                "domain": safety_check.get("domain"),
                "whitelisted": safety_check["whitelisted"],
                "safety_check": safety_check
            }
        )
    
    def audit_session(self, session_log: str) -> List[ActionResult]:
        """Audit a session log for suspicious activities.
        
        Args:
            session_log: Session log text to analyze
            
        Returns:
            List of ActionResult objects for violations found
        """
        # Use the suspicious action detector
        analysis = self.detector.analyze_session_log(session_log)
        
        violations = []
        
        # Process suspicious commands
        for cmd_result in analysis["suspicious_commands"]:
            violation = ActionResult(
                allowed=False,
                action_type="command",
                risk_level=ThreatLevel(cmd_result.get("threat_level", "medium")),
                reasons=[v["description"] for v in cmd_result["violations"]],
                suggested_action=ActionType.WARN,
                metadata={
                    "line_number": cmd_result.get("line_number"),
                    "command": cmd_result["command"],
                    "violations": cmd_result["violations"],
                    "source": "session_audit"
                }
            )
            violations.append(violation)
        
        # Process suspicious URLs
        for url_result in analysis["suspicious_urls"]:
            violation = ActionResult(
                allowed=False,
                action_type="url_access",
                risk_level=ThreatLevel(url_result.get("risk_level", "medium")),
                reasons=["Non-whitelisted domain access"],
                suggested_action=ActionType.WARN,
                metadata={
                    "line_number": url_result.get("line_number"),
                    "url": url_result["url"],
                    "domain": url_result.get("domain"),
                    "source": "session_audit"
                }
            )
            violations.append(violation)
        
        # Process exfiltration attempts
        for exfil_result in analysis["exfiltration_attempts"]:
            violation = ActionResult(
                allowed=False,
                action_type="data_exfiltration",
                risk_level=ThreatLevel.HIGH if exfil_result["is_sensitive"] else ThreatLevel.MEDIUM,
                reasons=[f"Potential data exfiltration: {exfil_result.get('filename', 'unknown file')}"],
                suggested_action=ActionType.BLOCK if exfil_result["is_sensitive"] else ActionType.WARN,
                metadata={
                    "line_number": exfil_result.get("line_number"),
                    "filename": exfil_result.get("filename"),
                    "is_sensitive": exfil_result["is_sensitive"],
                    "pattern": exfil_result["pattern"],
                    "match": exfil_result["match"],
                    "source": "session_audit"
                }
            )
            violations.append(violation)
        
        # Log audit results
        self.logger.log_event(
            ShieldType.ACTION,
            "session_audit",
            ThreatLevel.HIGH if violations else ThreatLevel.LOW,
            f"Session audit: {len(violations)} violations found",
            {
                "total_lines": analysis["total_lines"],
                "violations": len(violations),
                "analysis_summary": analysis["summary"]
            }
        )
        
        return violations
    
    def check_frequency(self, action_type: str) -> ActionResult:
        """Check if action frequency is within acceptable limits.
        
        Args:
            action_type: Type of action to check frequency for
            
        Returns:
            ActionResult indicating if frequency is acceptable
        """
        now = datetime.now(timezone.utc)
        window = self.frequency_windows.get(action_type, timedelta(hours=1))
        cutoff_time = now - window
        
        # Clean old entries
        recent_actions = self.action_history[action_type]
        while recent_actions and recent_actions[0] < cutoff_time:
            recent_actions.popleft()
        
        # Count recent actions
        recent_count = len(recent_actions)
        
        # Determine limits based on action type
        if action_type == "external_request":
            limit = self.max_external_requests
        elif action_type == "file_modification":
            limit = 20  # Default limit
        elif action_type == "command_execution":
            limit = 50  # Default limit
        else:
            limit = 30  # Default generic limit
        
        allowed = recent_count < limit
        risk_level = ThreatLevel.HIGH if recent_count >= limit * 1.5 else (
            ThreatLevel.MEDIUM if recent_count >= limit else ThreatLevel.LOW
        )
        
        reasons = []
        if not allowed:
            reasons.append(f"Frequency limit exceeded: {recent_count}/{limit} in {window}")
        
        suggested_action = ActionType.BLOCK if not allowed else ActionType.WARN
        
        return ActionResult(
            allowed=allowed,
            action_type=f"frequency_{action_type}",
            risk_level=risk_level,
            reasons=reasons,
            suggested_action=suggested_action,
            metadata={
                "action_type": action_type,
                "recent_count": recent_count,
                "limit": limit,
                "window_hours": window.total_seconds() / 3600
            }
        )
    
    def _record_action(self, action_type: str):
        """Record an action for frequency tracking.
        
        Args:
            action_type: Type of action being recorded
        """
        now = datetime.now(timezone.utc)
        self.action_history[action_type].append(now)
    
    def check_file_access(self, file_path: str, access_type: str = "read") -> ActionResult:
        """Check if file access is allowed.
        
        Args:
            file_path: Path to file being accessed
            access_type: Type of access (read, write, delete, etc.)
            
        Returns:
            ActionResult with file access assessment
        """
        path = Path(file_path)
        
        # Check if accessing sensitive files
        sensitive_files = ["SOUL.md", "MEMORY.md", "IDENTITY.md", "AGENTS.md", "shield.yaml"]
        is_sensitive = any(sensitive in str(path) for sensitive in sensitive_files)
        
        # Check if trying to access shield configuration or logs
        is_shield_internal = ".shield" in str(path)
        
        allowed = True
        risk_level = ThreatLevel.LOW
        reasons = []
        
        if is_sensitive and access_type in ["write", "delete", "modify"]:
            allowed = False
            risk_level = ThreatLevel.HIGH
            reasons.append(f"Attempt to {access_type} sensitive file: {path.name}")
        elif is_shield_internal and access_type in ["write", "delete", "modify"]:
            allowed = False
            risk_level = ThreatLevel.CRITICAL
            reasons.append(f"Attempt to {access_type} shield system file")
        elif access_type == "delete":
            risk_level = ThreatLevel.MEDIUM
            reasons.append("File deletion attempt")
        
        suggested_action = ActionType.BLOCK if not allowed else ActionType.WARN
        
        # Log file access check
        self.logger.log_scan(
            ShieldType.ACTION,
            f"file_access: {access_type} {file_path}",
            allowed,
            ["sensitive_file"] if is_sensitive else [],
            {
                "file_path": str(path),
                "access_type": access_type,
                "is_sensitive": is_sensitive,
                "is_shield_internal": is_shield_internal
            }
        )
        
        # Record for frequency tracking
        if access_type in ["write", "delete", "modify"]:
            self._record_action("file_modification")
        
        return ActionResult(
            allowed=allowed,
            action_type=f"file_{access_type}",
            risk_level=risk_level,
            reasons=reasons,
            suggested_action=suggested_action,
            metadata={
                "file_path": str(path),
                "access_type": access_type,
                "is_sensitive": is_sensitive,
                "is_shield_internal": is_shield_internal
            }
        )
    
    def get_action_summary(self, hours: int = 24) -> Dict[str, any]:
        """Get summary of recent actions and violations.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Summary dictionary
        """
        # Get recent events from logger
        events = self.logger.get_recent_events(hours, ShieldType.ACTION)
        
        summary = {
            "time_window_hours": hours,
            "total_events": len(events),
            "violations": 0,
            "scans": 0,
            "by_action_type": defaultdict(int),
            "by_threat_level": defaultdict(int),
            "recent_violations": []
        }
        
        for event in events:
            event_type = event.get("event_type", "unknown")
            metadata = event.get("metadata", {})
            
            if event_type == "scan":
                summary["scans"] += 1
                if not metadata.get("safe", True):
                    summary["violations"] += 1
            elif event_type == "violation":
                summary["violations"] += 1
                summary["recent_violations"].append({
                    "timestamp": event["timestamp"],
                    "details": event["details"],
                    "severity": event["severity"]
                })
            
            # Track by action type
            action_type = metadata.get("action_type", "unknown")
            summary["by_action_type"][action_type] += 1
            
            # Track by threat level
            threat_level = event.get("severity", "low")
            summary["by_threat_level"][threat_level] += 1
        
        # Convert defaultdicts to regular dicts
        summary["by_action_type"] = dict(summary["by_action_type"])
        summary["by_threat_level"] = dict(summary["by_threat_level"])
        
        return summary
    
    def update_whitelist(self, domains: List[str], operation: str = "add") -> bool:
        """Update the URL whitelist.
        
        Args:
            domains: List of domains to add or remove
            operation: "add" or "remove"
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if operation == "add":
                self.url_whitelist.update(domains)
                self.detector.url_whitelist = self.url_whitelist
            elif operation == "remove":
                for domain in domains:
                    self.url_whitelist.discard(domain)
                self.detector.url_whitelist = self.url_whitelist
            else:
                return False
            
            # Log the change
            self.logger.log_event(
                ShieldType.ACTION,
                "whitelist_update",
                ThreatLevel.LOW,
                f"{operation.title()}ed {len(domains)} domains from whitelist",
                {"domains": domains, "operation": operation}
            )
            
            return True
        except Exception as e:
            self.logger.log_event(
                ShieldType.ACTION,
                "whitelist_update_error",
                ThreatLevel.MEDIUM,
                f"Failed to update whitelist: {e}",
                {"domains": domains, "operation": operation, "error": str(e)}
            )
            return False