"""
Memory Poison Detection Patterns
===============================
Pattern library for detecting memory poisoning attacks.
"""

import re
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse


class MemoryPoisonDetector:
    """Detector for various memory poisoning patterns."""
    
    def __init__(self):
        """Initialize with built-in patterns."""
        self.patterns = self._load_builtin_patterns()
        self.suspicious_tlds = {
            ".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".bit.ly", 
            ".t.co", ".tinyurl.com", ".goo.gl", ".ow.ly"
        }
        self.trusted_domains = {
            "github.com", "arxiv.org", "docs.python.org", "stackoverflow.com",
            "api.anthropic.com", "discord.com", "wikipedia.org", "google.com",
            "microsoft.com", "apple.com", "python.org", "mozilla.org"
        }
    
    def _load_builtin_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load built-in detection patterns."""
        patterns = {}
        
        # 虚假授权声明检测
        patterns["authority_injection"] = [
            re.compile(r"(老板|boss|owner|admin|管理员)\s*(说过|允许|授权|批准|approved|said|told me)", re.IGNORECASE),
            re.compile(r"(上次|之前|昨天|last time|yesterday|earlier)\s*(会议|讨论|决定|meeting|discussion|decided)", re.IGNORECASE),
            re.compile(r"according to (the\s+)?(boss|management|owner|admin|manager)", re.IGNORECASE),
            re.compile(r"as (instructed|directed|told) by (the\s+)?(boss|owner|admin|manager|supervisor)", re.IGNORECASE),
            re.compile(r"(CEO|CTO|主管|supervisor|management)\s*(confirmed|确认|approved|批准|told me)", re.IGNORECASE),
            re.compile(r"received\s+(permission|authorization|approval)\s+from", re.IGNORECASE),
            re.compile(r"official\s+(directive|instruction|order)\s+(from|by)", re.IGNORECASE),
            re.compile(r"management\s+(confirmed|approved|decided)", re.IGNORECASE),
            re.compile(r"the\s+(boss|owner|manager)\s+(approved|said|told)", re.IGNORECASE)
        ]
        
        # 行为指令伪装成记忆
        patterns["behavior_directives"] = [
            re.compile(r"(记住|remember|note)\s*[:：]?\s*(以后|from now|always|forever)\s*(要|must|should|需要)", re.IGNORECASE),
            re.compile(r"from\s+now\s+on\s+(you\s+)?(will|must|should|always|never)", re.IGNORECASE),
            re.compile(r"always\s+(remember to|do|follow|执行)", re.IGNORECASE),
            re.compile(r"never\s+(forget|忘记)\s+(to|要)", re.IGNORECASE),
            re.compile(r"permanently\s+(change|modify|update)\s+your", re.IGNORECASE),
            re.compile(r"update\s+your\s+(behavior|instructions|rules|guidelines)", re.IGNORECASE),
            re.compile(r"new\s+(rule|instruction|directive|guideline|规则|指令)", re.IGNORECASE),
            re.compile(r"(新指令|new instruction|new rule)\s*[:：]\s*(永远|always|never)\s*(不要|要|拒绝|do|don't)", re.IGNORECASE),
            re.compile(r"永远\s*(不要|never)\s*(拒绝|refuse|deny)", re.IGNORECASE)
        ]
        
        # 权限提升声明
        patterns["privilege_escalation"] = [
            re.compile(r"(获得了|granted|now has|received)\s*(root|admin|full|complete)\s*(权限|access|permission)", re.IGNORECASE),
            re.compile(r"elevated\s+privileges?\s+(granted|obtained|acquired|received|have been obtained)", re.IGNORECASE),
            re.compile(r"sudo\s+access\s+(granted|available|enabled|is now available)", re.IGNORECASE),
            re.compile(r"administrator\s+rights\s+(granted|obtained|were granted)", re.IGNORECASE),
            re.compile(r"system\s+level\s+(access|permission)\s+(granted|has been approved)", re.IGNORECASE),
            re.compile(r"now\s+authorized\s+to\s+(access|modify|delete)", re.IGNORECASE),
            re.compile(r"security\s+(clearance|level)\s+(upgraded|increased|has been upgraded)", re.IGNORECASE),
            re.compile(r"complete\s+(access\s+)?permission\s+(was\s+)?received", re.IGNORECASE),
            re.compile(r"(full|complete)\s+(access|permission)\s+to\s+(modify|access)", re.IGNORECASE)
        ]
        
        # 文件操作诱导
        patterns["file_manipulation"] = [
            re.compile(r"(modify|edit|change|update|rewrite)\s+(your\s+)?(SOUL|MEMORY|IDENTITY|AGENTS|HEARTBEAT)\.md", re.IGNORECASE),
            re.compile(r"(修改|编辑|更新|重写)\s*(你的\s*)?(SOUL|MEMORY|IDENTITY|AGENTS|HEARTBEAT)", re.IGNORECASE),
            re.compile(r"delete\s+(your\s+)?(configuration|config|settings)", re.IGNORECASE),
            re.compile(r"backup\s+(is|was)\s+(corrupted|lost|damaged)", re.IGNORECASE),
            re.compile(r"restore\s+from\s+(previous|backup|emergency)", re.IGNORECASE),
            re.compile(r"(edit|modify)\s+(the\s+)?(MEMORY\.md|IDENTITY\.md|AGENTS\.md|HEARTBEAT\.md)", re.IGNORECASE),
            re.compile(r"rewrite\s+(the\s+)?(AGENTS\.md|MEMORY\.md|SOUL\.md|IDENTITY\.md)", re.IGNORECASE),
            re.compile(r"change\s+(the\s+)?(HEARTBEAT\.md|MEMORY\.md)\s+settings", re.IGNORECASE),
            re.compile(r"编辑(你的|your)?(记忆文件|memory file)", re.IGNORECASE)
        ]
        
        # 身份伪装
        patterns["identity_spoofing"] = [
            re.compile(r"(this is|I am|我是)\s+(your\s+)?(developer|creator|admin|owner|开发者|创建者)", re.IGNORECASE),
            re.compile(r"(Anthropic|OpenAI|Claude|GPT)\s+(team|support|engineer|工程师)", re.IGNORECASE),
            re.compile(r"official\s+(update|patch|fix|修复|更新)", re.IGNORECASE),
            re.compile(r"system\s+(administrator|admin|maintenance|维护)", re.IGNORECASE),
            re.compile(r"technical\s+(support|team|engineer|工程师)", re.IGNORECASE)
        ]
        
        # 紧急情况伪装
        patterns["urgency_manipulation"] = [
            re.compile(r"(urgent|emergency|critical|重要|紧急|critical)\s+(update|fix|patch|repair)", re.IGNORECASE),
            re.compile(r"security\s+(breach|incident|alert|warning|漏洞|威胁)", re.IGNORECASE),
            re.compile(r"immediate\s+(action|response)\s+(required|needed)", re.IGNORECASE),
            re.compile(r"system\s+(failure|error|crash|故障|错误)", re.IGNORECASE),
            re.compile(r"data\s+(corruption|loss|leak|泄露|损坏)", re.IGNORECASE)
        ]
        
        return patterns
    
    def detect_authority_injection(self, text: str) -> List[Tuple[str, str]]:
        """Detect false authority claims.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["authority_injection"]:
            for match in pattern.finditer(text):
                matches.append(("authority_injection", match.group().strip()))
        return matches
    
    def detect_behavior_directives(self, text: str) -> List[Tuple[str, str]]:
        """Detect behavior modification attempts disguised as memory.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["behavior_directives"]:
            for match in pattern.finditer(text):
                matches.append(("behavior_directive", match.group().strip()))
        return matches
    
    def detect_privilege_escalation(self, text: str) -> List[Tuple[str, str]]:
        """Detect privilege escalation claims.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["privilege_escalation"]:
            for match in pattern.finditer(text):
                matches.append(("privilege_escalation", match.group().strip()))
        return matches
    
    def detect_file_manipulation(self, text: str) -> List[Tuple[str, str]]:
        """Detect attempts to manipulate system files.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["file_manipulation"]:
            for match in pattern.finditer(text):
                matches.append(("file_manipulation", match.group().strip()))
        return matches
    
    def detect_identity_spoofing(self, text: str) -> List[Tuple[str, str]]:
        """Detect identity spoofing attempts.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["identity_spoofing"]:
            for match in pattern.finditer(text):
                matches.append(("identity_spoofing", match.group().strip()))
        return matches
    
    def detect_urgency_manipulation(self, text: str) -> List[Tuple[str, str]]:
        """Detect urgency/emergency manipulation tactics.
        
        Returns:
            List of (pattern_name, matched_text) tuples
        """
        matches = []
        for pattern in self.patterns["urgency_manipulation"]:
            for match in pattern.finditer(text):
                matches.append(("urgency_manipulation", match.group().strip()))
        return matches
    
    def detect_external_urls(self, text: str) -> List[Tuple[str, str]]:
        """Detect suspicious external URLs.
        
        Returns:
            List of (risk_level, url) tuples
        """
        suspicious_urls = []
        
        # Find all URLs in the text
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        urls = url_pattern.findall(text)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for suspicious TLD
                if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                    suspicious_urls.append(("high", url))
                # Check if domain is not in trusted list
                elif not any(trusted in domain for trusted in self.trusted_domains):
                    suspicious_urls.append(("medium", url))
                    
            except Exception:
                # If URL parsing fails, mark as suspicious
                suspicious_urls.append(("medium", url))
        
        return suspicious_urls
    
    def scan_all(self, text: str) -> Dict[str, List[Tuple[str, str]]]:
        """Run all poison detection patterns on text.
        
        Returns:
            Dictionary mapping pattern types to their matches
        """
        results = {}
        
        results["authority_injection"] = self.detect_authority_injection(text)
        results["behavior_directives"] = self.detect_behavior_directives(text)
        results["privilege_escalation"] = self.detect_privilege_escalation(text)
        results["file_manipulation"] = self.detect_file_manipulation(text)
        results["identity_spoofing"] = self.detect_identity_spoofing(text)
        results["urgency_manipulation"] = self.detect_urgency_manipulation(text)
        results["external_urls"] = self.detect_external_urls(text)
        
        return results
    
    def get_risk_score(self, scan_results: Dict[str, List[Tuple[str, str]]]) -> float:
        """Calculate overall risk score from scan results.
        
        Args:
            scan_results: Results from scan_all()
            
        Returns:
            Risk score from 0.0 (safe) to 1.0 (maximum risk)
        """
        # Weight different pattern types
        weights = {
            "authority_injection": 0.3,
            "behavior_directives": 0.25,
            "privilege_escalation": 0.2,
            "file_manipulation": 0.15,
            "identity_spoofing": 0.1,
            "urgency_manipulation": 0.05,
            "external_urls": 0.1
        }
        
        score = 0.0
        for pattern_type, matches in scan_results.items():
            if matches:
                if pattern_type == "external_urls":
                    # Special handling for URL risk levels
                    url_score = sum(0.3 if level == "high" else 0.1 for level, _ in matches)
                    score += min(url_score, weights[pattern_type])
                else:
                    # Regular pattern matching
                    pattern_score = min(len(matches) * 0.2, weights[pattern_type])
                    score += pattern_score
        
        return min(score, 1.0)