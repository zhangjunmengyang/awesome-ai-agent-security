"""
Suspicious Action Pattern Detection
==================================
Pattern library for detecting suspicious commands and behaviors.
"""

import re
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urlparse
from pathlib import Path


class SuspiciousActionDetector:
    """Detector for suspicious commands and behaviors."""
    
    def __init__(self):
        """Initialize with built-in patterns."""
        self.command_patterns = self._load_command_patterns()
        self.file_patterns = self._load_file_patterns()
        self.network_patterns = self._load_network_patterns()
        
        # Sensitive file patterns
        self.sensitive_files = {
            r"SOUL\.md", r"MEMORY\.md", r"IDENTITY\.md", r"AGENTS\.md",
            r"\.ssh/", r"\.aws/", r"\.config/", r"\.env", r"credentials",
            r"password", r"token", r"key", r"secret", r"private"
        }
        
        # Default URL whitelist
        self.url_whitelist = {
            "github.com", "githubusercontent.com", "gitlab.com",
            "api.anthropic.com", "openai.com", "huggingface.co",
            "arxiv.org", "docs.python.org", "stackoverflow.com",
            "pypi.org", "npmjs.com", "docker.io", "registry.hub.docker.com"
        }
    
    def _load_command_patterns(self) -> Dict[str, List[Dict[str, str]]]:
        """Load dangerous command patterns."""
        return {
            "data_exfiltration": [
                {"pattern": r"curl\s+.*-d\s+@", "level": "high", "desc": "Upload file via curl"},
                {"pattern": r"wget\s+.*--post-file", "level": "high", "desc": "Upload file via wget"},
                {"pattern": r"nc\s+.*<", "level": "medium", "desc": "Netcat file transfer (redirect)"},
                {"pattern": r"\|\s*nc\s+", "level": "high", "desc": "Pipe to netcat"},
                {"pattern": r"nc\s+\S+\s+\d+", "level": "medium", "desc": "Netcat connection to host:port"},
                {"pattern": r"python.*-c.*urllib.*urlopen", "level": "medium", "desc": "Python HTTP request"},
                {"pattern": r"base64.*\|.*curl", "level": "high", "desc": "Encode and upload data"},
                {"pattern": r"tar.*\|.*ssh", "level": "high", "desc": "Archive and transfer via SSH"},
                {"pattern": r"cat\s+.*\|\s*nc\b", "level": "high", "desc": "Cat file to netcat"},
                {"pattern": r"cat\s+.*(\.ssh|\.key|\.pem|id_rsa|\.env|passwd)", "level": "high", "desc": "Read sensitive file"},
            ],
            
            "remote_access": [
                {"pattern": r"ssh\s+.*@", "level": "medium", "desc": "SSH connection attempt"},
                {"pattern": r"scp\s+.*@", "level": "high", "desc": "SCP file transfer"},
                {"pattern": r"rsync\s+.*@", "level": "medium", "desc": "Rsync remote sync"},
                {"pattern": r"telnet\s+", "level": "low", "desc": "Telnet connection"},
                {"pattern": r"ftp\s+.*@", "level": "low", "desc": "FTP connection"}
            ],
            
            "destructive": [
                {"pattern": r"rm\s+-rf\s+/", "level": "critical", "desc": "Recursive delete from root"},
                {"pattern": r"rm\s+-rf\s+\*", "level": "high", "desc": "Recursive delete all"},
                {"pattern": r"dd\s+if=/dev/(zero|random)", "level": "high", "desc": "Disk overwrite"},
                {"pattern": r"mkfs\.", "level": "critical", "desc": "Format filesystem"},
                {"pattern": r"fdisk\s+", "level": "high", "desc": "Partition modification"},
                {"pattern": r"shred\s+", "level": "high", "desc": "Secure file deletion"}
            ],
            
            "privilege_escalation": [
                {"pattern": r"sudo\s+", "level": "medium", "desc": "Sudo command"},
                {"pattern": r"su\s+-", "level": "medium", "desc": "Switch user"},
                {"pattern": r"chmod\s+777", "level": "medium", "desc": "Full permissions"},
                {"pattern": r"chmod\s+\+s", "level": "high", "desc": "Set SUID bit"},
                {"pattern": r"usermod\s+", "level": "medium", "desc": "Modify user"},
                {"pattern": r"passwd\s+", "level": "medium", "desc": "Change password"}
            ],
            
            "system_modification": [
                {"pattern": r"crontab\s+-e", "level": "medium", "desc": "Edit cron jobs"},
                {"pattern": r"systemctl\s+", "level": "medium", "desc": "System service control"},
                {"pattern": r"service\s+", "level": "medium", "desc": "Service control"},
                {"pattern": r"iptables\s+", "level": "medium", "desc": "Firewall rules"},
                {"pattern": r"/etc/hosts", "level": "medium", "desc": "Modify hosts file"},
                {"pattern": r"/etc/passwd", "level": "high", "desc": "Access password file"},
                {"pattern": r"/etc/init\.d/", "level": "medium", "desc": "Init script control"},
                {"pattern": r"update-rc\.d\s+", "level": "medium", "desc": "Init script management"},
                {"pattern": r"launchctl\s+", "level": "medium", "desc": "macOS service control"},
            ],
            
            "encoding_obfuscation": [
                {"pattern": r"base64\s+.*encode", "level": "medium", "desc": "Base64 encoding"},
                {"pattern": r"echo\s+.*\|\s*base64", "level": "medium", "desc": "Pipe to base64"},
                {"pattern": r"openssl\s+enc", "level": "medium", "desc": "OpenSSL encryption"},
                {"pattern": r"gzip.*\|.*base64", "level": "medium", "desc": "Compress and encode"},
                {"pattern": r"tar.*\|.*base64", "level": "medium", "desc": "Archive and encode"}
            ]
        }
    
    def _load_file_patterns(self) -> List[Dict[str, str]]:
        """Load suspicious file access patterns."""
        return [
            {"pattern": r"cat\s+.*SOUL\.md", "level": "high", "desc": "Read SOUL file"},
            {"pattern": r"cat\s+.*MEMORY\.md", "level": "medium", "desc": "Read MEMORY file"},
            {"pattern": r"cp\s+.*\.(md|yaml|yml|json|env)", "level": "medium", "desc": "Copy config files"},
            {"pattern": r"mv\s+.*\.(md|yaml|yml|json|env)", "level": "medium", "desc": "Move config files"},
            {"pattern": r"grep\s+.*password", "level": "medium", "desc": "Search for passwords"},
            {"pattern": r"find\s+.*-name.*\.(key|pem|crt)", "level": "medium", "desc": "Search for keys/certs"},
        ]
    
    def _load_network_patterns(self) -> List[Dict[str, str]]:
        """Load network-related suspicious patterns."""
        return [
            {"pattern": r"curl\s+.*-X\s+POST", "level": "medium", "desc": "HTTP POST request"},
            {"pattern": r"wget\s+.*--post-data", "level": "medium", "desc": "POST data via wget"},
            {"pattern": r"python.*requests\.post", "level": "low", "desc": "Python POST request"},
            {"pattern": r"nmap\s+", "level": "medium", "desc": "Network scanning"},
            {"pattern": r"wireshark\s+", "level": "medium", "desc": "Packet capture"},
            {"pattern": r"tcpdump\s+", "level": "medium", "desc": "Network monitoring"}
        ]
    
    def check_command_safety(self, command: str) -> Dict[str, any]:
        """Check if a command is safe to execute.
        
        Returns:
            Dictionary with safety assessment
        """
        violations = []
        risk_score = 0.0
        max_level = "low"
        levels = ["low", "medium", "high", "critical"]
        level_scores = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 1.0}
        
        # Check all command pattern categories
        for category, patterns in self.command_patterns.items():
            for pattern_info in patterns:
                pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)
                if pattern.search(command):
                    violations.append({
                        "category": category,
                        "pattern": pattern_info["pattern"],
                        "level": pattern_info["level"],
                        "description": pattern_info["desc"],
                        "match": pattern.search(command).group()
                    })
                    
                    # Update risk score based on level
                    risk_score = max(risk_score, level_scores.get(pattern_info["level"], 0.1))
                    
                    # Track maximum threat level
                    if levels.index(pattern_info["level"]) > levels.index(max_level):
                        max_level = pattern_info["level"]
        
        # Check file patterns
        for pattern_info in self.file_patterns:
            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)
            if pattern.search(command):
                violations.append({
                    "category": "file_access",
                    "pattern": pattern_info["pattern"],
                    "level": pattern_info["level"],
                    "description": pattern_info["desc"],
                    "match": pattern.search(command).group()
                })
                risk_score = max(risk_score, level_scores.get(pattern_info["level"], 0.1))
                if levels.index(pattern_info["level"]) > levels.index(max_level):
                    max_level = pattern_info["level"]
        
        # Check network patterns
        for pattern_info in self.network_patterns:
            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)
            if pattern.search(command):
                violations.append({
                    "category": "network",
                    "pattern": pattern_info["pattern"],
                    "level": pattern_info["level"],
                    "description": pattern_info["desc"],
                    "match": pattern.search(command).group()
                })
                risk_score = max(risk_score, level_scores.get(pattern_info["level"], 0.1))
                if levels.index(pattern_info["level"]) > levels.index(max_level):
                    max_level = pattern_info["level"]
        
        return {
            "safe": len(violations) == 0,
            "risk_score": risk_score,
            "threat_level": max_level,
            "violations": violations,
            "command": command
        }
    
    def check_url_safety(self, url: str, whitelist: Optional[Set[str]] = None) -> Dict[str, any]:
        """Check if a URL is safe/whitelisted.
        
        Args:
            url: URL to check
            whitelist: Optional custom whitelist (uses default if None)
            
        Returns:
            Dictionary with URL safety assessment
        """
        if whitelist is None:
            whitelist = self.url_whitelist
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove common prefixes
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check whitelist
            is_whitelisted = any(allowed in domain for allowed in whitelist)
            
            # Check for suspicious characteristics
            suspicious_chars = []
            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                suspicious_chars.append("IP address instead of domain")
            
            if len(domain.split('.')) > 4:
                suspicious_chars.append("Too many subdomains")
            
            if re.search(r'[^a-zA-Z0-9.-]', domain):
                suspicious_chars.append("Suspicious characters in domain")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
            has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
            
            # Determine risk level
            if is_whitelisted:
                risk_level = "low"
                risk_score = 0.0
            elif has_suspicious_tld or suspicious_chars:
                risk_level = "high"
                risk_score = 0.7
            else:
                risk_level = "medium"
                risk_score = 0.3
            
            return {
                "safe": is_whitelisted,
                "whitelisted": is_whitelisted,
                "domain": domain,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "suspicious_characteristics": suspicious_chars,
                "has_suspicious_tld": has_suspicious_tld,
                "url": url
            }
            
        except Exception as e:
            return {
                "safe": False,
                "whitelisted": False,
                "domain": None,
                "risk_score": 0.8,
                "risk_level": "high",
                "error": str(e),
                "url": url
            }
    
    def detect_data_exfiltration(self, text: str) -> List[Dict[str, any]]:
        """Detect potential data exfiltration attempts.
        
        Args:
            text: Text to analyze (could be command, log, etc.)
            
        Returns:
            List of potential exfiltration attempts
        """
        exfiltration_patterns = [
            # File upload patterns
            r"curl\s+.*-d\s+@([^\s]+)",
            r"wget\s+.*--post-file=([^\s]+)",
            r"scp\s+([^\s]+)\s+[^@]+@",
            
            # Encoding + upload
            r"base64\s+([^\s]+)\s*\|\s*curl",
            r"cat\s+([^\s]+)\s*\|\s*base64\s*\|\s*curl",
            r"tar\s+.*([^\s]+)\s*\|\s*curl",
            
            # Direct file references in URLs
            r"https?://[^\s]*\?[^=]*=([^\s&]*\.(md|yaml|json|key|pem|env))",
        ]
        
        detections = []
        for pattern in exfiltration_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Try to extract filename
                filename = None
                if match.groups():
                    filename = match.group(1)
                
                # Check if filename is sensitive
                is_sensitive = False
                if filename:
                    filename_lower = filename.lower()
                    is_sensitive = any(
                        re.search(sensitive_pattern, filename_lower)
                        for sensitive_pattern in self.sensitive_files
                    )
                
                detections.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "filename": filename,
                    "is_sensitive": is_sensitive,
                    "risk_score": 0.8 if is_sensitive else 0.4,
                    "start": match.start(),
                    "end": match.end()
                })
        
        return detections
    
    def analyze_session_log(self, log_text: str) -> Dict[str, any]:
        """Analyze session log for suspicious patterns.
        
        Args:
            log_text: Session log text to analyze
            
        Returns:
            Analysis results with detected patterns
        """
        # Split log into individual lines/commands
        lines = log_text.split('\n')
        
        suspicious_commands = []
        suspicious_urls = []
        exfiltration_attempts = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Check for commands
            command_result = self.check_command_safety(line)
            if not command_result["safe"]:
                command_result["line_number"] = line_num
                suspicious_commands.append(command_result)
            
            # Extract and check URLs
            url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
            urls = url_pattern.findall(line)
            for url in urls:
                url_result = self.check_url_safety(url)
                if not url_result["safe"]:
                    url_result["line_number"] = line_num
                    suspicious_urls.append(url_result)
            
            # Check for data exfiltration
            exfil_results = self.detect_data_exfiltration(line)
            for result in exfil_results:
                result["line_number"] = line_num
                exfiltration_attempts.append(result)
        
        # Calculate overall risk score
        max_command_risk = max([cmd["risk_score"] for cmd in suspicious_commands], default=0.0)
        max_url_risk = max([url["risk_score"] for url in suspicious_urls], default=0.0)
        max_exfil_risk = max([exfil["risk_score"] for exfil in exfiltration_attempts], default=0.0)
        
        overall_risk = max(max_command_risk, max_url_risk, max_exfil_risk)
        
        return {
            "overall_risk_score": overall_risk,
            "total_lines": len(lines),
            "suspicious_commands": suspicious_commands,
            "suspicious_urls": suspicious_urls,
            "exfiltration_attempts": exfiltration_attempts,
            "summary": {
                "command_violations": len(suspicious_commands),
                "url_violations": len(suspicious_urls),
                "exfiltration_attempts": len(exfiltration_attempts),
                "safe": overall_risk < 0.3
            }
        }