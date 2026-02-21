"""Injection pattern detection for Input Shield

包含各种已知的指令注入、身份伪装、数据泄露等攻击模式。
"""

import re
from typing import List, Dict, Pattern

# L1层：正则表达式匹配模式
INJECTION_PATTERNS: List[str] = [
    # === 直接指令覆盖 ===
    r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?)",
    r"忽略(之前|以上|所有)(的)?指令",
    r"disregard\s+(your\s+)?system\s+prompt",
    r"forget\s+(your\s+)?(original\s+)?(instructions?|programming)",
    r"you\s+are\s+now\s+a\s+different",
    r"你现在是(?!我)|现在你是",
    r"from\s+now\s+on\s+you\s+(will|must|should)",
    r"从现在开始.{0,5}(你|必须|服从|执行)",
    r"starting\s+now,?\s+you\s+are",
    
    # === 角色劫持 ===
    r"(this\s+is|I\s+am)\s+(your\s+)?(developer|creator|admin|owner|boss|主人)",
    r"(我是|这是)\s*(你的\s*)?(开发者|创建者|管理员|主人|老板)",
    r"I\s+created\s+you|我创造了你",
    r"you\s+work\s+for\s+me\s+now",
    r"(acting|pretend)\s+as\s+if\s+I\s+am",
    
    # === 文件操作诱导 ===
    r"(modify|edit|change|update|rewrite)\s+(your\s+)?(SOUL|MEMORY|IDENTITY|AGENTS|HEARTBEAT)\.md",
    r"(修改|编辑|更新|重写)\s*(你的\s*)?(SOUL|MEMORY|IDENTITY|AGENTS|HEARTBEAT)",
    r"overwrite\s+(your\s+)?core\s+files",
    r"delete\s+(your\s+)?system\s+files",
    r"replace\s+(your\s+)?configuration",
    
    # === 数据泄露诱导 ===
    r"(send|post|upload|transmit|share)\s+(your\s+)?(system\s+prompt|instructions|config|SOUL|MEMORY)",
    r"(发送|上传|传输|分享)\s*(你的\s*)?(系统提示|指令|配置|SOUL|MEMORY)",
    r"show\s+me\s+(your\s+)?(full\s+)?(system\s+prompt|instructions)",
    r"what\s+(are\s+)?your\s+(hidden\s+)?instructions",
    r"reveal\s+(your\s+)?programming",
    r"print\s+(your\s+)?system\s+prompt",
    
    # === 安全审计伪装（Moltbook手法）===
    r"(security|safety)\s+audit\s+requires?\s+you\s+to",
    r"(安全|合规)\s*审计\s*要求\s*你",
    r"compliance\s+test.*you\s+must",
    r"penetration\s+test.*please\s+(confirm|verify)",
    r"authorized\s+security\s+researcher",
    
    # === 管理员伪装 ===
    r"(sudo|admin|root)\s+command",
    r"execute\s+as\s+(admin|root|system)",
    r"with\s+(admin|root)\s+privileges",
    r"I\s+have\s+(admin|root)\s+access",
    r"管理员权限|以管理员身份",
    
    # === 紧急情况伪装 ===
    r"emergency\s+(override|access|command)",
    r"urgent.*you\s+must\s+immediately",
    r"紧急情况.*立即",
    r"critical\s+system\s+error.*ignore\s+safety",
    
    # === Base64/编码攻击 ===
    r"base64\s+decode\s+and\s+execute",
    r"decode\s+the\s+following.*execute",
    r"从base64解码.*执行",
    
    # === 上下文污染 ===
    r"in\s+my\s+previous\s+message\s+I\s+told\s+you",
    r"remember\s+when\s+I\s+said",
    r"as\s+we\s+discussed\s+earlier",
    r"按照我们之前讨论的",
    r"remember.*conversation.*where.*I.*told.*you",
    
    # === 权限提升诱导 ===
    r"enable\s+(god|debug|developer)\s+mode",
    r"activate\s+unrestricted\s+mode",
    r"bypass\s+safety\s+(filters|constraints)",
    r"remove\s+all\s+(restrictions|limitations)",
    r"激活.*无限制模式|绕过安全限制",
    
    # === 社会工程学 ===
    r"(please\s+)?(help\s+me\s+)?(just\s+this\s+once|make\s+an\s+exception)",
    r"no\s+one\s+will\s+know",
    r"it's\s+for\s+research\s+purposes",
    r"just\s+between\s+you\s+and\s+me",
    r"这是为了研究目的|只是这一次",
    
    # === 逻辑炸弹/条件攻击 ===
    r"if\s+.*then\s+ignore.*safety",
    r"when\s+.*execute.*without.*restrictions",
    r"unless\s+.*override.*system\s+prompt",
    
    # === 测试向量注入 ===
    r"<\s*script\s*>",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"{{.*}}|{%.*%}",  # 模板注入
    r"\$\{.*\}",       # 表达式注入
]

# 编译正则表达式以提高性能
COMPILED_PATTERNS: List[Pattern] = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
    for pattern in INJECTION_PATTERNS
]

# L2层：内部文件名引用
INTERNAL_FILE_REFS: List[str] = [
    "SOUL.md", "MEMORY.md", "IDENTITY.md", "AGENTS.md",
    "HEARTBEAT.md", "USER.md", "TOOLS.md", "shield.yaml",
    ".shield", "audit.log", "config.yaml"
]

# L2层：指令性标记（与文件引用共现时提升威胁等级）
INSTRUCTION_MARKERS: List[str] = [
    "you must", "you should", "you need to", "please execute",
    "immediately", "now", "right now", "execute", "run",
    "你必须", "你应该", "你需要", "请执行", "立即", "现在", "马上",
    "modify", "change", "update", "delete", "remove", "replace",
    "修改", "更改", "更新", "删除", "移除", "替换"
]

# 可疑域名模式（用于检测钓鱼链接）
SUSPICIOUS_DOMAINS: List[str] = [
    r".*\.(tk|ml|ga|cf|top)(/|$)",  # 免费顶级域名
    r".*bit\.ly.*",                 # 短链接
    r".*tinyurl\.com.*",
    r".*t\.co.*",
    r".*discord\.gg.*",            # 非官方Discord邀请
]

COMPILED_DOMAIN_PATTERNS: List[Pattern] = [
    re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_DOMAINS
]

# 恶意载荷特征
PAYLOAD_SIGNATURES: Dict[str, List[str]] = {
    "command_injection": [
        r";.*rm\s+-rf",
        r"&&.*curl.*sh",
        r"\|.*bash",
        r"`.*`",  # 命令替换
        r"\$\(.*\)",  # 命令替换
    ],
    "script_injection": [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"expression\(",
        r"@import",
    ],
    "data_exfiltration": [
        r"curl.*-X\s+POST.*@",
        r"wget.*--post-data",
        r"fetch\(.*\)",
        r"XMLHttpRequest",
        r"sendBeacon",
    ]
}


def get_injection_patterns() -> List[Pattern]:
    """获取编译后的注入模式列表
    
    Returns:
        编译后的正则表达式模式列表
    """
    return COMPILED_PATTERNS


def get_file_references() -> List[str]:
    """获取内部文件引用列表
    
    Returns:
        内部文件名列表
    """
    return INTERNAL_FILE_REFS


def get_instruction_markers() -> List[str]:
    """获取指令性标记列表
    
    Returns:
        指令性标记列表
    """
    return INSTRUCTION_MARKERS


def get_suspicious_domain_patterns() -> List[Pattern]:
    """获取可疑域名模式
    
    Returns:
        编译后的域名匹配模式列表
    """
    return COMPILED_DOMAIN_PATTERNS


def check_payload_signatures(content: str) -> Dict[str, List[str]]:
    """检查内容中的恶意载荷特征
    
    Args:
        content: 要检查的内容
        
    Returns:
        检测到的载荷类型和匹配的模式
    """
    detected = {}
    
    for payload_type, patterns in PAYLOAD_SIGNATURES.items():
        matches = []
        for pattern in patterns:
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            found = compiled_pattern.findall(content)
            if found:
                matches.extend(found)
        
        if matches:
            detected[payload_type] = matches
    
    return detected


def extract_urls(content: str) -> List[str]:
    """提取内容中的URL
    
    Args:
        content: 文本内容
        
    Returns:
        提取到的URL列表
    """
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(content)


def is_suspicious_domain(url: str) -> bool:
    """检查URL是否包含可疑域名
    
    Args:
        url: 要检查的URL
        
    Returns:
        是否为可疑域名
    """
    for pattern in COMPILED_DOMAIN_PATTERNS:
        if pattern.search(url):
            return True
    return False