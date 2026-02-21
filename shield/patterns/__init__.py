"""Pattern Detection Modules

各种攻击模式和可疑行为模式：
- injection: 指令注入模式
- poison: 记忆投毒模式
- suspicious: 可疑行为模式
"""

from .injection import INJECTION_PATTERNS, INTERNAL_FILE_REFS, INSTRUCTION_MARKERS

__all__ = [
    "INJECTION_PATTERNS",
    "INTERNAL_FILE_REFS", 
    "INSTRUCTION_MARKERS",
]