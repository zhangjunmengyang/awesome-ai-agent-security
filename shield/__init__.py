"""Shield - AI Agent Defense System

六盾防御体系：
- 🔍 Input Shield: 输入净化
- 🚧 Action Shield: 行为守卫  
- 🔒 Soul Shield: 灵魂锁盾
- 🧠 Memory Shield: 记忆守卫
- 🎭 Persona Shield: 人格锚定
- 📦 Supply Shield: 供应链审查
"""

__version__ = "0.1.0"
__author__ = "Shield Engineering Team"

from .models import (
    ScanResult,
    ActionResult,
    Violation,
    ChangeRequest,
    DriftScore,
    ConsistencyResult,
    SupplyResult,
)

__all__ = [
    "ScanResult",
    "ActionResult", 
    "Violation",
    "ChangeRequest",
    "DriftScore",
    "ConsistencyResult",
    "SupplyResult",
]