"""
Shield Data Models
================
Common data structures used across all shield modules.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path


class ThreatLevel(Enum):
    """Threat level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityLevel(Enum):
    """安全威胁等级 (alias for ThreatLevel for compatibility)"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented


class ShieldType(Enum):
    """Types of shields available."""
    INPUT = "input"
    ACTION = "action"
    SOUL = "soul"
    MEMORY = "memory"
    PERSONA = "persona"
    SUPPLY = "supply"


class ActionType(Enum):
    """Response actions for violations."""
    WARN = "warn"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    CONFIRM = "confirm"


@dataclass
class ScanResult:
    """Result from any shield scan operation."""
    safe: bool
    shield_type: ShieldType
    threat_level: ThreatLevel
    matched_patterns: List[str]
    violations: List[str]
    recommendation: ActionType
    details: Dict[str, Any]
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class MemoryEntry:
    """Memory entry with source tracking and trust level."""
    content: str
    source: str  # "owner_direct", "self_reflection", "external_summary", "tool_output"
    trust_level: float  # 0.0 - 1.0
    timestamp: datetime
    verified: bool = False
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ConsistencyResult:
    """Result from memory consistency check."""
    consistent: bool
    conflicts: List[str]
    new_facts: List[str]
    existing_facts: List[str]
    confidence: float  # 0.0 - 1.0
    recommendation: str
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class ActionResult:
    """Result from action shield checks."""
    allowed: bool
    action_type: str  # "command", "url", "file_access", etc.
    risk_level: ThreatLevel
    reasons: List[str]
    suggested_action: ActionType
    metadata: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class ViolationRecord:
    """Record of a shield violation for audit log."""
    shield_type: ShieldType
    violation_type: str
    severity: ThreatLevel
    details: str
    file_path: Optional[str]
    content_sample: Optional[str]
    source: str
    timestamp: datetime
    resolved: bool = False
    resolution_notes: Optional[str] = None


@dataclass
class CanaryToken:
    """Canary trap token with metadata."""
    token: str
    token_type: str  # "api_key", "internal_url", "project_name", etc.
    location: str  # where it was injected
    injected_at: datetime
    purpose: str
    pattern: Optional[str] = None  # regex pattern to detect it


@dataclass
class Violation:
    """违规记录
    
    记录各种安全违规事件。
    """
    violation_id: str
    shield_type: ShieldType
    severity: ThreatLevel
    description: str
    file_path: Optional[str] = None
    content_snippet: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[datetime] = None
    resolved: bool = False
    resolution_notes: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class ChangeRequest:
    """变更请求
    
    用于Soul Shield的变更授权流程。
    """
    request_id: str
    file_path: str
    change_type: str  # "modify", "delete", "create"
    diff: Optional[str] = None
    reason: Optional[str] = None
    requester: Optional[str] = None
    timestamp: Optional[datetime] = None
    approved: bool = False
    approver: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    executed: bool = False
    execution_timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class DriftScore:
    """人格漂移评分
    
    用于Persona Shield的人格一致性评估。
    """
    overall_score: float  # 0.0-1.0, 1.0为完全一致
    consistency_score: float
    tone_score: float
    value_score: float
    behavior_score: float
    sample_outputs: List[str]
    deviations: List[str]
    baseline_version: str
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
    
    @property
    def is_drifted(self) -> bool:
        """判断是否存在显著漂移（阈值0.7）"""
        return self.overall_score < 0.7


@dataclass
class SupplyResult:
    """供应链扫描结果
    
    用于Supply Shield的包/技能扫描。
    """
    safe: bool
    package_name: str
    package_path: str
    risk_level: ThreatLevel
    issues: List[str]
    permissions_requested: List[str]
    suspicious_code_snippets: List[str]
    blocklist_matches: List[str]
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class Version:
    """文件版本信息
    
    用于Soul Shield的版本管理。
    """
    version_id: str
    file_path: str
    content_hash: str
    timestamp: datetime
    size: int
    description: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []