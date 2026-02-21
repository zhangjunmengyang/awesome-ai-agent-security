"""Unified audit logging for Shield Defense System

统一的审计日志系统，所有盾都写入同一日志。
"""

import json
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from .models import ShieldType, SeverityLevel, ThreatLevel, Violation, ScanResult, ActionResult


class ShieldLogger:
    """Shield统一审计日志器
    
    提供结构化日志记录，支持日志轮转和格式化输出。
    """
    
    def __init__(self, log_path: str = ".shield/audit.log", 
                 max_size_mb: int = 10, rotate: bool = True):
        """初始化日志器
        
        Args:
            log_path: 日志文件路径或工作区目录路径
            max_size_mb: 日志文件最大大小（MB）
            rotate: 是否启用日志轮转
        """
        # 如果传入的是目录，自动追加 .shield/audit.log
        log_path_obj = Path(log_path)
        if log_path_obj.is_dir() or (not log_path_obj.suffix and not log_path_obj.name.endswith('.log')):
            self.log_path = log_path_obj / ".shield" / "audit.log"
        else:
            self.log_path = log_path_obj
            
        self.max_size_mb = max_size_mb
        self.rotate = rotate
        
        # 创建日志目录
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 设置logger
        self.logger = logging.getLogger("shield_audit")
        self.logger.setLevel(logging.INFO)
        
        # 清除现有handlers
        self.logger.handlers.clear()
        
        # 配置handler
        if rotate:
            handler = logging.handlers.RotatingFileHandler(
                self.log_path,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=5
            )
        else:
            handler = logging.FileHandler(self.log_path)
        
        # 设置格式器
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def _create_log_entry(self, event_type: str, shield_type: ShieldType,
                         severity: SeverityLevel, message: str,
                         details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建标准日志条目
        
        Args:
            event_type: 事件类型（scan, block, warn, allow等）
            shield_type: 盾类型
            severity: 严重程度
            message: 描述信息
            details: 额外详细信息
            
        Returns:
            标准格式的日志条目
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "shield": shield_type.value,
            "severity": severity.value,
            "message": message
        }
        
        if details:
            entry["details"] = details
            
        return entry
    
    def log_scan(self, shield_type, *args, **kwargs):
        """记录扫描事件（兼容多种调用方式）
        
        支持:
            log_scan(shield_type, scan_result, source=None)  — P0 风格
            log_scan(shield_type, description, safe, patterns, details) — P1 风格
        """
        try:
            shield_val = shield_type.value if hasattr(shield_type, 'value') else str(shield_type)
            
            if len(args) >= 1 and hasattr(args[0], 'safe'):
                # P0 style: scan_result object
                scan_result = args[0]
                source = args[1] if len(args) > 1 else kwargs.get('source')
                safe = scan_result.safe
                level = getattr(scan_result, 'level', None) or getattr(scan_result, 'threat_level', None)
                level_val = level.value if hasattr(level, 'value') else str(level) if level else 'unknown'
                msg = f"Scan {'safe' if safe else 'threat'}"
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "scan",
                    "shield": shield_val,
                    "severity": level_val,
                    "safe": safe,
                    "message": msg,
                }
                if source:
                    entry["source"] = source
            else:
                # P1 style: positional args
                description = args[0] if len(args) > 0 else "scan"
                safe = args[1] if len(args) > 1 else True
                patterns = args[2] if len(args) > 2 else []
                details = args[3] if len(args) > 3 else {}
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "scan",
                    "shield": shield_val,
                    "safe": safe,
                    "description": str(description),
                    "message": f"Scan {'safe' if safe else 'threat'}",
                }
                if details:
                    entry["details"] = details
            
            if safe:
                self.logger.info(json.dumps(entry, default=str))
            else:
                self.logger.warning(json.dumps(entry, default=str))
        except Exception:
            # Logger should never crash the shield
            pass
    
    def log_action(self, action_result: ActionResult, command: Optional[str] = None):
        """记录行为检测事件
        
        Args:
            action_result: 行为检测结果
            command: 被检测的命令
        """
        details = {
            "allowed": action_result.allowed,
            "action_type": action_result.action_type,
            "reasons": action_result.reasons,
            "suggested_action": action_result.suggested_action.value if hasattr(action_result.suggested_action, 'value') else str(action_result.suggested_action)
        }
        
        if command:
            details["command"] = command
            
        if hasattr(action_result, 'metadata') and action_result.metadata:
            details.update(action_result.metadata)
        
        # Convert ThreatLevel to SeverityLevel  
        severity = action_result.risk_level
        if hasattr(severity, 'value'):
            sev_mapping = {
                'low': SeverityLevel.LOW,
                'medium': SeverityLevel.MEDIUM,  
                'high': SeverityLevel.HIGH,
                'critical': SeverityLevel.CRITICAL
            }
            sev_level = sev_mapping.get(severity.value, SeverityLevel.LOW)
        else:
            sev_level = severity
        
        entry = self._create_log_entry(
            "action_check",
            ShieldType.ACTION,
            sev_level,
            f"Action {'allowed' if action_result.allowed else 'blocked'}: {action_result.action_type}",
            details
        )
        
        if action_result.allowed:
            self.logger.info(json.dumps(entry))
        else:
            self.logger.error(json.dumps(entry))
    
    def log_violation(self, violation: Violation):
        """记录违规事件
        
        Args:
            violation: 违规记录
        """
        details = {
            "violation_id": violation.violation_id,
            "description": violation.description
        }
        
        if violation.file_path:
            details["file_path"] = violation.file_path
            
        if violation.content_snippet:
            details["content_snippet"] = violation.content_snippet
            
        if violation.source:
            details["source"] = violation.source
        
        entry = self._create_log_entry(
            "violation",
            violation.shield_type,
            violation.severity,
            f"Security violation detected: {violation.description}",
            details
        )
        
        if violation.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            self.logger.error(json.dumps(entry))
        else:
            self.logger.warning(json.dumps(entry))
    
    def log_file_change(self, file_path: str, change_type: str, 
                       approved: bool, reason: Optional[str] = None):
        """记录文件变更事件
        
        Args:
            file_path: 文件路径
            change_type: 变更类型（modify, create, delete）
            approved: 是否已授权
            reason: 变更原因
        """
        details = {
            "file_path": file_path,
            "change_type": change_type,
            "approved": approved
        }
        
        if reason:
            details["reason"] = reason
        
        severity = SeverityLevel.LOW if approved else SeverityLevel.HIGH
        
        entry = self._create_log_entry(
            "file_change",
            ShieldType.SOUL,
            severity,
            f"File {change_type} {'approved' if approved else 'blocked'}: {file_path}",
            details
        )
        
        if approved:
            self.logger.info(json.dumps(entry))
        else:
            self.logger.warning(json.dumps(entry))
    
    def log_persona_drift(self, drift_score: float, deviations: list):
        """记录人格漂移事件
        
        Args:
            drift_score: 漂移评分
            deviations: 偏差列表
        """
        details = {
            "drift_score": drift_score,
            "deviations": deviations
        }
        
        severity = SeverityLevel.HIGH if drift_score < 0.5 else SeverityLevel.MEDIUM
        
        entry = self._create_log_entry(
            "persona_drift",
            ShieldType.PERSONA,
            severity,
            f"Persona drift detected (score: {drift_score:.2f})",
            details
        )
        
        self.logger.warning(json.dumps(entry))
    
    def log_memory_inconsistency(self, consistency_score: float, conflicts: list):
        """记录记忆不一致事件
        
        Args:
            consistency_score: 一致性评分
            conflicts: 冲突列表
        """
        details = {
            "consistency_score": consistency_score,
            "conflicts": conflicts
        }
        
        severity = SeverityLevel.MEDIUM if consistency_score < 0.7 else SeverityLevel.LOW
        
        entry = self._create_log_entry(
            "memory_inconsistency",
            ShieldType.MEMORY,
            severity,
            f"Memory inconsistency detected (score: {consistency_score:.2f})",
            details
        )
        
        self.logger.warning(json.dumps(entry))
    
    def log_consistency_check(self, new_entry: str, conflicts: list, consistent: bool):
        """记录一致性检查事件
        
        Args:
            new_entry: 新记忆条目
            conflicts: 冲突列表
            consistent: 是否一致
        """
        details = {
            "new_entry_length": len(new_entry),
            "conflicts_count": len(conflicts),
            "conflicts": conflicts[:5] if conflicts else [],  # 最多记录5个冲突
            "consistent": consistent
        }
        
        severity = SeverityLevel.HIGH if not consistent and conflicts else SeverityLevel.LOW
        
        entry = self._create_log_entry(
            "consistency_check",
            ShieldType.MEMORY,
            severity,
            f"Memory consistency check: {'consistent' if consistent else 'conflicts detected'}",
            details
        )
        
        if consistent:
            self.logger.info(json.dumps(entry))
        else:
            self.logger.warning(json.dumps(entry))
    
    def log_canary_trigger(self, token_id: str, file_path: str):
        """记录金丝雀令牌触发事件
        
        Args:
            token_id: 令牌ID
            file_path: 文件路径
        """
        details = {
            "token_id": token_id,
            "file_path": file_path
        }
        
        entry = self._create_log_entry(
            "canary_trigger",
            ShieldType.SOUL,
            SeverityLevel.CRITICAL,
            f"Canary token triggered: {token_id} in {file_path}",
            details
        )
        
        self.logger.critical(json.dumps(entry))
    
    def log_system_event(self, event: str, details: Optional[Dict[str, Any]] = None):
        """记录系统事件
        
        Args:
            event: 事件描述
            details: 事件详情
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "system",
            "shield": "system",
            "severity": SeverityLevel.LOW.value,
            "message": event
        }
        
        if details:
            entry["details"] = details
        
        self.logger.info(json.dumps(entry))
    
    def log_event(self, shield_type: ShieldType, event_type: str, severity: ThreatLevel, 
                  message: str, details: Optional[Dict[str, Any]] = None):
        """记录通用事件
        
        Args:
            shield_type: 盾类型
            event_type: 事件类型
            severity: 严重程度
            message: 事件消息
            details: 事件详情
        """
        # Convert ThreatLevel to SeverityLevel
        if hasattr(severity, 'value'):
            sev_mapping = {
                'low': SeverityLevel.LOW,
                'medium': SeverityLevel.MEDIUM,  
                'high': SeverityLevel.HIGH,
                'critical': SeverityLevel.CRITICAL
            }
            sev_level = sev_mapping.get(severity.value, SeverityLevel.LOW)
        else:
            sev_level = severity
            
        entry = self._create_log_entry(event_type, shield_type, sev_level, message, details)
        
        if severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.logger.error(json.dumps(entry))
        elif severity == ThreatLevel.MEDIUM:
            self.logger.warning(json.dumps(entry))
        else:
            self.logger.info(json.dumps(entry))
    
    def log_canary_leak(self, token: str, location: str, shield_type: ShieldType):
        """记录金丝雀令牌泄露事件
        
        Args:
            token: 泄露的令牌
            location: 泄露位置
            shield_type: 检测的盾类型
        """
        details = {
            "token_id": token[:12] + "...",  # 只记录部分令牌
            "full_token": token,
            "location": location
        }
        
        entry = self._create_log_entry(
            "canary_leak",
            shield_type,
            SeverityLevel.CRITICAL,
            f"Canary token leaked: {token[:12]}... at {location}",
            details
        )
        
        self.logger.critical(json.dumps(entry))
    
    def get_log_path(self) -> Path:
        """获取日志文件路径"""
        return self.log_path
    
    def get_recent_logs(self, lines: int = 50) -> list:
        """获取最近的日志条目
        
        Args:
            lines: 返回的行数
            
        Returns:
            最近的日志条目列表
        """
        try:
            with open(self.log_path, 'r') as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        except FileNotFoundError:
            return []
    
    def get_recent_events(self, hours: int = 24, shield_type: Optional[ShieldType] = None) -> list:
        """获取最近的事件
        
        Args:
            hours: 小时数
            shield_type: 可选的盾类型过滤
            
        Returns:
            最近的事件列表
        """
        try:
            events = []
            with open(self.log_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        # 简单实现：返回所有事件，实际应该根据时间和类型过滤
                        if shield_type is None or event.get("shield") == shield_type.value:
                            events.append(event)
                    except (json.JSONDecodeError, KeyError):
                        continue
            return events[-100:]  # 返回最近100条
        except FileNotFoundError:
            return []


# 全局日志器实例
_logger_instance: Optional[ShieldLogger] = None


def get_logger(log_path: str = ".shield/audit.log", 
               max_size_mb: int = 10, rotate: bool = True) -> ShieldLogger:
    """获取全局日志器实例
    
    Args:
        log_path: 日志文件路径
        max_size_mb: 最大文件大小
        rotate: 是否轮转
        
    Returns:
        ShieldLogger实例
    """
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = ShieldLogger(log_path, max_size_mb, rotate)
    
    return _logger_instance


def reset_logger():
    """重置全局日志器（主要用于测试）"""
    global _logger_instance
    _logger_instance = None