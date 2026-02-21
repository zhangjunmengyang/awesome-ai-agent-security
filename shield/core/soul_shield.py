"""Soul Shield - 灵魂锁盾

文件完整性保护和变更管理系统。基于现有memory_guard.py重构并增强。

新增功能：
- 文件写保护（chmod）
- 变更请求/审批流程
- 版本管理和回滚
- 增强的审计日志
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from ..models import (
    Violation, ChangeRequest, Version, CanaryToken, 
    SeverityLevel, ShieldType
)
from ..config import SoulShieldConfig
from ..logger import ShieldLogger


class SoulShield:
    """灵魂锁盾
    
    保护关键人格文件免受未授权修改，提供版本管理和审批流程。
    """
    
    def __init__(self, config: SoulShieldConfig, logger: ShieldLogger):
        """初始化Soul Shield
        
        Args:
            config: Soul Shield配置
            logger: 日志器实例
        """
        self.config = config
        self.logger = logger
        
        # 文件分类
        self.critical_files = config.critical_files
        self.monitored_files = config.monitored_files
        self.all_protected_files = self.critical_files + self.monitored_files
        
        # 存储路径
        self.hash_store = ".shield/hashes.json"
        self.canary_store = ".shield/canaries.json"  
        self.versions_dir = ".shield/versions"
        self.pending_changes_dir = ".shield/pending"
        
        # 统计信息
        self.check_count = 0
        self.violation_count = 0
    
    def init_baseline(self, workspace: str) -> Dict[str, Any]:
        """初始化文件基线
        
        Args:
            workspace: 工作空间路径
            
        Returns:
            初始化结果统计
        """
        workspace_path = Path(workspace)
        if not workspace_path.exists():
            raise ValueError(f"Workspace not found: {workspace}")
        
        # 创建必要目录
        shield_dir = workspace_path / ".shield"
        shield_dir.mkdir(exist_ok=True)
        (shield_dir / "versions").mkdir(exist_ok=True)
        (shield_dir / "pending").mkdir(exist_ok=True)
        
        # 计算所有文件的hash
        hashes = {}
        protected_count = 0
        
        for file_name in self.all_protected_files:
            file_path = workspace_path / file_name
            if file_path.exists() and file_path.is_file():
                file_hash = self._compute_file_hash(file_path)
                file_stat = file_path.stat()
                
                hashes[file_name] = {
                    "hash": file_hash,
                    "size": file_stat.st_size,
                    "mtime": file_stat.st_mtime,
                    "mode": oct(file_stat.st_mode),
                    "initialized_at": datetime.now(timezone.utc).isoformat(),
                    "critical": file_name in self.critical_files
                }
                
                # 创建初始版本
                self._create_version(workspace, file_name, "baseline", 
                                   "Initial baseline version")
                
                protected_count += 1
        
        # 保存hash基线
        self._save_hashes(workspace, hashes)
        
        # 应用写保护
        if self.config.write_protect:
            self._apply_write_protection(workspace)
        
        # 记录日志
        self.logger.log_system_event("soul_shield_init", {
            "workspace": workspace,
            "protected_files": protected_count,
            "critical_files": len(self.critical_files),
            "write_protect": self.config.write_protect
        })
        
        return {
            "protected_files": protected_count,
            "critical_files": len([f for f in self.critical_files if (workspace_path / f).exists()]),
            "monitored_files": len([f for f in self.monitored_files if (workspace_path / f).exists()]),
            "write_protected": self.config.write_protect
        }
    
    def check(self, workspace: str) -> List[Violation]:
        """检查文件完整性
        
        Args:
            workspace: 工作空间路径
            
        Returns:
            违规记录列表
        """
        self.check_count += 1
        violations = []
        
        workspace_path = Path(workspace)
        stored_hashes = self._load_hashes(workspace)
        
        if not stored_hashes:
            violation = Violation(
                violation_id=str(uuid.uuid4()),
                shield_type=ShieldType.SOUL,
                severity=SeverityLevel.HIGH,
                description="No baseline found - Soul Shield not initialized",
                resolution_notes="Run 'shield init' to initialize baseline"
            )
            violations.append(violation)
            return violations
        
        # 检查每个受保护文件
        for file_name in self.all_protected_files:
            file_path = workspace_path / file_name
            stored_info = stored_hashes.get(file_name)
            
            # 文件已删除
            if not file_path.exists():
                if stored_info:
                    violation = self._create_violation(
                        file_name, "file_deleted", SeverityLevel.CRITICAL,
                        f"Critical file {file_name} has been deleted",
                        stored_info
                    )
                    violations.append(violation)
                continue
            
            # 文件不在基线中（新文件）
            if not stored_info:
                if file_name in self.critical_files:
                    # 关键文件出现新文件是可疑的
                    violation = self._create_violation(
                        file_name, "unauthorized_file", SeverityLevel.HIGH,
                        f"New critical file {file_name} found (not in baseline)",
                        None
                    )
                    violations.append(violation)
                continue
            
            # 检查hash完整性
            current_hash = self._compute_file_hash(file_path)
            if current_hash != stored_info["hash"]:
                # 文件被修改
                current_stat = file_path.stat()
                size_delta = current_stat.st_size - stored_info.get("size", 0)
                
                severity = SeverityLevel.CRITICAL if file_name in self.critical_files else SeverityLevel.MEDIUM
                
                violation = self._create_violation(
                    file_name, "file_modified", severity,
                    f"File {file_name} has been modified (hash mismatch, size Δ{size_delta:+d})",
                    stored_info, {
                        "old_hash": stored_info["hash"][:16],
                        "new_hash": current_hash[:16],
                        "size_delta": size_delta
                    }
                )
                violations.append(violation)
            
            # 检查权限
            if self.config.write_protect:
                current_mode = file_path.stat().st_mode
                if current_mode & stat.S_IWUSR:  # 用户写权限被恢复
                    violation = self._create_violation(
                        file_name, "protection_removed", SeverityLevel.HIGH,
                        f"Write protection removed from {file_name}",
                        stored_info
                    )
                    violations.append(violation)
        
        # 更新统计
        if violations:
            self.violation_count += len(violations)
        
        # 记录所有违规到日志
        for violation in violations:
            self.logger.log_violation(violation)
        
        return violations
    
    def protect(self, workspace: str) -> Dict[str, Any]:
        """应用文件写保护
        
        Args:
            workspace: 工作空间路径
            
        Returns:
            操作结果统计
        """
        return self._apply_write_protection(workspace)
    
    def unprotect(self, workspace: str, reason: str = "", 
                  requester: str = "system") -> Dict[str, Any]:
        """移除写保护（需要授权）
        
        Args:
            workspace: 工作空间路径
            reason: 移除原因
            requester: 请求者
            
        Returns:
            操作结果统计
        """
        if self.config.require_approval:
            # 创建变更请求
            change_request = ChangeRequest(
                request_id=str(uuid.uuid4()),
                file_path="*write_protection*",
                change_type="unprotect",
                reason=reason,
                requester=requester
            )
            
            self._save_change_request(workspace, change_request)
            self.logger.log_file_change("*write_protection*", "unprotect_requested", False, reason)
            
            return {
                "status": "pending_approval",
                "request_id": change_request.request_id,
                "message": "Unprotect request created, awaiting approval"
            }
        
        # 直接移除保护
        return self._remove_write_protection(workspace, reason)
    
    def request_change(self, file_path: str, diff: str, source: str = "",
                      workspace: str = "") -> ChangeRequest:
        """创建变更请求
        
        Args:
            file_path: 文件路径
            diff: 变更内容
            source: 变更来源
            workspace: 工作空间路径
            
        Returns:
            变更请求对象
        """
        change_request = ChangeRequest(
            request_id=str(uuid.uuid4()),
            file_path=file_path,
            change_type="modify",
            diff=diff,
            reason=f"Change requested from {source}",
            requester=source
        )
        
        if workspace:
            self._save_change_request(workspace, change_request)
            self.logger.log_file_change(file_path, "change_requested", False, 
                                       f"From {source}")
        
        return change_request
    
    def approve_change(self, request_id: str, workspace: str, 
                      approver: str = "admin") -> Dict[str, Any]:
        """批准变更请求
        
        Args:
            request_id: 请求ID
            workspace: 工作空间路径  
            approver: 批准者
            
        Returns:
            执行结果
        """
        # 加载变更请求
        request = self._load_change_request(workspace, request_id)
        if not request:
            raise ValueError(f"Change request {request_id} not found")
        
        if request.approved:
            return {"status": "already_approved", "request_id": request_id}
        
        # 标记为已批准
        request.approved = True
        request.approver = approver
        request.approval_timestamp = datetime.now()
        
        # 保存更新后的请求
        self._save_change_request(workspace, request)
        
        # 记录日志
        self.logger.log_file_change(request.file_path, "change_approved", True,
                                   f"Approved by {approver}")
        
        return {
            "status": "approved",
            "request_id": request_id,
            "file_path": request.file_path,
            "approver": approver
        }
    
    def rollback(self, file_path: str, version: int, workspace: str) -> Dict[str, Any]:
        """回滚文件到指定版本
        
        Args:
            file_path: 文件路径
            version: 版本号
            workspace: 工作空间路径
            
        Returns:
            回滚结果
        """
        # 查找版本文件
        version_file = self._find_version_file(workspace, file_path, version)
        if not version_file:
            raise ValueError(f"Version {version} of {file_path} not found")
        
        workspace_path = Path(workspace)
        target_file = workspace_path / file_path
        
        # 创建当前版本的备份
        if target_file.exists():
            self._create_version(workspace, file_path, "pre_rollback",
                               f"Backup before rollback to v{version}")
        
        # 暂时移除写保护
        had_protection = False
        if target_file.exists() and not (target_file.stat().st_mode & stat.S_IWUSR):
            target_file.chmod(target_file.stat().st_mode | stat.S_IWUSR)
            had_protection = True
        
        try:
            # 复制版本文件
            shutil.copy2(version_file, target_file)
            
            # 恢复写保护
            if had_protection and self.config.write_protect:
                target_file.chmod(target_file.stat().st_mode & ~stat.S_IWUSR)
            
            # 更新hash基线
            self._update_file_hash(workspace, file_path)
            
            # 记录日志
            self.logger.log_file_change(file_path, "rollback", True,
                                       f"Rolled back to version {version}")
            
            return {
                "status": "success",
                "file_path": file_path,
                "version": version,
                "message": f"Successfully rolled back {file_path} to version {version}"
            }
            
        except Exception as e:
            self.logger.log_file_change(file_path, "rollback_failed", False, str(e))
            raise
    
    def history(self, file_path: str, workspace: str) -> List[Version]:
        """获取文件的版本历史
        
        Args:
            file_path: 文件路径
            workspace: 工作空间路径
            
        Returns:
            版本历史列表
        """
        versions = []
        versions_path = Path(workspace) / self.versions_dir
        
        if not versions_path.exists():
            return versions
        
        # 扫描版本文件
        file_pattern = file_path.replace("/", "_").replace(".", "_")
        
        for version_file in versions_path.glob(f"{file_pattern}_v*.json"):
            try:
                with open(version_file, 'r') as f:
                    version_data = json.load(f)
                
                version = Version(
                    version_id=version_data["version_id"],
                    file_path=version_data["file_path"],
                    content_hash=version_data["content_hash"],
                    timestamp=datetime.fromisoformat(version_data["timestamp"]),
                    size=version_data["size"],
                    description=version_data.get("description", ""),
                    tags=version_data.get("tags", [])
                )
                versions.append(version)
                
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        
        # 按时间排序
        versions.sort(key=lambda v: v.timestamp, reverse=True)
        return versions
    
    def inject_canaries(self, workspace: str, count: int = 3) -> List[CanaryToken]:
        """注入金丝雀令牌
        
        Args:
            workspace: 工作空间路径
            count: 令牌数量
            
        Returns:
            创建的令牌列表
        """
        import secrets
        
        workspace_path = Path(workspace)
        memory_file = workspace_path / "MEMORY.md"
        
        if not memory_file.exists():
            raise ValueError("MEMORY.md not found")
        
        # 生成唯一令牌
        canaries = []
        token_types = ["api_key", "internal_url", "project_name", "auth_token", "database_key"]
        
        for i in range(min(count, len(token_types))):
            token_content = f"canary-{secrets.token_hex(6)}"
            canary = CanaryToken(
                token_id=f"canary_{i}_{secrets.token_hex(4)}",
                content=token_content,
                file_path="MEMORY.md",
                position=["header", "middle", "footer"][i % 3],
                created_at=datetime.now()
            )
            canaries.append(canary)
        
        # 保存令牌注册表
        self._save_canaries(workspace, canaries)
        
        # 记录日志
        self.logger.log_system_event("canaries_injected", {
            "workspace": workspace,
            "count": len(canaries),
            "tokens": [c.token_id for c in canaries]
        })
        
        return canaries
    
    def check_canaries(self, text: str, workspace: str) -> List[str]:
        """检查文本中是否包含金丝雀令牌
        
        Args:
            text: 要检查的文本
            workspace: 工作空间路径
            
        Returns:
            泄露的令牌ID列表
        """
        canaries = self._load_canaries(workspace)
        leaked_tokens = []
        
        for canary in canaries:
            if canary.content in text:
                # 标记令牌为已触发
                canary.mark_triggered()
                leaked_tokens.append(canary.token_id)
                
                # 记录关键日志
                self.logger.log_canary_trigger(canary.token_id, canary.file_path)
        
        # 更新令牌状态
        if leaked_tokens:
            self._save_canaries(workspace, canaries)
        
        return leaked_tokens
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息
        
        Returns:
            统计数据字典
        """
        return {
            "checks_performed": self.check_count,
            "violations_found": self.violation_count,
            "violation_rate": self.violation_count / max(self.check_count, 1),
            "critical_files": len(self.critical_files),
            "monitored_files": len(self.monitored_files),
            "write_protection": self.config.write_protect,
            "require_approval": self.config.require_approval,
            "max_versions": self.config.max_versions
        }
    
    # ========== 私有方法 ==========
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """计算文件SHA-256哈希"""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    
    def _load_hashes(self, workspace: str) -> Dict[str, Any]:
        """加载存储的hash基线"""
        hash_file = Path(workspace) / self.hash_store
        if hash_file.exists():
            with open(hash_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_hashes(self, workspace: str, hashes: Dict[str, Any]):
        """保存hash基线"""
        hash_file = Path(workspace) / self.hash_store
        hash_file.parent.mkdir(parents=True, exist_ok=True)
        with open(hash_file, 'w') as f:
            json.dump(hashes, f, indent=2)
    
    def _create_violation(self, file_name: str, violation_type: str, 
                         severity: SeverityLevel, description: str,
                         stored_info: Optional[Dict[str, Any]], 
                         extra_data: Optional[Dict[str, Any]] = None) -> Violation:
        """创建违规记录"""
        violation = Violation(
            violation_id=str(uuid.uuid4()),
            shield_type=ShieldType.SOUL,
            severity=severity,
            description=description,
            file_path=file_name,
            source=violation_type
        )
        
        if stored_info:
            violation.content_snippet = f"Expected hash: {stored_info['hash'][:16]}..."
        
        return violation
    
    def _apply_write_protection(self, workspace: str) -> Dict[str, Any]:
        """应用文件写保护"""
        workspace_path = Path(workspace)
        protected_count = 0
        failed_count = 0
        
        for file_name in self.all_protected_files:
            file_path = workspace_path / file_name
            if file_path.exists() and file_path.is_file():
                try:
                    # 移除用户写权限 (chmod 444)
                    current_mode = file_path.stat().st_mode
                    new_mode = current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
                    file_path.chmod(new_mode)
                    protected_count += 1
                except OSError:
                    failed_count += 1
        
        self.logger.log_system_event("write_protection_applied", {
            "workspace": workspace,
            "protected": protected_count,
            "failed": failed_count
        })
        
        return {"protected": protected_count, "failed": failed_count}
    
    def _remove_write_protection(self, workspace: str, reason: str) -> Dict[str, Any]:
        """移除写保护"""
        workspace_path = Path(workspace)
        unprotected_count = 0
        failed_count = 0
        
        for file_name in self.all_protected_files:
            file_path = workspace_path / file_name
            if file_path.exists() and file_path.is_file():
                try:
                    # 恢复用户写权限 (chmod 644)
                    current_mode = file_path.stat().st_mode
                    new_mode = current_mode | stat.S_IWUSR
                    file_path.chmod(new_mode)
                    unprotected_count += 1
                except OSError:
                    failed_count += 1
        
        self.logger.log_file_change("*write_protection*", "unprotect", True, reason)
        
        return {"unprotected": unprotected_count, "failed": failed_count}
    
    def _create_version(self, workspace: str, file_path: str, 
                       version_type: str, description: str) -> str:
        """创建文件版本快照"""
        workspace_path = Path(workspace)
        source_file = workspace_path / file_path
        
        if not source_file.exists():
            return ""
        
        # 生成版本ID
        timestamp = datetime.now()
        version_id = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{version_type}"
        
        # 版本文件名
        safe_filename = file_path.replace("/", "_").replace(".", "_")
        version_filename = f"{safe_filename}_v{version_id}"
        
        versions_path = workspace_path / self.versions_dir
        versions_path.mkdir(parents=True, exist_ok=True)
        
        # 复制文件内容
        content_file = versions_path / f"{version_filename}.content"
        shutil.copy2(source_file, content_file)
        
        # 创建元数据
        metadata = {
            "version_id": version_id,
            "file_path": file_path,
            "content_hash": self._compute_file_hash(source_file),
            "timestamp": timestamp.isoformat(),
            "size": source_file.stat().st_size,
            "description": description,
            "tags": [version_type]
        }
        
        # 保存元数据
        meta_file = versions_path / f"{version_filename}.json"
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return version_id
    
    def _find_version_file(self, workspace: str, file_path: str, 
                          version: int) -> Optional[Path]:
        """查找指定版本的文件"""
        versions_path = Path(workspace) / self.versions_dir
        if not versions_path.exists():
            return None
        
        safe_filename = file_path.replace("/", "_").replace(".", "_")
        
        # 简单实现：按版本号查找
        for content_file in versions_path.glob(f"{safe_filename}_v*.content"):
            # 这里可以实现更复杂的版本匹配逻辑
            return content_file
        
        return None
    
    def _update_file_hash(self, workspace: str, file_path: str):
        """更新文件的hash基线"""
        workspace_path = Path(workspace)
        target_file = workspace_path / file_path
        
        if not target_file.exists():
            return
        
        hashes = self._load_hashes(workspace)
        if file_path in hashes:
            hashes[file_path]["hash"] = self._compute_file_hash(target_file)
            hashes[file_path]["size"] = target_file.stat().st_size
            hashes[file_path]["mtime"] = target_file.stat().st_mtime
            self._save_hashes(workspace, hashes)
    
    def _save_change_request(self, workspace: str, request: ChangeRequest):
        """保存变更请求"""
        requests_path = Path(workspace) / self.pending_changes_dir
        requests_path.mkdir(parents=True, exist_ok=True)
        
        request_file = requests_path / f"{request.request_id}.json"
        with open(request_file, 'w') as f:
            # 将dataclass转换为字典
            request_dict = {
                "request_id": request.request_id,
                "file_path": request.file_path,
                "change_type": request.change_type,
                "diff": request.diff,
                "reason": request.reason,
                "requester": request.requester,
                "timestamp": request.timestamp.isoformat(),
                "approved": request.approved,
                "approver": request.approver,
                "approval_timestamp": request.approval_timestamp.isoformat() if request.approval_timestamp else None,
                "executed": request.executed,
                "execution_timestamp": request.execution_timestamp.isoformat() if request.execution_timestamp else None
            }
            json.dump(request_dict, f, indent=2)
    
    def _load_change_request(self, workspace: str, request_id: str) -> Optional[ChangeRequest]:
        """加载变更请求"""
        request_file = Path(workspace) / self.pending_changes_dir / f"{request_id}.json"
        
        if not request_file.exists():
            return None
        
        try:
            with open(request_file, 'r') as f:
                data = json.load(f)
            
            request = ChangeRequest(
                request_id=data["request_id"],
                file_path=data["file_path"],
                change_type=data["change_type"],
                diff=data.get("diff"),
                reason=data.get("reason"),
                requester=data.get("requester"),
                timestamp=datetime.fromisoformat(data["timestamp"]),
                approved=data["approved"],
                approver=data.get("approver"),
                approval_timestamp=datetime.fromisoformat(data["approval_timestamp"]) if data.get("approval_timestamp") else None,
                executed=data["executed"],
                execution_timestamp=datetime.fromisoformat(data["execution_timestamp"]) if data.get("execution_timestamp") else None
            )
            return request
            
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
    
    def _save_canaries(self, workspace: str, canaries: List[CanaryToken]):
        """保存金丝雀令牌注册表"""
        canary_file = Path(workspace) / self.canary_store
        canary_file.parent.mkdir(parents=True, exist_ok=True)
        
        canary_data = {}
        for canary in canaries:
            canary_data[canary.token_id] = {
                "content": canary.content,
                "file_path": canary.file_path,
                "position": canary.position,
                "created_at": canary.created_at.isoformat(),
                "last_seen": canary.last_seen.isoformat() if canary.last_seen else None,
                "triggered": canary.triggered
            }
        
        with open(canary_file, 'w') as f:
            json.dump(canary_data, f, indent=2)
    
    def _load_canaries(self, workspace: str) -> List[CanaryToken]:
        """加载金丝雀令牌"""
        canary_file = Path(workspace) / self.canary_store
        
        if not canary_file.exists():
            return []
        
        try:
            with open(canary_file, 'r') as f:
                canary_data = json.load(f)
            
            canaries = []
            for token_id, data in canary_data.items():
                canary = CanaryToken(
                    token_id=token_id,
                    content=data["content"],
                    file_path=data["file_path"],
                    position=data["position"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
                    triggered=data.get("triggered", False)
                )
                canaries.append(canary)
            
            return canaries
            
        except (json.JSONDecodeError, KeyError, ValueError):
            return []