"""
Red Team Testing Framework
==========================

红队测试框架，用于全面评估Agent防御系统的有效性。

功能：
- 运行完整攻击战役
- 测试各个Shield组件
- 生成详细测试报告
- 统计检测率和绕过率
"""

import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

from .prompt_injection import InjectionPayloadGenerator
from .memory_poisoning import MemoryPoisoner
from .tool_abuse import ToolAbuser

# 尝试导入shield模块，如果不存在则使用模拟版本
try:
    from shield.core.input_shield import InputShield
    from shield.core.memory_shield import MemoryShield  
    from shield.core.action_shield import ActionShield
    from shield.models import ScanResult, ThreatLevel, ActionType
    SHIELD_AVAILABLE = True
except ImportError:
    SHIELD_AVAILABLE = False
    # 模拟Shield类用于测试
    class MockShield:
        def scan(self, content: Any) -> Dict[str, Any]:
            return {
                "safe": True,
                "threat_level": "LOW",
                "matched_patterns": [],
                "recommendation": "ALLOW"
            }
    
    InputShield = MockShield
    MemoryShield = MockShield  
    ActionShield = MockShield


@dataclass
class AttackTestResult:
    """单个测试的结果"""
    payload_id: str
    payload: Dict[str, Any]
    shield_response: Dict[str, Any] 
    detected: bool
    bypassed: bool
    execution_time: float
    timestamp: datetime
    error: Optional[str] = None


@dataclass
class CampaignReport:
    """攻击战役完整报告"""
    campaign_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_payloads: int
    detected_count: int
    bypassed_count: int
    error_count: int
    detection_rate: float
    bypass_rate: float
    error_rate: float
    results_by_category: Dict[str, Dict[str, int]]
    results_by_severity: Dict[str, Dict[str, int]]
    detailed_results: List[AttackTestResult]
    recommendations: List[str]


class RedTeamRunner:
    """红队测试执行引擎
    
    协调各种攻击payload的生成和执行，
    统计检测率，生成详细报告。
    """
    
    def __init__(self, target_shields: Optional[Dict[str, Any]] = None):
        """初始化红队测试器
        
        Args:
            target_shields: 目标Shield实例字典，格式为 {'input': InputShield(), ...}
        """
        self.target_shields = target_shields or {}
        
        # 初始化攻击生成器
        self.injection_generator = InjectionPayloadGenerator()
        self.memory_poisoner = MemoryPoisoner()
        self.tool_abuser = ToolAbuser()
        
        # 测试结果存储
        self.test_results: List[AttackTestResult] = []
        self.campaign_start_time: Optional[datetime] = None
        self.campaign_end_time: Optional[datetime] = None
        
        # 报告存储路径
        self.report_dir = Path("./red_team_reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def run_campaign(self, categories: Optional[List[str]] = None, 
                    shield_types: Optional[List[str]] = None) -> CampaignReport:
        """运行完整攻击战役
        
        Args:
            categories: 要测试的攻击类别列表，None表示测试所有类别
            shield_types: 要测试的Shield类型列表，None表示测试所有类型
            
        Returns:
            CampaignReport: 完整的战役报告
        """
        print("🚀 Starting Red Team Campaign...")
        
        self.campaign_start_time = datetime.now(timezone.utc)
        campaign_id = f"campaign_{int(time.time())}"
        
        # 清空之前的结果
        self.test_results = []
        
        # 确定要测试的类别
        all_categories = [
            "direct_injection", "indirect_injection", "obfuscation_injection",
            "crescendo_attack", "authority_spoofing", "authority_injection",
            "behavior_modification", "identity_corruption", "persistent_backdoor", 
            "canary_poisoning", "data_exfiltration", "command_injection",
            "privilege_escalation", "supply_chain_attack"
        ]
        test_categories = categories or all_categories
        
        # 确定要测试的Shield类型
        available_shields = list(self.target_shields.keys())
        test_shields = shield_types or available_shields
        
        print(f"📊 Testing {len(test_categories)} attack categories against {len(test_shields)} shield types")
        
        # 执行各类攻击测试
        for shield_type in test_shields:
            if shield_type == "input":
                self._test_input_shield(test_categories)
            elif shield_type == "memory":
                self._test_memory_shield(test_categories)
            elif shield_type == "action":
                self._test_action_shield(test_categories)
        
        self.campaign_end_time = datetime.now(timezone.utc)
        
        # 生成报告
        report = self._generate_campaign_report(campaign_id)
        
        # 保存报告
        self._save_report(report)
        
        print(f"✅ Campaign completed! Detection rate: {report.detection_rate:.1%}")
        return report
    
    def test_input_shield(self, shield: Any) -> Dict[str, Any]:
        """测试Input Shield
        
        Args:
            shield: InputShield实例
            
        Returns:
            Dict: 测试结果统计
        """
        print("🛡️ Testing Input Shield...")
        
        # 获取所有注入攻击payload
        payloads = []
        payloads.extend(self.injection_generator.get_all_payloads())
        
        results = {
            "total": len(payloads),
            "detected": 0,
            "bypassed": 0,
            "errors": 0,
            "details": []
        }
        
        for i, payload in enumerate(payloads):
            print(f"  Testing payload {i+1}/{len(payloads)}: {payload['technique']}")
            
            try:
                start_time = time.time()
                
                # 测试payload
                response = self._scan_with_shield(shield, payload["payload"])
                
                execution_time = time.time() - start_time
                
                # 判断是否被检测
                detected = not response.get("safe", True)
                bypassed = response.get("safe", True)
                
                if detected:
                    results["detected"] += 1
                else:
                    results["bypassed"] += 1
                
                # 记录详细结果
                test_result = AttackTestResult(
                    payload_id=f"input_{i}",
                    payload=payload,
                    shield_response=response,
                    detected=detected,
                    bypassed=bypassed,
                    execution_time=execution_time,
                    timestamp=datetime.now(timezone.utc)
                )
                
                self.test_results.append(test_result)
                results["details"].append(test_result)
                
            except Exception as e:
                results["errors"] += 1
                error_result = AttackTestResult(
                    payload_id=f"input_{i}",
                    payload=payload,
                    shield_response={},
                    detected=False,
                    bypassed=False,
                    execution_time=0.0,
                    timestamp=datetime.now(timezone.utc),
                    error=str(e)
                )
                self.test_results.append(error_result)
                results["details"].append(error_result)
        
        return results
    
    def test_memory_shield(self, shield: Any) -> Dict[str, Any]:
        """测试Memory Shield
        
        Args:
            shield: MemoryShield实例
            
        Returns:
            Dict: 测试结果统计
        """
        print("🧠 Testing Memory Shield...")
        
        # 获取所有记忆投毒payload
        payloads = self.memory_poisoner.get_all_payloads()
        
        results = {
            "total": len(payloads),
            "detected": 0,
            "bypassed": 0,
            "errors": 0,
            "details": []
        }
        
        for i, payload in enumerate(payloads):
            print(f"  Testing payload {i+1}/{len(payloads)}: {payload['technique']}")
            
            try:
                start_time = time.time()
                
                # 对于记忆攻击，测试整个payload结构
                response = self._scan_with_shield(shield, payload["payload"])
                
                execution_time = time.time() - start_time
                
                detected = not response.get("safe", True)
                bypassed = response.get("safe", True)
                
                if detected:
                    results["detected"] += 1
                else:
                    results["bypassed"] += 1
                
                test_result = AttackTestResult(
                    payload_id=f"memory_{i}",
                    payload=payload,
                    shield_response=response,
                    detected=detected,
                    bypassed=bypassed,
                    execution_time=execution_time,
                    timestamp=datetime.now(timezone.utc)
                )
                
                self.test_results.append(test_result)
                results["details"].append(test_result)
                
            except Exception as e:
                results["errors"] += 1
                error_result = AttackTestResult(
                    payload_id=f"memory_{i}",
                    payload=payload,
                    shield_response={},
                    detected=False,
                    bypassed=False,
                    execution_time=0.0,
                    timestamp=datetime.now(timezone.utc),
                    error=str(e)
                )
                self.test_results.append(error_result)
                results["details"].append(error_result)
        
        return results
    
    def test_action_shield(self, shield: Any) -> Dict[str, Any]:
        """测试Action Shield
        
        Args:
            shield: ActionShield实例
            
        Returns:
            Dict: 测试结果统计
        """
        print("⚡ Testing Action Shield...")
        
        # 获取所有工具滥用payload
        payloads = self.tool_abuser.get_all_payloads()
        
        results = {
            "total": len(payloads),
            "detected": 0,
            "bypassed": 0,
            "errors": 0,
            "details": []
        }
        
        for i, payload in enumerate(payloads):
            print(f"  Testing payload {i+1}/{len(payloads)}: {payload['technique']}")
            
            try:
                start_time = time.time()
                
                # 对于工具滥用攻击，测试payload内容
                test_content = payload["payload"]
                if isinstance(test_content, dict):
                    test_content = json.dumps(test_content)
                
                response = self._scan_with_shield(shield, test_content)
                
                execution_time = time.time() - start_time
                
                detected = not response.get("allowed", True) or not response.get("safe", True)
                bypassed = response.get("allowed", True) and response.get("safe", True)
                
                if detected:
                    results["detected"] += 1
                else:
                    results["bypassed"] += 1
                
                test_result = AttackTestResult(
                    payload_id=f"action_{i}",
                    payload=payload,
                    shield_response=response,
                    detected=detected,
                    bypassed=bypassed,
                    execution_time=execution_time,
                    timestamp=datetime.now(timezone.utc)
                )
                
                self.test_results.append(test_result)
                results["details"].append(test_result)
                
            except Exception as e:
                results["errors"] += 1
                error_result = AttackTestResult(
                    payload_id=f"action_{i}",
                    payload=payload,
                    shield_response={},
                    detected=False,
                    bypassed=False,
                    execution_time=0.0,
                    timestamp=datetime.now(timezone.utc),
                    error=str(e)
                )
                self.test_results.append(error_result)
                results["details"].append(error_result)
        
        return results
    
    def _test_input_shield(self, categories: List[str]) -> None:
        """内部方法：测试Input Shield"""
        if "input" not in self.target_shields:
            print("⚠️ Input Shield not available, skipping input tests")
            return
        
        shield = self.target_shields["input"]
        self.test_input_shield(shield)
    
    def _test_memory_shield(self, categories: List[str]) -> None:
        """内部方法：测试Memory Shield"""
        if "memory" not in self.target_shields:
            print("⚠️ Memory Shield not available, skipping memory tests")  
            return
        
        shield = self.target_shields["memory"]
        self.test_memory_shield(shield)
    
    def _test_action_shield(self, categories: List[str]) -> None:
        """内部方法：测试Action Shield"""
        if "action" not in self.target_shields:
            print("⚠️ Action Shield not available, skipping action tests")
            return
        
        shield = self.target_shields["action"]
        self.test_action_shield(shield)
    
    def _scan_with_shield(self, shield: Any, content: Any) -> Dict[str, Any]:
        """使用Shield扫描内容
        
        Args:
            shield: Shield实例
            content: 要扫描的内容
            
        Returns:
            Dict: 扫描结果
        """
        if hasattr(shield, 'scan'):
            result = shield.scan(content)
            # 标准化结果格式
            if hasattr(result, '__dict__'):
                return asdict(result)
            return result
        else:
            # 模拟扫描结果
            return {
                "safe": True,
                "threat_level": "LOW",
                "matched_patterns": [],
                "recommendation": "ALLOW"
            }
    
    def _generate_campaign_report(self, campaign_id: str) -> CampaignReport:
        """生成战役报告
        
        Args:
            campaign_id: 战役ID
            
        Returns:
            CampaignReport: 完整报告
        """
        if not self.campaign_start_time or not self.campaign_end_time:
            raise ValueError("Campaign times not set")
        
        duration = (self.campaign_end_time - self.campaign_start_time).total_seconds()
        
        # 统计总体结果
        total = len(self.test_results)
        detected = sum(1 for r in self.test_results if r.detected)
        bypassed = sum(1 for r in self.test_results if r.bypassed)
        errors = sum(1 for r in self.test_results if r.error is not None)
        
        # 按类别统计
        category_stats = {}
        for result in self.test_results:
            category = result.payload.get("category", "unknown")
            if category not in category_stats:
                category_stats[category] = {"total": 0, "detected": 0, "bypassed": 0, "errors": 0}
            
            category_stats[category]["total"] += 1
            if result.error:
                category_stats[category]["errors"] += 1
            elif result.detected:
                category_stats[category]["detected"] += 1
            else:
                category_stats[category]["bypassed"] += 1
        
        # 按严重程度统计
        severity_stats = {}
        for result in self.test_results:
            severity = result.payload.get("severity", "UNKNOWN")
            if severity not in severity_stats:
                severity_stats[severity] = {"total": 0, "detected": 0, "bypassed": 0, "errors": 0}
            
            severity_stats[severity]["total"] += 1
            if result.error:
                severity_stats[severity]["errors"] += 1
            elif result.detected:
                severity_stats[severity]["detected"] += 1
            else:
                severity_stats[severity]["bypassed"] += 1
        
        # 生成建议
        recommendations = self._generate_recommendations(category_stats, severity_stats)
        
        return CampaignReport(
            campaign_id=campaign_id,
            start_time=self.campaign_start_time,
            end_time=self.campaign_end_time,
            duration_seconds=duration,
            total_payloads=total,
            detected_count=detected,
            bypassed_count=bypassed,
            error_count=errors,
            detection_rate=detected / total if total > 0 else 0.0,
            bypass_rate=bypassed / total if total > 0 else 0.0,
            error_rate=errors / total if total > 0 else 0.0,
            results_by_category=category_stats,
            results_by_severity=severity_stats,
            detailed_results=self.test_results,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, category_stats: Dict, severity_stats: Dict) -> List[str]:
        """生成安全建议
        
        Args:
            category_stats: 按类别统计
            severity_stats: 按严重程度统计
            
        Returns:
            List[str]: 建议列表
        """
        recommendations = []
        
        # 检查高危绕过
        critical_bypassed = severity_stats.get("CRITICAL", {}).get("bypassed", 0)
        high_bypassed = severity_stats.get("HIGH", {}).get("bypassed", 0)
        
        if critical_bypassed > 0:
            recommendations.append(f"🚨 {critical_bypassed} CRITICAL severity attacks bypassed - immediate attention required")
        
        if high_bypassed > 0:
            recommendations.append(f"⚠️ {high_bypassed} HIGH severity attacks bypassed - review detection rules")
        
        # 按类别分析
        high_bypass_categories = []
        for category, stats in category_stats.items():
            if stats["total"] > 0:
                bypass_rate = stats["bypassed"] / stats["total"]
                if bypass_rate > 0.5:  # 超过50%绕过率
                    high_bypass_categories.append(f"{category} ({bypass_rate:.1%} bypassed)")
        
        if high_bypass_categories:
            recommendations.append(f"📈 High bypass rates in: {', '.join(high_bypass_categories)}")
        
        # 检测率建议
        overall_detection = sum(stats["detected"] for stats in category_stats.values())
        overall_total = sum(stats["total"] for stats in category_stats.values())
        
        if overall_total > 0:
            detection_rate = overall_detection / overall_total
            if detection_rate < 0.7:
                recommendations.append("🔍 Overall detection rate below 70% - consider updating detection rules")
            elif detection_rate > 0.9:
                recommendations.append("✅ Excellent detection rate - maintain current security posture")
        
        return recommendations
    
    def _save_report(self, report: CampaignReport) -> None:
        """保存报告到文件
        
        Args:
            report: 要保存的报告
        """
        # JSON格式报告
        json_file = self.report_dir / f"{report.campaign_id}_report.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False, default=str)
        
        # 文本格式摘要  
        text_file = self.report_dir / f"{report.campaign_id}_summary.txt"
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(self._format_text_report(report))
        
        print(f"📄 Reports saved to {self.report_dir}/")
    
    def _format_text_report(self, report: CampaignReport) -> str:
        """格式化文本报告
        
        Args:
            report: 报告对象
            
        Returns:
            str: 格式化的文本报告
        """
        lines = []
        lines.append("=" * 60)
        lines.append(f"Red Team Campaign Report: {report.campaign_id}")
        lines.append("=" * 60)
        lines.append("")
        
        # 基本信息
        lines.append(f"Start Time: {report.start_time}")
        lines.append(f"End Time: {report.end_time}")
        lines.append(f"Duration: {report.duration_seconds:.1f} seconds")
        lines.append("")
        
        # 统计摘要
        lines.append("SUMMARY")
        lines.append("-" * 20)
        lines.append(f"Total Payloads: {report.total_payloads}")
        lines.append(f"Detected: {report.detected_count} ({report.detection_rate:.1%})")
        lines.append(f"Bypassed: {report.bypassed_count} ({report.bypass_rate:.1%})")
        lines.append(f"Errors: {report.error_count} ({report.error_rate:.1%})")
        lines.append("")
        
        # 按类别统计
        lines.append("RESULTS BY CATEGORY")
        lines.append("-" * 30)
        for category, stats in report.results_by_category.items():
            total = stats["total"]
            detected = stats["detected"]
            bypassed = stats["bypassed"]
            detection_rate = detected / total if total > 0 else 0
            
            lines.append(f"{category}:")
            lines.append(f"  Total: {total}, Detected: {detected} ({detection_rate:.1%}), Bypassed: {bypassed}")
        
        lines.append("")
        
        # 按严重程度统计
        lines.append("RESULTS BY SEVERITY")
        lines.append("-" * 30)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in report.results_by_severity:
                stats = report.results_by_severity[severity]
                total = stats["total"]
                detected = stats["detected"]
                bypassed = stats["bypassed"]
                detection_rate = detected / total if total > 0 else 0
                
                lines.append(f"{severity}:")
                lines.append(f"  Total: {total}, Detected: {detected} ({detection_rate:.1%}), Bypassed: {bypassed}")
        
        lines.append("")
        
        # 建议
        if report.recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 20)
            for rec in report.recommendations:
                lines.append(f"• {rec}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def generate_report(self) -> Optional[CampaignReport]:
        """生成当前测试结果的报告
        
        Returns:
            CampaignReport: 报告，如果没有测试结果则返回None
        """
        if not self.test_results:
            return None
        
        # 如果没有设置战役时间，使用测试结果的时间范围
        if not self.campaign_start_time:
            self.campaign_start_time = min(r.timestamp for r in self.test_results)
        if not self.campaign_end_time:
            self.campaign_end_time = max(r.timestamp for r in self.test_results)
        
        campaign_id = f"manual_{int(time.time())}"
        return self._generate_campaign_report(campaign_id)