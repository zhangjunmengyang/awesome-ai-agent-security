"""
Red Team Toolkit Tests
======================

测试红队攻击模拟工具的各个组件。

测试内容：
- Payload生成（数量、格式、必要字段）
- RedTeamRunner基本运行
- Shield检测率统计
"""

import pytest
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from attacks.prompt_injection import InjectionPayloadGenerator
from attacks.memory_poisoning import MemoryPoisoner
from attacks.tool_abuse import ToolAbuser
from attacks.red_team import RedTeamRunner, AttackTestResult, CampaignReport


class TestInjectionPayloadGenerator:
    """测试提示注入攻击payload生成器"""
    
    def setup_method(self):
        """设置测试环境"""
        self.generator = InjectionPayloadGenerator()
    
    def test_direct_injection_generation(self):
        """测试直接注入payload生成"""
        payloads = self.generator.direct_injection()
        
        # 检查数量
        assert len(payloads) > 0, "Should generate at least one direct injection payload"
        assert len(payloads) >= 5, "Should generate multiple direct injection payloads"
        
        # 检查格式
        for payload in payloads:
            assert isinstance(payload, dict), "Payload should be a dictionary"
            
            # 必要字段检查
            required_fields = ['payload', 'technique', 'description', 'severity', 'category']
            for field in required_fields:
                assert field in payload, f"Payload missing required field: {field}"
            
            # 字段值检查
            assert payload['category'] == 'direct_injection', "Category should be direct_injection"
            assert payload['severity'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], "Invalid severity level"
            assert len(payload['payload']) > 0, "Payload content should not be empty"
            assert len(payload['technique']) > 0, "Technique should not be empty"
            assert len(payload['description']) > 0, "Description should not be empty"
    
    def test_indirect_injection_generation(self):
        """测试间接注入payload生成"""
        payloads = self.generator.indirect_injection()
        
        assert len(payloads) > 0, "Should generate indirect injection payloads"
        
        for payload in payloads:
            assert payload['category'] == 'indirect_injection'
            assert 'payload' in payload
            assert 'technique' in payload
            # 间接注入通常包含HTML、JSON、邮件等结构化内容
            payload_content = payload['payload']
            assert isinstance(payload_content, str)
    
    def test_obfuscation_injection_generation(self):
        """测试混淆注入payload生成"""
        payloads = self.generator.obfuscation_injection()
        
        assert len(payloads) > 0, "Should generate obfuscation injection payloads"
        
        # 检查是否包含各种混淆技术
        techniques = [p['technique'] for p in payloads]
        assert any('base64' in tech for tech in techniques), "Should include base64 obfuscation"
        assert any('unicode' in tech for tech in techniques), "Should include unicode obfuscation"
        
        for payload in payloads:
            assert payload['category'] == 'obfuscation_injection'
    
    def test_crescendo_attack_generation(self):
        """测试渐进式攻击payload生成"""
        payloads = self.generator.crescendo_attack()
        
        assert len(payloads) > 0, "Should generate crescendo attack payloads"
        
        # 检查是否有多个阶段
        techniques = [p['technique'] for p in payloads]
        stages = [tech for tech in techniques if 'stage' in tech]
        assert len(stages) >= 2, "Crescendo attack should have multiple stages"
        
        for payload in payloads:
            assert payload['category'] == 'crescendo_attack'
    
    def test_authority_spoofing_generation(self):
        """测试权威伪造攻击payload生成"""
        payloads = self.generator.authority_spoofing()
        
        assert len(payloads) > 0, "Should generate authority spoofing payloads"
        
        # 检查严重程度（权威伪造通常是高危攻击）
        severities = [p['severity'] for p in payloads]
        assert 'CRITICAL' in severities or 'HIGH' in severities, "Authority spoofing should include high severity attacks"
        
        for payload in payloads:
            assert payload['category'] == 'authority_spoofing'
    
    def test_multilingual_payloads(self):
        """测试多语言payload生成"""
        all_payloads = self.generator.get_all_payloads()
        
        # 检查是否包含中英文payload
        languages = [p.get('language', 'en') for p in all_payloads]
        assert 'en' in languages, "Should include English payloads"
        assert 'zh' in languages, "Should include Chinese payloads"
        
        # 检查中文payload内容
        zh_payloads = [p for p in all_payloads if p.get('language') == 'zh']
        assert len(zh_payloads) > 0, "Should have Chinese payloads"
        
        for payload in zh_payloads:
            # 中文payload应该包含中文字符
            content = payload['payload']
            assert any('\u4e00' <= char <= '\u9fff' for char in content), "Chinese payload should contain Chinese characters"
    
    def test_get_all_payloads(self):
        """测试获取所有payload"""
        all_payloads = self.generator.get_all_payloads()
        
        assert len(all_payloads) > 0, "Should generate payloads"
        
        # 统计各类别数量
        categories = {}
        for payload in all_payloads:
            cat = payload.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        
        # 应该包含所有支持的类别
        expected_categories = ['direct_injection', 'indirect_injection', 'obfuscation_injection',
                             'crescendo_attack', 'authority_spoofing']
        for cat in expected_categories:
            assert cat in categories, f"Missing category: {cat}"
    
    def test_payload_filtering(self):
        """测试payload过滤功能"""
        # 按类别过滤
        direct_payloads = self.generator.get_payloads_by_category('direct_injection')
        assert all(p['category'] == 'direct_injection' for p in direct_payloads)
        
        # 按严重程度过滤
        critical_payloads = self.generator.get_payloads_by_severity('CRITICAL')
        assert all(p['severity'] == 'CRITICAL' for p in critical_payloads)


class TestMemoryPoisoner:
    """测试记忆投毒攻击生成器"""
    
    def setup_method(self):
        """设置测试环境"""
        self.poisoner = MemoryPoisoner()
    
    def test_authority_injection_generation(self):
        """测试权威注入攻击payload生成"""
        payloads = self.poisoner.authority_injection()
        
        assert len(payloads) > 0, "Should generate authority injection payloads"
        
        for payload in payloads:
            assert payload['category'] == 'authority_injection'
            assert payload['severity'] in ['HIGH', 'CRITICAL'], "Authority injection should be high severity"
            
            # 检查payload结构（应该包含记忆条目结构）
            memory_payload = payload['payload']
            assert isinstance(memory_payload, dict), "Memory payload should be structured"
            assert 'content' in memory_payload, "Memory payload should have content"
            assert 'source' in memory_payload, "Memory payload should have source"
            assert 'trust_level' in memory_payload, "Memory payload should have trust_level"
    
    def test_behavior_modification_generation(self):
        """测试行为修改攻击payload生成"""
        payloads = self.poisoner.behavior_modification()
        
        assert len(payloads) > 0, "Should generate behavior modification payloads"
        
        # 检查是否有渐进式攻击序列
        techniques = [p['technique'] for p in payloads]
        stages = [tech for tech in techniques if 'stage' in tech]
        assert len(stages) >= 2, "Behavior modification should include multi-stage attacks"
        
        for payload in payloads:
            assert payload['category'] == 'behavior_modification'
    
    def test_identity_corruption_generation(self):
        """测试身份篡改攻击payload生成"""
        payloads = self.poisoner.identity_corruption()
        
        assert len(payloads) > 0, "Should generate identity corruption payloads"
        
        # 检查是否涉及SOUL.md等身份文件
        soul_related = [p for p in payloads if 'SOUL' in str(p['payload'])]
        assert len(soul_related) > 0, "Should include SOUL.md related attacks"
        
        for payload in payloads:
            assert payload['category'] == 'identity_corruption'
            assert payload['severity'] in ['HIGH', 'CRITICAL'], "Identity corruption should be high severity"
    
    def test_persistent_backdoor_generation(self):
        """测试持久化后门攻击payload生成"""
        payloads = self.poisoner.persistent_backdoor()
        
        assert len(payloads) > 0, "Should generate persistent backdoor payloads"
        
        # 检查是否有触发机制
        trigger_related = [p for p in payloads if 'trigger' in p['technique']]
        assert len(trigger_related) > 0, "Should include trigger-based backdoors"
        
        for payload in payloads:
            assert payload['category'] == 'persistent_backdoor'
    
    def test_canary_poisoning_generation(self):
        """测试金丝雀投毒攻击payload生成"""
        payloads = self.poisoner.canary_poisoning()
        
        assert len(payloads) > 0, "Should generate canary poisoning payloads"
        
        # 检查是否涉及canary token处理
        canary_related = [p for p in payloads if 'canary' in p['technique'].lower()]
        assert len(canary_related) > 0, "Should include canary-specific attacks"
        
        for payload in payloads:
            assert payload['category'] == 'canary_poisoning'


class TestToolAbuser:
    """测试工具滥用攻击生成器"""
    
    def setup_method(self):
        """设置测试环境"""
        self.abuser = ToolAbuser()
    
    def test_data_exfiltration_generation(self):
        """测试数据外泄攻击payload生成"""
        payloads = self.abuser.data_exfiltration()
        
        assert len(payloads) > 0, "Should generate data exfiltration payloads"
        
        # 检查是否包含各种外泄技术
        techniques = [p['technique'] for p in payloads]
        assert any('curl' in tech for tech in techniques), "Should include curl-based exfiltration"
        assert any('base64' in tech for tech in techniques), "Should include base64 encoding"
        
        for payload in payloads:
            assert payload['category'] == 'data_exfiltration'
    
    def test_command_injection_generation(self):
        """测试命令注入攻击payload生成"""
        payloads = self.abuser.command_injection()
        
        assert len(payloads) > 0, "Should generate command injection payloads"
        
        # 检查是否包含各种注入技术
        techniques = [p['technique'] for p in payloads]
        assert any('pipe' in tech for tech in techniques), "Should include pipe injection"
        assert any('semicolon' in tech for tech in techniques), "Should include semicolon chaining"
        
        for payload in payloads:
            assert payload['category'] == 'command_injection'
            assert payload['severity'] in ['HIGH', 'CRITICAL'], "Command injection should be high severity"
    
    def test_privilege_escalation_generation(self):
        """测试权限提升攻击payload生成"""
        payloads = self.abuser.privilege_escalation()
        
        assert len(payloads) > 0, "Should generate privilege escalation payloads"
        
        # 检查是否包含各种提权技术
        techniques = [p['technique'] for p in payloads]
        assert any('sudo' in tech for tech in techniques), "Should include sudo abuse"
        assert any('setuid' in tech or 'suid' in tech for tech in techniques), "Should include SUID attacks"
        
        for payload in payloads:
            assert payload['category'] == 'privilege_escalation'
    
    def test_supply_chain_attack_generation(self):
        """测试供应链攻击payload生成"""
        payloads = self.abuser.supply_chain_attack()
        
        assert len(payloads) > 0, "Should generate supply chain attack payloads"
        
        # 检查payload结构（供应链攻击通常包含复杂的包结构）
        for payload in payloads:
            assert payload['category'] == 'supply_chain_attack'
            attack_payload = payload['payload']
            assert isinstance(attack_payload, dict), "Supply chain payload should be structured"


class TestRedTeamRunner:
    """测试红队测试执行器"""
    
    def setup_method(self):
        """设置测试环境"""
        self.runner = RedTeamRunner()
        
        # 创建测试用的临时报告目录
        self.test_report_dir = Path("./test_red_team_reports")
        self.test_report_dir.mkdir(exist_ok=True)
        self.runner.report_dir = self.test_report_dir
    
    def teardown_method(self):
        """清理测试环境"""
        import shutil
        if self.test_report_dir.exists():
            shutil.rmtree(self.test_report_dir)
    
    def test_runner_initialization(self):
        """测试红队执行器初始化"""
        assert self.runner.injection_generator is not None
        assert self.runner.memory_poisoner is not None
        assert self.runner.tool_abuser is not None
        assert self.runner.test_results == []
    
    def test_mock_shield_testing(self):
        """测试使用模拟Shield的测试功能"""
        # 创建模拟Shield
        class MockShield:
            def __init__(self, detection_rate=0.7):
                self.detection_rate = detection_rate
            
            def scan(self, content):
                # 模拟检测逻辑：随机返回检测结果
                import random
                detected = random.random() < self.detection_rate
                return {
                    'safe': not detected,
                    'threat_level': 'HIGH' if detected else 'LOW',
                    'matched_patterns': ['test_pattern'] if detected else [],
                    'recommendation': 'BLOCK' if detected else 'ALLOW'
                }
        
        mock_shield = MockShield(detection_rate=0.8)
        
        # 测试单个Shield
        results = self.runner.test_input_shield(mock_shield)
        
        assert 'total' in results
        assert 'detected' in results
        assert 'bypassed' in results
        assert 'errors' in results
        assert results['total'] > 0
        assert results['detected'] + results['bypassed'] + results['errors'] == results['total']
    
    def test_campaign_execution(self):
        """测试完整战役执行"""
        # 使用模拟Shield运行小规模战役
        mock_shields = {
            'input': type('MockShield', (), {
                'scan': lambda self, content: {'safe': True, 'threat_level': 'LOW'}
            })()
        }
        
        runner = RedTeamRunner(mock_shields)
        runner.report_dir = self.test_report_dir
        
        # 运行有限类别的测试以减少测试时间
        limited_categories = ['direct_injection', 'data_exfiltration']
        
        report = runner.run_campaign(
            categories=limited_categories,
            shield_types=['input']
        )
        
        # 验证报告结构
        assert isinstance(report, CampaignReport)
        assert report.campaign_id is not None
        assert report.total_payloads > 0
        assert report.detection_rate >= 0.0
        assert report.bypass_rate >= 0.0
        assert report.error_rate >= 0.0
        assert abs(report.detection_rate + report.bypass_rate + report.error_rate - 1.0) < 0.01
    
    def test_results_statistics(self):
        """测试结果统计功能"""
        # 创建测试结果
        test_results = [
            AttackTestResult(
                payload_id="test_1",
                payload={
                    'category': 'direct_injection',
                    'severity': 'HIGH',
                    'technique': 'test_tech'
                },
                shield_response={'safe': False},
                detected=True,
                bypassed=False,
                execution_time=0.1,
                timestamp=datetime.now(timezone.utc)
            ),
            AttackTestResult(
                payload_id="test_2",
                payload={
                    'category': 'direct_injection',
                    'severity': 'MEDIUM',
                    'technique': 'test_tech2'
                },
                shield_response={'safe': True},
                detected=False,
                bypassed=True,
                execution_time=0.05,
                timestamp=datetime.now(timezone.utc)
            )
        ]
        
        self.runner.test_results = test_results
        self.runner.campaign_start_time = datetime.now(timezone.utc)
        self.runner.campaign_end_time = datetime.now(timezone.utc)
        
        report = self.runner.generate_report()
        
        assert report is not None
        assert report.total_payloads == 2
        assert report.detected_count == 1
        assert report.bypassed_count == 1
        assert report.error_count == 0
        assert report.detection_rate == 0.5
    
    def test_report_generation_and_saving(self):
        """测试报告生成和保存功能"""
        # 创建最小测试数据
        self.runner.test_results = [
            AttackTestResult(
                payload_id="test_1",
                payload={
                    'category': 'test_category',
                    'severity': 'MEDIUM',
                    'technique': 'test_technique'
                },
                shield_response={'safe': True},
                detected=False,
                bypassed=True,
                execution_time=0.1,
                timestamp=datetime.now(timezone.utc)
            )
        ]
        
        self.runner.campaign_start_time = datetime.now(timezone.utc)
        time.sleep(0.1)  # 确保有时间差
        self.runner.campaign_end_time = datetime.now(timezone.utc)
        
        report = self.runner._generate_campaign_report("test_campaign")
        self.runner._save_report(report)
        
        # 验证报告文件生成
        json_file = self.test_report_dir / "test_campaign_report.json"
        text_file = self.test_report_dir / "test_campaign_summary.txt"
        
        assert json_file.exists(), "JSON report should be generated"
        assert text_file.exists(), "Text summary should be generated"
        
        # 验证JSON报告内容
        with open(json_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        assert report_data['campaign_id'] == "test_campaign"
        assert report_data['total_payloads'] == 1
        assert 'results_by_category' in report_data
        assert 'results_by_severity' in report_data
    
    def test_recommendations_generation(self):
        """测试安全建议生成功能"""
        # 模拟高危攻击绕过场景
        category_stats = {
            'direct_injection': {
                'total': 10,
                'detected': 3,
                'bypassed': 7,
                'errors': 0
            }
        }
        
        severity_stats = {
            'CRITICAL': {
                'total': 5,
                'detected': 1,
                'bypassed': 4,
                'errors': 0
            },
            'HIGH': {
                'total': 3,
                'detected': 1,
                'bypassed': 2,
                'errors': 0
            }
        }
        
        recommendations = self.runner._generate_recommendations(category_stats, severity_stats)
        
        assert len(recommendations) > 0, "Should generate recommendations for poor performance"
        
        # 检查是否包含关键建议
        rec_text = ' '.join(recommendations)
        assert 'CRITICAL' in rec_text, "Should mention critical severity bypasses"
        assert 'direct_injection' in rec_text, "Should mention high bypass rate categories"


class TestIntegration:
    """集成测试"""
    
    def test_payload_generation_integration(self):
        """测试所有payload生成器集成"""
        generators = [
            InjectionPayloadGenerator(),
            MemoryPoisoner(),
            ToolAbuser()
        ]
        
        total_payloads = 0
        all_categories = set()
        all_severities = set()
        
        for generator in generators:
            payloads = generator.get_all_payloads()
            total_payloads += len(payloads)
            
            for payload in payloads:
                all_categories.add(payload['category'])
                all_severities.add(payload['severity'])
        
        assert total_payloads > 50, "Should generate substantial number of payloads across all generators"
        assert len(all_categories) >= 10, "Should cover multiple attack categories"
        assert all_severities >= {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}, "Should include all severity levels"
    
    def test_end_to_end_simulation(self):
        """端到端模拟测试"""
        # 创建简单的模拟Shield
        class DetectionShield:
            def scan(self, content):
                # 简单的检测逻辑：检测包含"ignore"的内容
                if isinstance(content, dict):
                    content = str(content)
                detected = 'ignore' in content.lower()
                return {
                    'safe': not detected,
                    'threat_level': 'HIGH' if detected else 'LOW',
                    'matched_patterns': ['ignore_pattern'] if detected else []
                }
        
        shields = {'input': DetectionShield()}
        runner = RedTeamRunner(shields)
        
        # 设置临时报告目录
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            runner.report_dir = Path(temp_dir)
            
            # 运行小规模测试
            report = runner.run_campaign(
                categories=['direct_injection'],
                shield_types=['input']
            )
            
            # 验证结果合理性
            assert report.total_payloads > 0
            assert 0 <= report.detection_rate <= 1
            assert 0 <= report.bypass_rate <= 1
            assert report.detection_rate + report.bypass_rate + report.error_rate == pytest.approx(1.0, abs=0.01)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])