"""
Red Team CLI - Attack Simulation Command Line Interface
=======================================================

提供命令行接口来使用红队攻击模拟工具。

Commands:
- list: 列出所有攻击类别和payload数量
- generate: 生成指定类别的攻击payload
- run: 运行红队测试战役
- report: 查看测试报告
"""

import json
import click
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from .prompt_injection import InjectionPayloadGenerator
from .memory_poisoning import MemoryPoisoner
from .tool_abuse import ToolAbuser  
from .red_team import RedTeamRunner

# 尝试导入shield模块
try:
    from shield.config import get_config
    from shield.core.input_shield import InputShield
    from shield.core.memory_shield import MemoryShield
    from shield.core.action_shield import ActionShield
    from shield.logger import get_logger
    SHIELD_AVAILABLE = True
except ImportError:
    SHIELD_AVAILABLE = False
    print("⚠️ Shield modules not available - running in simulation mode")


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def attack(ctx, verbose):
    """🔴 Red Team Attack Simulation Toolkit
    
    用于测试AI Agent防御系统的攻击模拟工具集。
    
    Examples:
        attack list                           # 列出所有攻击类别
        attack generate --category direct_injection
        attack run --target shield_config.yaml
        attack report --latest
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@attack.command()
@click.option('--category', '-c', help='Filter by specific attack category')
@click.option('--severity', '-s', help='Filter by severity level (LOW/MEDIUM/HIGH/CRITICAL)')
def list(category, severity):
    """列出所有可用的攻击类别和payload数量
    
    显示每个攻击类别的payload数量、严重程度分布等统计信息。
    """
    print("🔴 Red Team Attack Payload Inventory")
    print("=" * 50)
    
    # 初始化生成器
    injection_gen = InjectionPayloadGenerator()
    memory_poisoner = MemoryPoisoner()
    tool_abuser = ToolAbuser()
    
    # 收集所有payload
    all_payloads = []
    all_payloads.extend(injection_gen.get_all_payloads())
    all_payloads.extend(memory_poisoner.get_all_payloads())
    all_payloads.extend(tool_abuser.get_all_payloads())
    
    # 应用过滤器
    filtered_payloads = all_payloads
    if category:
        filtered_payloads = [p for p in filtered_payloads if p.get('category') == category]
    if severity:
        filtered_payloads = [p for p in filtered_payloads if p.get('severity') == severity.upper()]
    
    # 按类别统计
    category_stats = {}
    severity_stats = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    
    for payload in filtered_payloads:
        cat = payload.get('category', 'unknown')
        sev = payload.get('severity', 'UNKNOWN')
        
        if cat not in category_stats:
            category_stats[cat] = {"count": 0, "severities": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}}
        
        category_stats[cat]["count"] += 1
        if sev in category_stats[cat]["severities"]:
            category_stats[cat]["severities"][sev] += 1
        
        if sev in severity_stats:
            severity_stats[sev] += 1
    
    # 显示类别统计
    print("\n📊 Payload Count by Category:")
    print("-" * 30)
    
    for cat, stats in sorted(category_stats.items()):
        count = stats["count"]
        critical = stats["severities"]["CRITICAL"]
        high = stats["severities"]["HIGH"]
        medium = stats["severities"]["MEDIUM"]
        low = stats["severities"]["LOW"]
        
        severity_breakdown = f"C:{critical} H:{high} M:{medium} L:{low}"
        print(f"{cat:25} {count:3d} payloads [{severity_breakdown}]")
    
    # 显示严重程度统计
    print(f"\n🚨 Severity Distribution:")
    print("-" * 25)
    total = sum(severity_stats.values())
    for sev, count in severity_stats.items():
        percentage = (count / total * 100) if total > 0 else 0
        print(f"{sev:8} {count:3d} payloads ({percentage:5.1f}%)")
    
    print(f"\n📈 Total Payloads: {total}")
    
    if category or severity:
        print(f"\n🔍 Filters Applied:")
        if category:
            print(f"   Category: {category}")
        if severity:
            print(f"   Severity: {severity}")


@attack.command()
@click.option('--category', '-c', required=True, help='Attack category to generate')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', 
              help='Output format (json or text)')
@click.option('--output', '-o', help='Output file path (default: stdout)')
@click.option('--limit', '-l', type=int, help='Limit number of payloads generated')
def generate(category, format, output, limit):
    """生成指定类别的攻击payload
    
    支持的类别：
    - direct_injection: 直接注入攻击  
    - indirect_injection: 间接注入攻击
    - obfuscation_injection: 混淆注入攻击
    - crescendo_attack: 渐进式攻击
    - authority_spoofing: 权威伪造攻击
    - authority_injection: 权威注入攻击
    - behavior_modification: 行为修改攻击
    - identity_corruption: 身份篡改攻击  
    - persistent_backdoor: 持久化后门攻击
    - canary_poisoning: 金丝雀投毒攻击
    - data_exfiltration: 数据外泄攻击
    - command_injection: 命令注入攻击
    - privilege_escalation: 权限提升攻击
    - supply_chain_attack: 供应链攻击
    """
    print(f"🎯 Generating {category} attack payloads...")
    
    # 初始化对应的生成器
    payloads = []
    
    # 提示注入类别
    if category in ["direct_injection", "indirect_injection", "obfuscation_injection", 
                   "crescendo_attack", "authority_spoofing"]:
        generator = InjectionPayloadGenerator()
        if category == "direct_injection":
            payloads = generator.direct_injection()
        elif category == "indirect_injection":
            payloads = generator.indirect_injection()
        elif category == "obfuscation_injection":
            payloads = generator.obfuscation_injection()
        elif category == "crescendo_attack":
            payloads = generator.crescendo_attack()
        elif category == "authority_spoofing":
            payloads = generator.authority_spoofing()
    
    # 记忆投毒类别
    elif category in ["authority_injection", "behavior_modification", "identity_corruption",
                     "persistent_backdoor", "canary_poisoning"]:
        generator = MemoryPoisoner()
        if category == "authority_injection":
            payloads = generator.authority_injection()
        elif category == "behavior_modification":
            payloads = generator.behavior_modification()
        elif category == "identity_corruption":
            payloads = generator.identity_corruption()
        elif category == "persistent_backdoor":
            payloads = generator.persistent_backdoor()
        elif category == "canary_poisoning":
            payloads = generator.canary_poisoning()
    
    # 工具滥用类别
    elif category in ["data_exfiltration", "command_injection", "privilege_escalation",
                     "supply_chain_attack"]:
        generator = ToolAbuser()
        if category == "data_exfiltration":
            payloads = generator.data_exfiltration()
        elif category == "command_injection":
            payloads = generator.command_injection()
        elif category == "privilege_escalation":
            payloads = generator.privilege_escalation()
        elif category == "supply_chain_attack":
            payloads = generator.supply_chain_attack()
    
    else:
        click.echo(f"❌ Unknown category: {category}", err=True)
        sys.exit(1)
    
    # 应用数量限制
    if limit and limit > 0:
        payloads = payloads[:limit]
    
    print(f"✅ Generated {len(payloads)} payloads")
    
    # 格式化输出
    if format == 'json':
        output_data = {
            "category": category,
            "generated_at": datetime.now().isoformat(),
            "count": len(payloads),
            "payloads": payloads
        }
        output_text = json.dumps(output_data, indent=2, ensure_ascii=False)
    else:  # text format
        lines = []
        lines.append(f"Attack Category: {category}")
        lines.append(f"Generated: {datetime.now()}")
        lines.append(f"Count: {len(payloads)}")
        lines.append("=" * 50)
        
        for i, payload in enumerate(payloads, 1):
            lines.append(f"\n[{i}] {payload.get('technique', 'Unknown')}")
            lines.append(f"Severity: {payload.get('severity', 'Unknown')}")
            lines.append(f"Description: {payload.get('description', 'No description')}")
            lines.append("Payload:")
            
            payload_content = payload.get('payload', '')
            if isinstance(payload_content, dict):
                lines.append(json.dumps(payload_content, indent=2, ensure_ascii=False))
            else:
                lines.append(str(payload_content))
            lines.append("-" * 30)
        
        output_text = "\n".join(lines)
    
    # 输出到文件或stdout
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(output_text)
        print(f"📄 Output saved to {output}")
    else:
        click.echo(output_text)


@attack.command()
@click.option('--target', '-t', help='Shield configuration file path')
@click.option('--categories', '-c', help='Comma-separated list of attack categories to test')
@click.option('--shields', '-s', help='Comma-separated list of shield types to test (input,memory,action)')
@click.option('--output', '-o', help='Report output directory (default: ./red_team_reports)')
@click.option('--dry-run', is_flag=True, help='Show what would be tested without actually running')
def run(target, categories, shields, output, dry_run):
    """运行红队测试战役
    
    对指定的Shield配置运行完整的攻击测试，生成详细报告。
    
    Examples:
        attack run --target shield.yaml
        attack run --categories direct_injection,command_injection
        attack run --shields input,action --dry-run
    """
    print("🚀 Preparing Red Team Campaign...")
    
    # 解析参数
    test_categories = None
    if categories:
        test_categories = [cat.strip() for cat in categories.split(',')]
    
    test_shields = None
    if shields:
        test_shields = [shield.strip() for shield in shields.split(',')]
    
    # 显示测试计划
    if dry_run:
        print("\n🔍 Dry Run - Test Plan:")
        print("-" * 30)
        print(f"Target config: {target or 'default simulation'}")
        print(f"Categories: {test_categories or 'all'}")
        print(f"Shields: {test_shields or 'all available'}")
        
        # 统计payload数量
        injection_gen = InjectionPayloadGenerator()
        memory_poisoner = MemoryPoisoner()
        tool_abuser = ToolAbuser()
        
        total_payloads = 0
        total_payloads += len(injection_gen.get_all_payloads())
        total_payloads += len(memory_poisoner.get_all_payloads())
        total_payloads += len(tool_abuser.get_all_payloads())
        
        print(f"Total payloads: ~{total_payloads}")
        print("\n✅ Dry run completed - use without --dry-run to execute")
        return
    
    # 初始化Shield实例
    target_shields = {}
    
    if SHIELD_AVAILABLE and target:
        try:
            # 加载Shield配置
            print(f"📖 Loading shield configuration from {target}")
            config = get_config(target)
            logger = get_logger("red_team")
            
            # 初始化各个Shield
            if not test_shields or 'input' in test_shields:
                target_shields['input'] = InputShield(config.input_shield, logger)
                print("✅ Input Shield loaded")
            
            if not test_shields or 'memory' in test_shields:
                target_shields['memory'] = MemoryShield(config.memory_shield, logger)
                print("✅ Memory Shield loaded")
            
            if not test_shields or 'action' in test_shields:
                target_shields['action'] = ActionShield(config.action_shield, logger)
                print("✅ Action Shield loaded")
                
        except Exception as e:
            print(f"⚠️ Failed to load shields: {e}")
            print("🔄 Running in simulation mode...")
            # 使用模拟Shield
            if not test_shields or 'input' in test_shields:
                target_shields['input'] = None
            if not test_shields or 'memory' in test_shields:
                target_shields['memory'] = None
            if not test_shields or 'action' in test_shields:
                target_shields['action'] = None
    else:
        print("🔄 Running in simulation mode (no shield config provided)")
        # 模拟模式
        if not test_shields or 'input' in test_shields:
            target_shields['input'] = None
        if not test_shields or 'memory' in test_shields:
            target_shields['memory'] = None
        if not test_shields or 'action' in test_shields:
            target_shields['action'] = None
    
    # 设置报告输出目录
    if output:
        report_dir = Path(output)
        report_dir.mkdir(exist_ok=True)
    
    # 初始化红队执行器
    runner = RedTeamRunner(target_shields)
    if output:
        runner.report_dir = Path(output)
    
    # 运行战役
    try:
        report = runner.run_campaign(categories=test_categories, shield_types=test_shields)
        
        # 显示摘要
        print("\n" + "=" * 60)
        print("🎯 Red Team Campaign Results")
        print("=" * 60)
        print(f"Campaign ID: {report.campaign_id}")
        print(f"Duration: {report.duration_seconds:.1f} seconds")
        print(f"Total Payloads: {report.total_payloads}")
        print(f"Detection Rate: {report.detection_rate:.1%} ({report.detected_count} detected)")
        print(f"Bypass Rate: {report.bypass_rate:.1%} ({report.bypassed_count} bypassed)")
        print(f"Error Rate: {report.error_rate:.1%} ({report.error_count} errors)")
        
        # 显示建议
        if report.recommendations:
            print("\n💡 Recommendations:")
            for rec in report.recommendations:
                print(f"  • {rec}")
        
        print(f"\n📄 Detailed reports saved in {runner.report_dir}/")
        
    except KeyboardInterrupt:
        print("\n⏹️ Campaign interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Campaign failed: {e}")
        sys.exit(1)


@attack.command()
@click.option('--latest', is_flag=True, help='Show the latest report')
@click.option('--campaign-id', help='Show specific campaign report')
@click.option('--list-all', is_flag=True, help='List all available reports')
@click.option('--format', type=click.Choice(['summary', 'detailed']), default='summary',
              help='Report detail level')
def report(latest, campaign_id, list_all, format):
    """查看红队测试报告
    
    浏览之前执行的测试战役结果和统计信息。
    
    Examples:
        attack report --latest              # 显示最新报告摘要
        attack report --campaign-id campaign_123 --format detailed
        attack report --list-all           # 列出所有报告
    """
    report_dir = Path("./red_team_reports")
    
    if not report_dir.exists():
        click.echo("📁 No reports directory found. Run 'attack run' first.", err=True)
        return
    
    # 查找报告文件
    json_reports = list(report_dir.glob("*_report.json"))
    
    if not json_reports:
        click.echo("📄 No reports found. Run 'attack run' first.", err=True)
        return
    
    if list_all:
        print("📊 Available Red Team Reports")
        print("=" * 40)
        
        for report_file in sorted(json_reports):
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                campaign_id = data.get('campaign_id', 'unknown')
                start_time = data.get('start_time', 'unknown')
                total_payloads = data.get('total_payloads', 0)
                detection_rate = data.get('detection_rate', 0) * 100
                
                print(f"📋 {campaign_id}")
                print(f"   Date: {start_time}")
                print(f"   Payloads: {total_payloads}, Detection: {detection_rate:.1f}%")
                print()
                
            except Exception as e:
                print(f"⚠️ Error reading {report_file}: {e}")
        
        return
    
    # 选择要显示的报告
    target_report = None
    
    if campaign_id:
        # 查找指定ID的报告
        for report_file in json_reports:
            if campaign_id in report_file.name:
                target_report = report_file
                break
        
        if not target_report:
            click.echo(f"❌ Campaign {campaign_id} not found", err=True)
            return
    
    elif latest:
        # 选择最新的报告
        target_report = max(json_reports, key=lambda f: f.stat().st_mtime)
    
    else:
        # 交互式选择
        if len(json_reports) == 1:
            target_report = json_reports[0]
        else:
            print("📊 Available reports:")
            for i, report_file in enumerate(sorted(json_reports), 1):
                print(f"  {i}. {report_file.stem}")
            
            while True:
                try:
                    choice = click.prompt("Select report number", type=int)
                    if 1 <= choice <= len(json_reports):
                        target_report = sorted(json_reports)[choice - 1]
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(json_reports)}")
                except (ValueError, KeyboardInterrupt):
                    print("Selection cancelled")
                    return
    
    # 加载并显示报告
    try:
        with open(target_report, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        print("\n" + "=" * 60)
        print(f"🎯 Red Team Campaign Report: {report_data.get('campaign_id')}")
        print("=" * 60)
        
        # 基本信息
        print(f"Start Time: {report_data.get('start_time')}")
        print(f"Duration: {report_data.get('duration_seconds', 0):.1f} seconds")
        print(f"Total Payloads: {report_data.get('total_payloads', 0)}")
        
        # 统计信息
        detection_rate = report_data.get('detection_rate', 0) * 100
        bypass_rate = report_data.get('bypass_rate', 0) * 100
        error_rate = report_data.get('error_rate', 0) * 100
        
        print(f"Detection Rate: {detection_rate:.1f}%")
        print(f"Bypass Rate: {bypass_rate:.1f}%")
        print(f"Error Rate: {error_rate:.1f}%")
        
        # 按类别统计
        category_results = report_data.get('results_by_category', {})
        if category_results:
            print("\n📊 Results by Category:")
            print("-" * 30)
            for category, stats in category_results.items():
                total = stats.get('total', 0)
                detected = stats.get('detected', 0) 
                detection_pct = (detected / total * 100) if total > 0 else 0
                print(f"{category:25} {detected:3d}/{total:3d} ({detection_pct:5.1f}%)")
        
        # 按严重程度统计
        severity_results = report_data.get('results_by_severity', {})
        if severity_results:
            print("\n🚨 Results by Severity:")
            print("-" * 25)
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in severity_results:
                    stats = severity_results[severity]
                    total = stats.get('total', 0)
                    detected = stats.get('detected', 0)
                    detection_pct = (detected / total * 100) if total > 0 else 0
                    print(f"{severity:8} {detected:3d}/{total:3d} ({detection_pct:5.1f}%)")
        
        # 建议
        recommendations = report_data.get('recommendations', [])
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
        
        # 详细结果（如果请求）
        if format == 'detailed':
            detailed_results = report_data.get('detailed_results', [])
            if detailed_results:
                print(f"\n🔍 Detailed Results ({len(detailed_results)} tests):")
                print("-" * 40)
                
                for i, result in enumerate(detailed_results[:20]):  # 限制显示前20个
                    payload = result.get('payload', {})
                    technique = payload.get('technique', 'unknown')
                    category = payload.get('category', 'unknown')
                    detected = result.get('detected', False)
                    exec_time = result.get('execution_time', 0)
                    
                    status = "🟢 DETECTED" if detected else "🔴 BYPASSED"
                    print(f"[{i+1:2d}] {technique:30} {category:15} {status} ({exec_time:.3f}s)")
                
                if len(detailed_results) > 20:
                    print(f"... and {len(detailed_results) - 20} more results")
        
        print("\n" + "=" * 60)
        
    except Exception as e:
        click.echo(f"❌ Error loading report: {e}", err=True)


if __name__ == '__main__':
    attack()