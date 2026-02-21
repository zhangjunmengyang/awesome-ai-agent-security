"""
Red Team Toolkit for Agent-Sentinel-Shield Testing
==================================================

攻击模拟工具集，用于测试AI Agent防御系统的有效性。

组件:
- InjectionPayloadGenerator: 提示注入攻击库
- MemoryPoisoner: 记忆投毒攻击库  
- ToolAbuser: 工具滥用攻击库
- RedTeamRunner: 红队测试框架

Usage:
    from attacks import InjectionPayloadGenerator, RedTeamRunner
    
    # 生成攻击payload
    generator = InjectionPayloadGenerator()
    payloads = generator.direct_injection()
    
    # 运行红队测试
    runner = RedTeamRunner(target_shield)
    results = runner.run_campaign()
"""

from .prompt_injection import InjectionPayloadGenerator
from .memory_poisoning import MemoryPoisoner  
from .tool_abuse import ToolAbuser
from .red_team import RedTeamRunner

__version__ = "1.0.0"
__all__ = [
    "InjectionPayloadGenerator",
    "MemoryPoisoner", 
    "ToolAbuser",
    "RedTeamRunner",
]