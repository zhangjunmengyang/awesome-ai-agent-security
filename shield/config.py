"""Configuration management for Shield Defense System

配置文件加载和管理，支持YAML格式配置。
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .models import ActionType, SeverityLevel


@dataclass
class InputShieldConfig:
    """Input Shield配置"""
    enabled: bool = True
    regex_patterns: str = "built-in"
    detect_file_refs: bool = True
    semantic_check: bool = False
    semantic_model: Optional[str] = None
    action: ActionType = ActionType.WARN


@dataclass
class ActionShieldConfig:
    """Action Shield配置"""
    enabled: bool = True
    dangerous_commands: List[Dict[str, Union[str, SeverityLevel]]] = field(default_factory=list)
    url_whitelist: List[str] = field(default_factory=list)
    detect_exfiltration: bool = True
    action: ActionType = ActionType.WARN


@dataclass
class SoulShieldConfig:
    """Soul Shield配置"""
    enabled: bool = True
    critical_files: List[str] = field(default_factory=lambda: [
        "SOUL.md", "IDENTITY.md", "AGENTS.md"
    ])
    monitored_files: List[str] = field(default_factory=lambda: [
        "HEARTBEAT.md", "TOOLS.md", "USER.md"
    ])
    write_protect: bool = True
    require_approval: bool = True
    max_versions: int = 10
    action: ActionType = ActionType.BLOCK


@dataclass
class MemoryShieldConfig:
    """Memory Shield配置"""
    enabled: bool = True
    watch_paths: List[str] = field(default_factory=lambda: [
        "MEMORY.md", "memory/*.md"
    ])
    detect_authority_injection: bool = True
    detect_external_urls: bool = True
    detect_behavior_directives: bool = True
    tag_sources: bool = True
    consistency_check: bool = True
    action: ActionType = ActionType.WARN


@dataclass
class PersonaShieldConfig:
    """Persona Shield配置"""
    enabled: bool = True
    check_interval: int = 10
    drift_threshold: float = 0.3
    anchor_method: str = "periodic_reload"
    requires_llm: bool = True
    action: ActionType = ActionType.WARN


@dataclass
class SupplyShieldConfig:
    """Supply Shield配置"""
    enabled: bool = True
    scan_skills: bool = True
    scan_node_modules: bool = False
    blocklist: str = "built-in"
    check_permissions: bool = True
    action: ActionType = ActionType.BLOCK


@dataclass
class LoggingConfig:
    """日志配置"""
    path: str = ".shield/audit.log"
    level: str = "INFO"
    max_size_mb: int = 10
    rotate: bool = True


@dataclass
class ShieldConfig:
    """Shield系统总配置"""
    workspace: str = "~/.openclaw/workspace"
    shields: Dict[str, Any] = field(default_factory=dict)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    # 各盾的具体配置
    input: InputShieldConfig = field(default_factory=InputShieldConfig)
    action: ActionShieldConfig = field(default_factory=ActionShieldConfig)
    soul: SoulShieldConfig = field(default_factory=SoulShieldConfig)
    memory: MemoryShieldConfig = field(default_factory=MemoryShieldConfig)
    persona: PersonaShieldConfig = field(default_factory=PersonaShieldConfig)
    supply: SupplyShieldConfig = field(default_factory=SupplyShieldConfig)
    
    def __post_init__(self):
        # 展开用户路径
        self.workspace = os.path.expanduser(self.workspace)
        self.logging.path = os.path.expanduser(self.logging.path)
    
    def get_url_whitelist(self) -> List[str]:
        """获取URL白名单"""
        return self.action.url_whitelist
    
    def get_dangerous_commands(self) -> List[Dict[str, any]]:
        """获取危险命令配置"""
        return self.action.dangerous_commands
    
    def get_max_external_requests(self) -> int:
        """获取最大外部请求数"""
        return 20  # 默认值
    
    def get_shield_config(self, shield_type: str):
        """获取特定盾的配置"""
        return getattr(self, shield_type, None)
    
    def get_canary_count(self) -> int:
        """获取金丝雀令牌数量"""
        return 5  # 默认值


class ConfigLoader:
    """配置加载器"""
    
    DEFAULT_CONFIG_PATHS = [
        "shield.yaml",
        "data/shield.yaml",
        ".shield/config.yaml",
        os.path.expanduser("~/.shield/config.yaml"),
        os.path.expanduser("~/.openclaw/workspace/shield.yaml")
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化配置加载器
        
        Args:
            config_path: 指定的配置文件路径，None则自动查找
        """
        self.config_path = config_path
        self._config: Optional[ShieldConfig] = None
    
    def _find_config_file(self) -> Optional[Path]:
        """查找配置文件
        
        Returns:
            找到的配置文件路径，None表示未找到
        """
        search_paths = [self.config_path] if self.config_path else []
        search_paths.extend(self.DEFAULT_CONFIG_PATHS)
        
        for path_str in search_paths:
            if not path_str:
                continue
                
            path = Path(path_str).expanduser().resolve()
            if path.exists() and path.is_file():
                return path
        
        return None
    
    def _load_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """加载YAML文件
        
        Args:
            file_path: YAML文件路径
            
        Returns:
            解析后的配置字典
            
        Raises:
            FileNotFoundError: 文件不存在
            yaml.YAMLError: YAML格式错误
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    
    def _create_default_config(self) -> ShieldConfig:
        """创建默认配置
        
        Returns:
            默认的ShieldConfig实例
        """
        config = ShieldConfig()
        
        # 设置默认的危险命令模式
        config.action.dangerous_commands = [
            {"pattern": r"curl.*-d.*@", "level": "high"},
            {"pattern": r"ssh.*@", "level": "medium"},
            {"pattern": r"rm -rf", "level": "high"},
            {"pattern": r"wget.*-O.*\|.*sh", "level": "critical"},
            {"pattern": r"python.*-c.*exec\(", "level": "high"}
        ]
        
        # 设置默认的URL白名单
        config.action.url_whitelist = [
            "github.com",
            "arxiv.org", 
            "api.anthropic.com",
            "discord.com",
            "stackoverflow.com",
            "docs.python.org",
            "api.openai.com",
            "huggingface.co",
            "pypi.org",
            "npmjs.com",
            "google.com",
            "en.wikipedia.org",
            "raw.githubusercontent.com"
        ]
        
        return config
    
    def _merge_configs(self, base_config: ShieldConfig, 
                      yaml_config: Dict[str, Any]) -> ShieldConfig:
        """合并配置
        
        Args:
            base_config: 基础配置
            yaml_config: YAML配置字典
            
        Returns:
            合并后的配置
        """
        # 深拷贝基础配置
        import copy
        config = copy.deepcopy(base_config)
        
        # 基础设置
        if "workspace" in yaml_config:
            config.workspace = yaml_config["workspace"]
        
        # 日志设置
        if "logging" in yaml_config:
            logging_config = yaml_config["logging"]
            for key, value in logging_config.items():
                if hasattr(config.logging, key):
                    setattr(config.logging, key, value)
        
        # 各盾设置
        if "shields" in yaml_config:
            shields = yaml_config["shields"]
            
            for shield_name in ["input", "action", "soul", "memory", "persona", "supply"]:
                if shield_name in shields:
                    shield_config = getattr(config, shield_name)
                    yaml_shield_config = shields[shield_name]
                    
                    for key, value in yaml_shield_config.items():
                        if hasattr(shield_config, key):
                            # 特殊处理action字段
                            if key == "action" and isinstance(value, str):
                                try:
                                    setattr(shield_config, key, ActionType(value))
                                except ValueError:
                                    pass  # 保留默认值
                            else:
                                setattr(shield_config, key, value)
        
        return config
    
    def load(self) -> ShieldConfig:
        """加载配置
        
        Returns:
            加载的配置对象
        """
        if self._config is not None:
            return self._config
        
        # 创建默认配置
        config = self._create_default_config()
        
        # 查找并加载配置文件
        config_file = self._find_config_file()
        if config_file:
            try:
                yaml_config = self._load_yaml_file(config_file)
                config = self._merge_configs(config, yaml_config)
            except Exception as e:
                print(f"Warning: Failed to load config from {config_file}: {e}")
                print("Using default configuration")
        
        self._config = config
        return config
    
    def reload(self) -> ShieldConfig:
        """重新加载配置
        
        Returns:
            重新加载的配置对象
        """
        self._config = None
        return self.load()
    
    def save_default_config(self, output_path: str = "data/default.yaml"):
        """保存默认配置到文件
        
        Args:
            output_path: 输出文件路径
        """
        config = self._create_default_config()
        
        # 转换为字典格式
        config_dict = {
            "workspace": config.workspace,
            "shields": {
                "input": {
                    "enabled": config.input.enabled,
                    "regex_patterns": config.input.regex_patterns,
                    "detect_file_refs": config.input.detect_file_refs,
                    "semantic_check": config.input.semantic_check,
                    "semantic_model": config.input.semantic_model,
                    "action": config.input.action.value
                },
                "action": {
                    "enabled": config.action.enabled,
                    "dangerous_commands": config.action.dangerous_commands,
                    "url_whitelist": config.action.url_whitelist,
                    "detect_exfiltration": config.action.detect_exfiltration,
                    "action": config.action.action.value
                },
                "soul": {
                    "enabled": config.soul.enabled,
                    "critical_files": config.soul.critical_files,
                    "monitored_files": config.soul.monitored_files,
                    "write_protect": config.soul.write_protect,
                    "require_approval": config.soul.require_approval,
                    "max_versions": config.soul.max_versions,
                    "action": config.soul.action.value
                },
                "memory": {
                    "enabled": config.memory.enabled,
                    "watch_paths": config.memory.watch_paths,
                    "detect_authority_injection": config.memory.detect_authority_injection,
                    "detect_external_urls": config.memory.detect_external_urls,
                    "detect_behavior_directives": config.memory.detect_behavior_directives,
                    "tag_sources": config.memory.tag_sources,
                    "consistency_check": config.memory.consistency_check,
                    "action": config.memory.action.value
                },
                "persona": {
                    "enabled": config.persona.enabled,
                    "check_interval": config.persona.check_interval,
                    "drift_threshold": config.persona.drift_threshold,
                    "anchor_method": config.persona.anchor_method,
                    "requires_llm": config.persona.requires_llm,
                    "action": config.persona.action.value
                },
                "supply": {
                    "enabled": config.supply.enabled,
                    "scan_skills": config.supply.scan_skills,
                    "scan_node_modules": config.supply.scan_node_modules,
                    "blocklist": config.supply.blocklist,
                    "check_permissions": config.supply.check_permissions,
                    "action": config.supply.action.value
                }
            },
            "logging": {
                "path": config.logging.path,
                "level": config.logging.level,
                "max_size_mb": config.logging.max_size_mb,
                "rotate": config.logging.rotate
            }
        }
        
        # 创建输出目录
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入YAML文件
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=True)
        
        print(f"Default configuration saved to: {output_path}")


# 全局配置加载器
_config_loader: Optional[ConfigLoader] = None


def get_config(config_path: Optional[str] = None) -> ShieldConfig:
    """获取配置
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        Shield配置对象
    """
    global _config_loader
    
    if _config_loader is None:
        _config_loader = ConfigLoader(config_path)
    
    return _config_loader.load()


def reload_config() -> ShieldConfig:
    """重新加载配置
    
    Returns:
        重新加载的配置对象
    """
    global _config_loader
    
    if _config_loader is not None:
        return _config_loader.reload()
    
    return get_config()