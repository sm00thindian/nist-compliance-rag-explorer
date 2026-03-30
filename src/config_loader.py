"""
Configuration loader for the NIST Compliance RAG Explorer.
Handles loading and validation of configuration settings.
"""
import os
import configparser
import logging
from typing import Dict, Any, Optional, List

class Config:
    """Configuration manager for the application."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = configparser.ConfigParser()
        self.config_path = config_path or self._find_config_file()

        if self.config_path and os.path.exists(self.config_path):
            self.config.read(self.config_path)
        else:
            # Load defaults from template
            template_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.ini.template')
            if os.path.exists(template_path):
                self.config.read(template_path)
            else:
                self._set_defaults()

    def _find_config_file(self) -> Optional[str]:
        """Find the config file in standard locations."""
        search_paths = [
            'config/config.ini',
            'config.ini',
            os.path.join(os.path.dirname(__file__), '..', 'config', 'config.ini')
        ]

        for path in search_paths:
            if os.path.exists(path):
                return path
        return None

    def _set_defaults(self):
        """Set default configuration values."""
        defaults = {
            'spacy_model': 'en_core_web_trf',
            'embedding_model': 'all-mpnet-base-v2',
            'embedding_dimensions': '768',
            'similarity_metric': 'cosine',
            'model_cache_dir': './models',
            'enable_gpu': 'false',
            'model_fallbacks': 'all-MiniLM-L12-v2,text-embedding-3-small',
            'stig_folder': './stigs',
            'max_retrieval_results': '100',
            'enable_hybrid_search': 'false',
            'log_level': 'INFO'
        }

        if not self.config.has_section('DEFAULT'):
            self.config.add_section('DEFAULT')

        for key, value in defaults.items():
            if not self.config.has_option('DEFAULT', key):
                self.config.set('DEFAULT', key, value)

    def get(self, key: str, fallback: Any = None) -> Any:
        """Get a configuration value."""
        try:
            value = self.config.get('DEFAULT', key, fallback=fallback)
            return self._parse_value(value)
        except (configparser.NoOptionError, configparser.NoSectionError):
            return self._parse_value(fallback)

    def get_list(self, key: str, fallback: str = '') -> List[str]:
        """Get a configuration value as a list."""
        value = self.get(key, fallback)
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        return value if isinstance(value, list) else []

    def _parse_value(self, value: Any) -> Any:
        """Parse configuration values to appropriate types."""
        if value is None:
            return None

        if isinstance(value, str):
            value = value.strip()

            # Boolean values
            if value.lower() in ('true', 'yes', '1', 'on'):
                return True
            elif value.lower() in ('false', 'no', '0', 'off'):
                return False

            # Numeric values
            try:
                if '.' in value:
                    return float(value)
                else:
                    return int(value)
            except ValueError:
                pass

        return value

    def get_embedding_config(self) -> Dict[str, Any]:
        """Get embedding model configuration."""
        return {
            'model_name': self.get('embedding_model', 'all-mpnet-base-v2'),
            'dimensions': self.get('embedding_dimensions', 768),
            'similarity_metric': self.get('similarity_metric', 'cosine'),
            'cache_dir': self.get('model_cache_dir', './models'),
            'enable_gpu': self.get('enable_gpu', False),
            'fallbacks': self.get_list('model_fallbacks', 'all-MiniLM-L12-v2,text-embedding-3-small')
        }

    def get_app_config(self) -> Dict[str, Any]:
        """Get application configuration."""
        return {
            'stig_folder': self.get('stig_folder', './stigs'),
            'max_retrieval_results': self.get('max_retrieval_results', 100),
            'enable_hybrid_search': self.get('enable_hybrid_search', False),
            'log_level': self.get('log_level', 'INFO'),
            'spacy_model': self.get('spacy_model', 'en_core_web_trf')
        }

    def get_data_urls(self) -> Dict[str, str]:
        """Get data source URLs."""
        return {
            'catalog_url': self.get('catalog_url'),
            'high_baseline_url': self.get('high_baseline_url'),
            'assessment_url': self.get('nist_800_53a_json_url'),
            'cci_url': self.get('cci_url'),
            'attack_mapping_url': self.get('nist_800_53_attack_mapping_url')
        }

# Global config instance
_config_instance = None

def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance

def reload_config(config_path: Optional[str] = None) -> Config:
    """Reload configuration from file."""
    global _config_instance
    _config_instance = Config(config_path)
    return _config_instance