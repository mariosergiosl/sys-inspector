# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/utils/config_loader.py
# DESCRIPTION: Utility module to load and validate YAML configuration files.
#              Ensures default values are present for critical system flags.
#
#              UPDATED: Added defaults for Network (Server/Daemon)
#              and Collection settings.
#
# OPTIONS:
#
# PARAMETERS:
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# CHANGELOG:
# VERSION: 0.90.14
# ==============================================================================

import os
import sys
import yaml

# Default configuration structure to ensure the app runs even with minimal config
DEFAULT_CONFIG = {
    "general": {
        "mode": "snapshot",
        "log_level": "INFO"
    },
    "network": {
        "bind_address": "0.0.0.0",
        "bind_port": 8080,
        "target_url": "http://127.0.0.1:8080"
    },
    "collection": {
        "interval": 30
    },
    "storage": {
        "type": "sqlite",
        "sqlite_path": "data/sys_inspector.db",
        "retention_days": 10,
        "db_size_limit_bytes": 20971520  # 20MB Default
    },
    "features": {
        "container_awareness": True,
        "gpu_monitoring": False,
        "security_inspection": True
    },
    "security": {
        "encrypt_sensitive_data": False,
        "key_file": "conf/secrets.key",
        "anonymize_ips": False
    }
}


def _merge_defaults(user_config, defaults):
    """
    Recursively merges user configuration with defaults.
    If a key is missing in user_config, it takes from defaults.
    """
    for key, value in defaults.items():
        if key not in user_config:
            user_config[key] = value
        elif isinstance(value, dict) and isinstance(user_config[key], dict):
            _merge_defaults(user_config[key], value)
    return user_config


def load_config(config_path):
    """
    Loads the YAML configuration file.

    Args:
        config_path (str): Relative or absolute path to the .yaml file.

    Returns:
        dict: The complete configuration dictionary with defaults merged.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file format is invalid.
    """
    if not os.path.exists(config_path):
        print(f"[WARN] Config file not found at {config_path}. Using defaults.")
        return DEFAULT_CONFIG

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = yaml.safe_load(f) or {}

        # Merge with defaults to guarantee structure
        final_config = _merge_defaults(user_config, DEFAULT_CONFIG)
        return final_config

    except yaml.YAMLError as exc:
        print(f"[ERROR] Failed to parse config file: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Unexpected error loading config: {exc}")
        sys.exit(1)
