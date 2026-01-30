#!/usr/bin/env python3
"""
Configuration utilities for the ICS Scanner.
Provides functions for loading and handling configuration settings.
"""

import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    "general": {
        "threads": 10,
        "timeout": 5,
        "verify_ssl": True
    },
    "protocols": {
        "modbus": {
            "enabled": True,
            "ports": [502],
            "read_registers": [0, 1, 2, 3, 4, 10000, 10001, 10002, 40000, 40001, 40002]
        },
        "dnp3": {
            "enabled": True,
            "ports": [20000]
        },
        "bacnet": {
            "enabled": True,
            "ports": [47808]
        },
        "s7": {
            "enabled": True,
            "ports": [102],
            "rack": 0,
            "slot": 1
        },
        "ethernet-ip": {
            "enabled": True,
            "ports": [44818]
        },
        "opcua": {
            "enabled": True,
            "ports": [4840]
        },
        "profinet": {
            "enabled": True,
            "ports": [34962, 34963, 34964]
        },
        "iec104": {
            "enabled": True,
            "ports": [2404]
        },
        "hart": {
            "enabled": True,
            "ports": [5094]
        },
        "snmp": {
            "enabled": True,
            "ports": [161],
            "community_strings": ["public", "private", "manager", "admin", "supervisor"]
        },
        "mqtt": {
            "enabled": True,
            "ports": [1883, 8883]
        }
    },
    "scan_intensity": {
        "low": {
            "description": "Passive scan (device discovery, version detection)",
            "destructive": False
        },
        "medium": {
            "description": "Query system state (read registers, security settings)",
            "destructive": False
        },
        "high": {
            "description": "Simulated attack vectors (control attempts, write tests)",
            "destructive": True,
            "warning_message": "High intensity scan may affect system operation!"
        }
    }
}

def get_config_path():
    """
    Get the path to the configuration file.
    
    Returns:
        Path: Path to the configuration file
    """
    # First try the current directory
    config_path = Path("config.yml")
    if config_path.exists():
        return config_path
    
    # Then try the user's home directory
    home_config = Path.home() / ".ics_scanner" / "config.yml"
    if home_config.exists():
        return home_config
    
    # If none exists, return the default location where we'll create it
    default_path = Path.home() / ".ics_scanner" / "config.yml"
    default_path.parent.mkdir(parents=True, exist_ok=True)
    return default_path

def create_default_config(config_path):
    """
    Create a default configuration file.
    
    Args:
        config_path (Path): Path to the configuration file
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)

def load_config():
    """
    Load the configuration settings.
    
    Returns:
        dict: Configuration settings
    """
    config_path = get_config_path()
    
    # If the config file doesn't exist, create it with default values
    if not config_path.exists():
        create_default_config(config_path)
        return DEFAULT_CONFIG
    
    # Load the config file
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Merge with default config to ensure all fields are present
        merged_config = DEFAULT_CONFIG.copy()
        if config:
            _deep_update(merged_config, config)
            
        return merged_config
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        return DEFAULT_CONFIG

def save_config(config):
    """
    Save the configuration settings.
    
    Args:
        config (dict): Configuration settings
    """
    config_path = get_config_path()
    
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)

def _deep_update(d, u):
    """
    Recursively update a dictionary.
    
    Args:
        d (dict): Dictionary to update
        u (dict): Dictionary with updates
        
    Returns:
        dict: Updated dictionary
    """
    for k, v in u.items():
        if isinstance(v, dict) and k in d and isinstance(d[k], dict):
            _deep_update(d[k], v)
        else:
            d[k] = v
    return d 