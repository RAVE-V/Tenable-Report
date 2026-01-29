"""Device type detection utilities"""

import re
import json
from pathlib import Path
from typing import Optional, Dict


class DeviceTypeDetector:
    """Detect device type from operating system string"""
    
    # Path to custom overrides file
    OVERRIDES_FILE = Path(".cache") / "device_overrides.json"
    
    # Pre-compiled regex patterns for better performance
    _SERVER_PATTERNS = [
        # Windows Server (including Datacenter/Standard editions)
        re.compile(r'windows\s+server', re.IGNORECASE),
        re.compile(r'windows\s+2008', re.IGNORECASE),
        re.compile(r'windows\s+2012', re.IGNORECASE),
        re.compile(r'windows\s+2016', re.IGNORECASE),
        re.compile(r'windows\s+2019', re.IGNORECASE),
        re.compile(r'windows\s+2022', re.IGNORECASE),
        re.compile(r'windows\s+2025', re.IGNORECASE),
        re.compile(r'datacenter', re.IGNORECASE),  # Windows Datacenter editions
        re.compile(r'standard\s+edition', re.IGNORECASE),  # Windows Standard editions
        
        # Linux/Unix Server Distributions
        re.compile(r'ubuntu(?!.*desktop)', re.IGNORECASE),
        re.compile(r'red\s*hat', re.IGNORECASE),
        re.compile(r'rhel', re.IGNORECASE),
        re.compile(r'centos', re.IGNORECASE),
        re.compile(r'rocky', re.IGNORECASE),
        re.compile(r'alma', re.IGNORECASE),
        re.compile(r'debian', re.IGNORECASE),
        re.compile(r'fedora', re.IGNORECASE),
        re.compile(r'oracle\s+linux', re.IGNORECASE),
        re.compile(r'suse', re.IGNORECASE),
        re.compile(r'opensuse', re.IGNORECASE),
        re.compile(r'amazon\s+linux', re.IGNORECASE),
        re.compile(r'linux', re.IGNORECASE),
        
        # Generic Server Indicator (catches anything with "server")
        re.compile(r'server', re.IGNORECASE),
    ]
    
    _WORKSTATION_PATTERNS = [
        re.compile(r'windows\s+10', re.IGNORECASE),
        re.compile(r'windows\s+11', re.IGNORECASE),
        re.compile(r'windows\s+7', re.IGNORECASE),
        re.compile(r'windows\s+8', re.IGNORECASE),
        re.compile(r'windows\s+xp', re.IGNORECASE),
        re.compile(r'macos', re.IGNORECASE),
        re.compile(r'mac\s+os', re.IGNORECASE),
        re.compile(r'desktop', re.IGNORECASE),
    ]
    
    _NETWORK_KEYWORDS = ['cisco', 'juniper', 'fortinet', 'palo alto', 'router', 'switch', 'firewall', 'f5', 'netscaler']
    
    _overrides_cache: Dict[str, str] = None
    
    @classmethod
    def _load_overrides(cls) -> Dict[str, str]:
        """Load custom OS -> device type overrides from file"""
        if cls._overrides_cache is not None:
            return cls._overrides_cache
        
        cls._overrides_cache = {}
        if cls.OVERRIDES_FILE.exists():
            try:
                with open(cls.OVERRIDES_FILE, 'r') as f:
                    cls._overrides_cache = json.load(f)
            except (json.JSONDecodeError, IOError):
                cls._overrides_cache = {}
        return cls._overrides_cache
    
    @classmethod
    def _save_overrides(cls, overrides: Dict[str, str]):
        """Save overrides to file"""
        cls.OVERRIDES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(cls.OVERRIDES_FILE, 'w') as f:
            json.dump(overrides, f, indent=2)
        cls._overrides_cache = overrides
    
    @classmethod
    def add_override(cls, os_pattern: str, device_type: str) -> bool:
        """Add a custom OS -> device type mapping"""
        if device_type not in ['server', 'workstation', 'network', 'unknown']:
            return False
        overrides = cls._load_overrides()
        overrides[os_pattern.lower()] = device_type
        cls._save_overrides(overrides)
        return True
    
    @classmethod
    def remove_override(cls, os_pattern: str) -> bool:
        """Remove a custom OS -> device type mapping"""
        overrides = cls._load_overrides()
        if os_pattern.lower() in overrides:
            del overrides[os_pattern.lower()]
            cls._save_overrides(overrides)
            return True
        return False
    
    @classmethod
    def list_overrides(cls) -> Dict[str, str]:
        """List all custom overrides"""
        return cls._load_overrides().copy()
    
    @classmethod
    def detect_device_type(cls, operating_system: Optional[str]) -> str:
        """
        Detect device type from operating system string
        
        Args:
            operating_system: OS string from Tenable (e.g., "Windows Server 2019")
            
        Returns:
            Device type: 'server', 'workstation', 'network', or 'unknown'
        """
        if not operating_system:
            return 'unknown'
        
        # Handle lists (take first item)
        if isinstance(operating_system, list):
            operating_system = operating_system[0] if operating_system else ''
        
        if not isinstance(operating_system, str):
            return 'unknown'
        
        os_lower = operating_system.lower()
        
        # Check custom overrides first
        overrides = cls._load_overrides()
        for pattern, device_type in overrides.items():
            if pattern in os_lower:
                return device_type
        
        # Check for servers first (more specific)
        for pattern in cls._SERVER_PATTERNS:
            if pattern.search(operating_system):
                return 'server'
        
        # Check for workstations
        for pattern in cls._WORKSTATION_PATTERNS:
            if pattern.search(operating_system):
                return 'workstation'
        
        # Check for network devices
        if any(keyword in os_lower for keyword in cls._NETWORK_KEYWORDS):
            return 'network'
        
        # Default to unknown
        return 'unknown'
    
    @classmethod
    def is_server(cls, operating_system: Optional[str]) -> bool:
        """Check if device is a server"""
        return cls.detect_device_type(operating_system) == 'server'
