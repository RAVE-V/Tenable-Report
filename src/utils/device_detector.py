"""Device type detection utilities"""

import re
from typing import Optional


class DeviceTypeDetector:
    """Detect device type from operating system string"""
    
    # Pre-compiled regex patterns for better performance
    _SERVER_PATTERNS = [
        # Windows Server
        re.compile(r'windows\s+server', re.IGNORECASE),
        re.compile(r'windows\s+2008', re.IGNORECASE),
        re.compile(r'windows\s+2012', re.IGNORECASE),
        re.compile(r'windows\s+2016', re.IGNORECASE),
        re.compile(r'windows\s+2019', re.IGNORECASE),
        re.compile(r'windows\s+2022', re.IGNORECASE),
        re.compile(r'windows\s+2025', re.IGNORECASE),
        
        # Linux/Unix Server Distributions
        re.compile(r'ubuntu\s+server', re.IGNORECASE),
        re.compile(r'ubuntu', re.IGNORECASE),  # Most Ubuntu is server unless specified as Desktop
        re.compile(r'red\s+hat', re.IGNORECASE),
        re.compile(r'rhel', re.IGNORECASE),
        re.compile(r'centos', re.IGNORECASE),
        re.compile(r'rocky\s+linux', re.IGNORECASE),
        re.compile(r'almalinux', re.IGNORECASE),
        re.compile(r'debian', re.IGNORECASE),
        re.compile(r'fedora', re.IGNORECASE),
        re.compile(r'oracle\s+linux', re.IGNORECASE),
        re.compile(r'suse\s+linux', re.IGNORECASE),
        re.compile(r'opensuse', re.IGNORECASE),
        re.compile(r'amazon\s+linux', re.IGNORECASE),
        re.compile(r'arch\s+linux', re.IGNORECASE),
        re.compile(r'kali\s+linux', re.IGNORECASE),
        re.compile(r'linux', re.IGNORECASE),  # Generic Linux is likely server
        
        # Generic Server Indicator (must be last to catch anything with "server")
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
        re.compile(r'ubuntu\s+desktop', re.IGNORECASE),
        re.compile(r'fedora\s+workstation', re.IGNORECASE),
    ]
    
    _NETWORK_KEYWORDS = ['cisco', 'juniper', 'fortinet', 'palo alto', 'router', 'switch', 'firewall']
    
    @staticmethod
    def detect_device_type(operating_system: Optional[str]) -> str:
        """
        Detect device type from operating system string
        
        Args:
            operating_system: OS string from Tenable (e.g., "Windows Server 2019")
            
        Returns:
            Device type: 'server', 'workstation', 'network', or 'unknown'
        """
        if not operating_system or not isinstance(operating_system, str):
            return 'unknown'
        
        # Check for servers first (more specific)
        for pattern in DeviceTypeDetector._SERVER_PATTERNS:
            if pattern.search(operating_system):
                return 'server'
        
        # Check for workstations
        for pattern in DeviceTypeDetector._WORKSTATION_PATTERNS:
            if pattern.search(operating_system):
                return 'workstation'
        
        # Check for network devices
        os_lower = operating_system.lower()
        if any(keyword in os_lower for keyword in DeviceTypeDetector._NETWORK_KEYWORDS):
            return 'network'
        
        # Default to unknown
        return 'unknown'
    
    @staticmethod
    def is_server(operating_system: Optional[str]) -> bool:
        """
        Check if device is a server
        
        Args:
            operating_system: OS string from Tenable
            
        Returns:
            True if server, False otherwise
        """
        return DeviceTypeDetector.detect_device_type(operating_system) == 'server'
