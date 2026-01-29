"""Device type detection utilities"""

import re
from typing import Optional


class DeviceTypeDetector:
    """Detect device type from operating system string"""
    
    # Server OS patterns (case-insensitive)
    SERVER_PATTERNS = [
        # Windows Server
        r'windows\s+server',
        r'windows\s+2008',
        r'windows\s+2012',
        r'windows\s+2016',
        r'windows\s+2019',
        r'windows\s+2022',
        r'windows\s+2025',
        
        # Linux/Unix Servers
        r'ubuntu\s+server',
        r'red\s+hat',
        r'rhel',
        r'centos',
        r'debian',
        r'fedora\s+server',
        r'oracle\s+linux',
        r'suse\s+linux',
        r'amazon\s+linux',
        
        # Generic Server Indicators
        r'server',  # Generic catch-all (must be last)
    ]
    
    # Workstation/Desktop OS patterns
    WORKSTATION_PATTERNS = [
        r'windows\s+10',
        r'windows\s+11',
        r'windows\s+7',
        r'windows\s+8',
        r'windows\s+xp',
        r'macos',
        r'mac\s+os',
        r'ubuntu\s+desktop',
        r'fedora\s+workstation',
    ]
    
    @staticmethod
    def detect_device_type(operating_system: Optional[str]) -> str:
        """
        Detect device type from operating system string
        
        Args:
            operating_system: OS string from Tenable (e.g., "Windows Server 2019")
            
        Returns:
            Device type: 'server', 'workstation', 'network', or 'unknown'
        """
        if not operating_system:
            return 'unknown'
        
        os_lower = operating_system.lower()
        
        # Check for servers first (more specific)
        for pattern in DeviceTypeDetector.SERVER_PATTERNS:
            if re.search(pattern, os_lower):
                return 'server'
        
        # Check for workstations
        for pattern in DeviceTypeDetector.WORKSTATION_PATTERNS:
            if re.search(pattern, os_lower):
                return 'workstation'
        
        # Check for network devices
        if any(keyword in os_lower for keyword in ['cisco', 'juniper', 'fortinet', 'palo alto', 'router', 'switch', 'firewall']):
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
