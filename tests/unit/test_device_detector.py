"""Unit tests for DeviceTypeDetector"""

import pytest
from src.utils.device_detector import DeviceTypeDetector


class TestDeviceTypeDetector:
    """Test device type detection"""
    
    def test_windows_server_detection(self):
        """Test Windows Server OS detection"""
        detector = DeviceTypeDetector()
        
        test_cases = [
            "Windows Server 2019",
            "Windows Server 2016 Standard",
            "Windows Server 2022 Datacenter",
            "Microsoft Windows Server 2012 R2",
            "Windows 2019",
        ]
        
        for os_string in test_cases:
            assert detector.detect_device_type(os_string) == 'server', f"Failed for: {os_string}"
            assert detector.is_server(os_string), f"is_server failed for: {os_string}"
    
    def test_linux_server_detection(self):
        """Test Linux Server OS detection"""
        detector = DeviceTypeDetector()
        
        test_cases = [
            "Ubuntu Server 20.04",
            "Red Hat Enterprise Linux 8",
            "RHEL 7.9",
            "CentOS 7",
            "Debian GNU/Linux 11",
            "Amazon Linux 2",
            "Oracle Linux 8.5",
        ]
        
        for os_string in test_cases:
            assert detector.detect_device_type(os_string) == 'server', f"Failed for: {os_string}"
    
    def test_workstation_detection(self):
        """Test workstation OS detection"""
        detector = DeviceTypeDetector()
        
        test_cases = [
            "Windows 10 Pro",
            "Windows 11 Home",
            "Windows 7 Enterprise",
            "macOS Monterey",
            "Mac OS X 10.15",
            "Ubuntu Desktop 22.04",
        ]
        
        for os_string in test_cases:
            assert detector.detect_device_type(os_string) == 'workstation', f"Failed for: {os_string}"
            assert not detector.is_server(os_string), f"is_server should be False for: {os_string}"
    
    def test_network_device_detection(self):
        """Test network device detection"""
        detector = DeviceTypeDetector()
        
        test_cases = [
            "Cisco IOS 15.2",
            "Juniper JUNOS 18.4",
            "Fortinet FortiOS 6.4",
            "Palo Alto PAN-OS 10.0",
        ]
        
        for os_string in test_cases:
            assert detector.detect_device_type(os_string) == 'network', f"Failed for: {os_string}"
    
    def test_unknown_device(self):
        """Test unknown device type"""
        detector = DeviceTypeDetector()
        
        test_cases = [
            "Unknown OS",
            "Custom Embedded System",
            None,
            "",
        ]
        
        for os_string in test_cases:
            assert detector.detect_device_type(os_string) == 'unknown', f"Failed for: {os_string}"
    
    def test_case_insensitive(self):
        """Test case insensitivity"""
        detector = DeviceTypeDetector()
        
        assert detector.detect_device_type("WINDOWS SERVER 2019") == 'server'
        assert detector.detect_device_type("windows server 2019") == 'server'
        assert detector.detect_device_type("Windows Server 2019") == 'server'
    
    def test_partial_matches(self):
        """Test partial string matches"""
        detector = DeviceTypeDetector()
        
        # Should still detect "server" in description
        assert detector.detect_device_type("Microsoft Windows Server 2019 Standard Edition") == 'server'
        assert detector.detect_device_type("Ubuntu 20.04 LTS Server") == 'server'
