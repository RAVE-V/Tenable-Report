"""Configuration management for Tenable Report Generator"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration"""
    
    # Tenable API Configuration
    TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
    TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
    TENABLE_BASE_URL = os.getenv("TENABLE_BASE_URL", "https://cloud.tenable.com")
    USER_AGENT = os.getenv("USER_AGENT", "TenableReportGenerator/1.0")
    
    # Database Configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tenable_reports.db")
    
    # Export Configuration
    EXPORT_MAX_ASSETS_PER_CHUNK = int(os.getenv("EXPORT_MAX_ASSETS_PER_CHUNK", "5000"))
    EXPORT_MAX_WAIT_SECONDS = int(os.getenv("TENABLE_EXPORT_MAX_WAIT", "3600"))
    EXPORT_POLL_INITIAL_WAIT = int(os.getenv("EXPORT_POLL_INITIAL_WAIT", "5"))
    EXPORT_POLL_MAX_WAIT = int(os.getenv("EXPORT_POLL_MAX_WAIT", "60"))
    EXPORT_MAX_CONCURRENT_CHUNKS = int(os.getenv("TENABLE_EXPORT_CONCURRENT_CHUNKS", "4"))
    EXPORT_TIMEOUT = int(os.getenv("TENABLE_EXPORT_TIMEOUT", "60"))
    
    # Rate Limiting
    API_RATE_LIMIT_PER_MINUTE = int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "200"))
    
    # Report Configuration
    REPORTS_OUTPUT_DIR = Path(os.getenv("REPORTS_OUTPUT_DIR", "./reports"))
    
    # Cache Configuration
    CACHE_DIR = Path(os.getenv("CACHE_DIR", "./.cache"))
    CACHE_MAX_AGE_HOURS = int(os.getenv("CACHE_MAX_AGE_HOURS", "24"))
    
    # API Settings
    API_MAX_RETRIES = int(os.getenv("TENABLE_API_RETRIES", "3"))
    API_RETRY_BACKOFF_FACTOR = float(os.getenv("TENABLE_RETRY_BACKOFF", "0.5"))
    API_TIMEOUT = int(os.getenv("TENABLE_API_TIMEOUT", "30"))
    
    @classmethod
    def validate(cls):
        """Validate required configuration"""
        errors = []
        
        if not cls.TENABLE_ACCESS_KEY:
            errors.append("TENABLE_ACCESS_KEY is required")
        if not cls.TENABLE_SECRET_KEY:
            errors.append("TENABLE_SECRET_KEY is required")
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    @classmethod
    def ensure_reports_dir(cls):
        """Ensure reports output directory exists"""
        cls.REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
