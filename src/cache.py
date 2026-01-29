"""Vulnerability data cache manager"""

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from src.config import Config


class VulnCache:
    """Manage cached vulnerability data"""
    
    def __init__(self):
        self.cache_dir = Config.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, filters: Dict) -> str:
        """Generate cache key from filters"""
        # Sort keys for consistent hashing
        filter_str = json.dumps(filters, sort_keys=True)
        return hashlib.md5(filter_str.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"vulns_{cache_key}.json"
    
    def _get_metadata_path(self, cache_key: str) -> Path:
        """Get cache metadata file path"""
        return self.cache_dir / f"vulns_{cache_key}_meta.json"
    
    def get(self, filters: Dict) -> Optional[Dict]:
        """
        Get cached vulnerability data if available and fresh
        
        Returns:
            Dict with 'vulnerabilities' and 'metadata' keys, or None if not cached/stale
        """
        cache_key = self._get_cache_key(filters)
        cache_file = self._get_cache_path(cache_key)
        meta_file = self._get_metadata_path(cache_key)
        
        if not cache_file.exists() or not meta_file.exists():
            return None
        
        # Check cache age
        try:
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            cached_time = datetime.fromisoformat(metadata['timestamp'])
            age_hours = (datetime.now(timezone.utc) - cached_time).total_seconds() / 3600
            
            if age_hours > Config.CACHE_MAX_AGE_HOURS:
                return None  # Cache is stale
            
            # Load cached data
            with open(cache_file, 'r') as f:
                vulnerabilities = json.load(f)
            
            return {
                'vulnerabilities': vulnerabilities,
                'metadata': metadata
            }
        
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
    
    def set(self, filters: Dict, vulnerabilities: List[Dict]):
        """Cache vulnerability data"""
        cache_key = self._get_cache_key(filters)
        cache_file = self._get_cache_path(cache_key)
        meta_file = self._get_metadata_path(cache_key)
        
        # Save vulnerabilities
        with open(cache_file, 'w') as f:
            json.dump(vulnerabilities, f)
        
        # Save metadata
        metadata = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'filters': filters,
            'count': len(vulnerabilities)
        }
        
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def get_info(self, filters: Dict) -> Optional[Dict]:
        """Get cache metadata without loading full data"""
        cache_key = self._get_cache_key(filters)
        meta_file = self._get_metadata_path(cache_key)
        
        if not meta_file.exists():
            return None
        
        try:
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            cached_time = datetime.fromisoformat(metadata['timestamp'])
            age_hours = (datetime.now(timezone.utc) - cached_time).total_seconds() / 3600
            
            metadata['age_hours'] = round(age_hours, 1)
            metadata['is_stale'] = age_hours > Config.CACHE_MAX_AGE_HOURS
            
            return metadata
        
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
    
    def clear_all(self):
        """Clear all cached vulnerability data"""
        for cache_file in self.cache_dir.glob("vulns_*.json"):
            cache_file.unlink()
