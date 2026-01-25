"""Tenable API client for vulnerability export"""

import time
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.config import Config
from src.utils import measure_performance

logger = logging.getLogger(__name__)


class TenableAPIError(Exception):
    """Tenable API error"""
    pass


class TenableExporter:
    """
    Tenable.io API client for vulnerability export.
    Implements bulk export workflow: initiate → poll → download chunks → merge
    """
    
    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None):
        """
        Initialize Tenable API client
        
        Args:
            access_key: Tenable API access key (defaults to Config.TENABLE_ACCESS_KEY)
            secret_key: Tenable API secret key (defaults to Config.TENABLE_SECRET_KEY)
        """
        self.access_key = access_key or Config.TENABLE_ACCESS_KEY
        self.secret_key = secret_key or Config.TENABLE_SECRET_KEY
        self.base_url = Config.TENABLE_BASE_URL
        
        if not self.access_key or not self.secret_key:
            raise ValueError("Tenable API keys are required")
        
        self.headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key};",
            "User-Agent": Config.USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Setup session with retries
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=Config.API_MAX_RETRIES,
            backoff_factor=Config.API_RETRY_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        return session
    
    @measure_performance
    def export_vulnerabilities(self, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Full export workflow: initiate → poll → download chunks → merge
        
        Args:
            filters: Optional filter criteria (tags, severity, state, dates)
                Example: {
                    "tag.Environment": ["Production"],
                    "severity": ["critical", "high"],
                    "state": ["open", "reopened"]
                }
        
        Returns:
            List of vulnerability dictionaries
        """
        logger.info("Starting vulnerability export")
        
        # Step 1: Initiate export job
        export_uuid = self._initiate_export(filters or {})
        logger.info(f"Export job initiated: {export_uuid}")
        
        # Step 2: Poll for job completion
        status = self._poll_export_status(export_uuid)
        logger.info(f"Export job completed. Chunks available: {status['chunks_available']}")
        
        # Step 3: Download chunks in parallel
        vulnerabilities = self._download_chunks(export_uuid, status["chunks_available"])
        logger.info(f"Downloaded {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities
    
    def _initiate_export(self, filters: Dict) -> str:
        """
        Initiate vulnerability export job
        
        Args:
            filters: Filter criteria
        
        Returns:
            Export job UUID
        """
        # Default filters: active vulnerabilities only
        default_filters = {
            "state": ["open", "reopened"]
        }
        
        # Merge user filters with defaults
        merged_filters = {**default_filters, **filters}
        
        payload = {
            "num_assets": Config.EXPORT_MAX_ASSETS_PER_CHUNK,
            "filters": merged_filters
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/vulns/export",
                headers=self.headers,
                json=payload,
                timeout=Config.API_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()
            return data["export_uuid"]
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to initiate export: {e}")
            raise TenableAPIError(f"Export initiation failed: {e}")
    
    def _poll_export_status(self, export_uuid: str) -> Dict:
        """
        Poll export job status until completion with exponential backoff
        
        Args:
            export_uuid: Export job UUID
        
        Returns:
            Status dictionary with chunks_available count
        """
        wait_time = Config.EXPORT_POLL_INITIAL_WAIT
        elapsed = 0
        max_wait = Config.EXPORT_MAX_WAIT_SECONDS
        
        while elapsed < max_wait:
            try:
                response = self.session.get(
                    f"{self.base_url}/vulns/export/{export_uuid}/status",
                    headers=self.headers,
                    timeout=Config.API_TIMEOUT
                )
                response.raise_for_status()
                
                status = response.json()
                
                if status["status"] == "FINISHED":
                    return status
                elif status["status"] == "ERROR":
                    raise TenableAPIError(f"Export job failed: {status}")
                
                # Exponential backoff
                logger.debug(f"Export status: {status['status']}, waiting {wait_time}s")
                time.sleep(wait_time)
                elapsed += wait_time
                wait_time = min(wait_time * 1.5, Config.EXPORT_POLL_MAX_WAIT)
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to poll export status: {e}")
                raise TenableAPIError(f"Status polling failed: {e}")
        
        raise TimeoutError(f"Export job {export_uuid} did not complete in {max_wait}s")
    
    @measure_performance
    def _download_chunks(self, export_uuid: str, chunks_available: int) -> List[Dict]:
        """
        Download all export chunks in parallel
        
        Args:
            export_uuid: Export job UUID
            chunks_available: Number of chunks to download
        
        Returns:
            Merged list of vulnerabilities from all chunks
        """
        vulnerabilities = []
        
        def download_chunk(chunk_id: int) -> List[Dict]:
            """Download a single chunk"""
            try:
                response = self.session.get(
                    f"{self.base_url}/vulns/export/{export_uuid}/chunks/{chunk_id}",
                    headers=self.headers,
                    timeout=Config.EXPORT_TIMEOUT
                )
                response.raise_for_status()
                
                chunk_data = response.json()
                logger.debug(f"Downloaded chunk {chunk_id}: {len(chunk_data)} vulnerabilities")
                return chunk_data
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to download chunk {chunk_id}: {e}")
                raise TenableAPIError(f"Chunk download failed: {e}")
        
        # Download chunks in parallel
        with ThreadPoolExecutor(max_workers=Config.EXPORT_MAX_CONCURRENT_CHUNKS) as executor:
            future_to_chunk = {
                executor.submit(download_chunk, chunk_id): chunk_id 
                for chunk_id in range(chunks_available)
            }
            
            for future in as_completed(future_to_chunk):
                chunk_id = future_to_chunk[future]
                try:
                    chunk_data = future.result()
                    vulnerabilities.extend(chunk_data)
                except Exception as e:
                    logger.error(f"Chunk {chunk_id} failed: {e}")
                    raise
        
        return vulnerabilities
    
    def list_tags(self) -> List[Dict]:
        """
        List available tags from Tenable
        
        Returns:
            List of tag dictionaries with category and value
        """
        try:
            response = self.session.get(
                f"{self.base_url}/tags/values",
                headers=self.headers,
                timeout=Config.API_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get("values", [])
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list tags: {e}")
            raise TenableAPIError(f"Tag listing failed: {e}")
