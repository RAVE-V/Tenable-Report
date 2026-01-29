"""Quick test to verify chunks_available fix without real API calls"""

import logging
from unittest.mock import Mock, patch
from src.tenable_client import TenableExporter

# Setup logging to see detailed output
logging.basicConfig(level=logging.DEBUG)

def test_chunks_available_as_list():
    """Test that chunks_available as a list is handled correctly"""
    print("\n=== Test 1: chunks_available as list ===")
    
    with patch("src.tenable_client.requests.Session") as mock_session:
        # Mock the session
        mock_session_instance = mock_session.return_value
        
        # Mock initiate export response
        mock_init_response = Mock()
        mock_init_response.json.return_value = {"export_uuid": "test-uuid-123"}
        mock_session_instance.post.return_value = mock_init_response
        
        # Mock poll status response - chunks_available as LIST
        mock_status_response = Mock()
        mock_status_response.json.return_value = {
            "status": "FINISHED",
            "chunks_available": [1, 2, 3]  # List of chunk IDs
        }
        mock_session_instance.get.return_value = mock_status_response
        
        # Mock chunk download responses
        mock_chunk_responses = []
        for i in [1, 2, 3]:
            mock_chunk = Mock()
            mock_chunk.status_code = 200
            mock_chunk.json.return_value = [{"plugin": {"id": i}}]
            mock_chunk_responses.append(mock_chunk)
        
        mock_session_instance.get.side_effect = [
            mock_status_response,  # First call is status check
            *mock_chunk_responses   # Subsequent calls are chunk downloads
        ]
        
        # Create client and test
        client = TenableExporter(access_key="test", secret_key="test")
        client.session = mock_session_instance
        
        try:
            result = client.export_vulnerabilities({})
            print(f"✅ SUCCESS: Got {len(result)} vulnerabilities")
            print(f"   Expected chunk IDs [1, 2, 3] to be used")
            return True
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False


def test_chunks_available_as_integer():
    """Test that chunks_available as integer still works"""
    print("\n=== Test 2: chunks_available as integer ===")
    
    with patch("src.tenable_client.requests.Session") as mock_session:
        # Mock the session
        mock_session_instance = mock_session.return_value
        
        # Mock initiate export response
        mock_init_response = Mock()
        mock_init_response.json.return_value = {"export_uuid": "test-uuid-456"}
        mock_session_instance.post.return_value = mock_init_response
        
        # Mock poll status response - chunks_available as INTEGER
        mock_status_response = Mock()
        mock_status_response.json.return_value = {
            "status": "FINISHED",
            "chunks_available": 2  # Integer count
        }
        
        # Mock chunk download responses
        mock_chunk_0 = Mock()
        mock_chunk_0.status_code = 200
        mock_chunk_0.json.return_value = [{"plugin": {"id": 0}}]
        
        mock_chunk_1 = Mock()
        mock_chunk_1.status_code = 200
        mock_chunk_1.json.return_value = [{"plugin": {"id": 1}}]
        
        mock_session_instance.get.side_effect = [
            mock_status_response,  # Status check
            mock_chunk_0,          # Chunk 0
            mock_chunk_1           # Chunk 1
        ]
        
        # Create client and test
        client = TenableExporter(access_key="test", secret_key="test")
        client.session = mock_session_instance
        
        try:
            result = client.export_vulnerabilities({})
            print(f"✅ SUCCESS: Got {len(result)} vulnerabilities")
            print(f"   Expected chunk IDs [0, 1] to be used")
            return True
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Testing chunks_available fix")
    print("="*60)
    
    test1_passed = test_chunks_available_as_list()
    test2_passed = test_chunks_available_as_integer()
    
    print("\n" + "="*60)
    if test1_passed and test2_passed:
        print("✅ ALL TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
    print("="*60 + "\n")
