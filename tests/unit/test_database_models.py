"""Unit tests for database models"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import Base, Server, Application, ServerApplicationMap, ConfidenceLevel


@pytest.fixture
def db_session():
    """Create test database session"""
    # Use in-memory SQLite for testing
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    yield session
    
    session.close()


class TestServerModel:
    """Test Server model"""
    
    def test_create_server(self, db_session):
        """Test creating a server"""
        server = Server(
            hostname="test-server-01",
            asset_uuid="uuid-123",
            ipv4="192.168.1.10",
            operating_system="Ubuntu 20.04"
        )
        
        db_session.add(server)
        db_session.commit()
        
        assert server.server_id is not None
        assert server.created_at is not None
    
    def test_unique_hostname(self, db_session):
        """Test hostname uniqueness constraint"""
        server1 = Server(hostname="test-server", asset_uuid="uuid-1")
        server2 = Server(hostname="test-server", asset_uuid="uuid-2")
        
        db_session.add(server1)
        db_session.commit()
        
        db_session.add(server2)
        
        with pytest.raises(Exception):  # Integrity error
            db_session.commit()


class TestApplicationModel:
    """Test Application model"""
    
    def test_create_application(self, db_session):
        """Test creating an application"""
        app = Application(
            app_name="Web App",
            app_type="Web Application",
            description="Main web application",
            owner_team="Platform Team"
        )
        
        db_session.add(app)
        db_session.commit()
        
        assert app.app_id is not None
        assert app.created_at is not None


class TestServerApplicationMap:
    """Test server-application mapping"""
    
    def test_create_mapping(self, db_session):
        """Test creating a server-application mapping"""
        server = Server(hostname="server-01", asset_uuid="uuid-1")
        app = Application(app_name="App-01")
        
        db_session.add(server)
        db_session.add(app)
        db_session.commit()
        
        mapping = ServerApplicationMap(
            server_id=server.server_id,
            app_id=app.app_id,
            confidence=ConfidenceLevel.MANUAL,
            source="test",
            updated_by="test-user"
        )
        
        db_session.add(mapping)
        db_session.commit()
        
        assert mapping.mapping_id is not None
        assert mapping.confidence == ConfidenceLevel.MANUAL
    
    def test_unique_server_app_constraint(self, db_session):
        """Test unique server-app mapping constraint"""
        server = Server(hostname="server-01", asset_uuid="uuid-1")
        app = Application(app_name="App-01")
        
        db_session.add(server)
        db_session.add(app)
        db_session.commit()
        
        mapping1 = ServerApplicationMap(
            server_id=server.server_id,
            app_id=app.app_id,
            confidence=ConfidenceLevel.MANUAL
        )
        mapping2 = ServerApplicationMap(
            server_id=server.server_id,
            app_id=app.app_id,
            confidence=ConfidenceLevel.AUTO
        )
        
        db_session.add(mapping1)
        db_session.commit()
        
        db_session.add(mapping2)
        
        with pytest.raises(Exception):  # Integrity error
            db_session.commit()
    
    def test_cascade_delete(self, db_session):
        """Test cascade delete when server is deleted"""
        server = Server(hostname="server-01", asset_uuid="uuid-1")
        app = Application(app_name="App-01")
        
        db_session.add(server)
        db_session.add(app)
        db_session.commit()
        
        mapping = ServerApplicationMap(
            server_id=server.server_id,
            app_id=app.app_id
        )
        
        db_session.add(mapping)
        db_session.commit()
        
        # Delete server
        db_session.delete(server)
        db_session.commit()
        
        # Mapping should be deleted too
        result = db_session.query(ServerApplicationMap).filter_by(
            mapping_id=mapping.mapping_id
        ).first()
        
        assert result is None
