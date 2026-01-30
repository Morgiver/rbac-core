"""
Pytest configuration and shared fixtures for rbac-core tests.
"""

import os
import pytest
from datetime import datetime

from rbac_core.domain.models import Role, Policy, RoleAssignment
from rbac_core.domain.value_objects import Permission


# ============================================================================
# Domain Model Fixtures
# ============================================================================

@pytest.fixture
def sample_role():
    """Create a sample role for testing"""
    return Role(
        id="role-1",
        name="admin",
        description="Administrator role",
        permissions=[
            Permission(resource="users", action="read"),
            Permission(resource="users", action="write"),
        ],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


@pytest.fixture
def sample_policy():
    """Create a sample policy for testing"""
    return Policy(
        id="policy-1",
        name="user_management",
        description="User management policy",
        permissions=[
            Permission(resource="users", action="read"),
            Permission(resource="users", action="create"),
        ],
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


# ============================================================================
# In-Memory Repository Fixtures
# ============================================================================

@pytest.fixture
def role_repo():
    """Create a fresh in-memory role repository"""
    from rbac_core.adapters.repositories.memory import InMemoryRoleRepository
    return InMemoryRoleRepository()


@pytest.fixture
def policy_repo():
    """Create a fresh in-memory policy repository"""
    from rbac_core.adapters.repositories.memory import InMemoryPolicyRepository
    return InMemoryPolicyRepository()


@pytest.fixture
def assignment_repo():
    """Create a fresh in-memory role assignment repository"""
    from rbac_core.adapters.repositories.memory import InMemoryRoleAssignmentRepository
    return InMemoryRoleAssignmentRepository()


# ============================================================================
# Database Fixtures (SQLAlchemy)
# ============================================================================

@pytest.fixture(scope='function')
def db_engine():
    """Create SQLAlchemy engine for testing"""
    conn_string = os.environ.get('TEST_DB_CONNECTION_STRING')
    db_type = os.environ.get('TEST_DB_TYPE', 'memory')

    if not conn_string or db_type != 'postgresql':
        pytest.skip("PostgreSQL database not configured")

    from sqlalchemy import create_engine
    engine = create_engine(conn_string)

    # Create tables
    from rbac_core.adapters.repositories.sqlalchemy import Base
    Base.metadata.create_all(engine)

    yield engine

    # Cleanup tables after test
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope='function')
def db_session(db_engine):
    """Create SQLAlchemy session for testing"""
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()

    yield session

    session.rollback()
    session.close()


# ============================================================================
# Database Fixtures (MongoDB)
# ============================================================================

@pytest.fixture(scope='function')
def mongo_client():
    """Create MongoDB client for testing"""
    conn_string = os.environ.get('TEST_DB_CONNECTION_STRING')
    db_type = os.environ.get('TEST_DB_TYPE', 'memory')

    if not conn_string or db_type != 'mongodb':
        pytest.skip("MongoDB database not configured")

    from pymongo import MongoClient
    client = MongoClient(conn_string)

    yield client

    client.close()


@pytest.fixture(scope='function')
def mongo_db(mongo_client):
    """Create MongoDB database for testing"""
    db_name = os.environ.get('TEST_DB_NAME', 'test_rbac_mongo')
    db = mongo_client[db_name]

    yield db

    # Cleanup all collections after test
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})


# ============================================================================
# Pytest Hooks
# ============================================================================

def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "adapter(name): mark test to run only for specific adapter"
    )


def pytest_collection_modifyitems(config, items):
    """Skip tests based on adapter filter"""
    adapter_filter = config.getoption("--adapter", default=None)

    if not adapter_filter:
        return

    for item in items:
        # Check if test class name indicates specific adapter
        if hasattr(item, 'cls') and item.cls:
            class_name = item.cls.__name__

            # Map class names to adapters
            if 'SQLAlchemy' in class_name and adapter_filter != 'sqlalchemy':
                item.add_marker(pytest.mark.skip(reason=f"Skipping SQLAlchemy tests (adapter={adapter_filter})"))
            elif 'MongoDB' in class_name and adapter_filter != 'mongodb':
                item.add_marker(pytest.mark.skip(reason=f"Skipping MongoDB tests (adapter={adapter_filter})"))
            elif 'InMemory' in class_name and adapter_filter not in ['memory', 'inmemory']:
                item.add_marker(pytest.mark.skip(reason=f"Skipping InMemory tests (adapter={adapter_filter})"))


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--adapter",
        action="store",
        default=None,
        help="Run tests only for specific adapter (sqlalchemy, mongodb, memory)"
    )
