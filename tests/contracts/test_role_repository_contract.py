"""
Role repository contract tests

ALL role repository implementations MUST pass these tests.
"""

import pytest
from datetime import datetime

from rbac_core.domain.models import Role
from rbac_core.domain.value_objects import Permission


class RoleRepositoryContractTests:
    """
    Base contract tests that ALL role repository implementations must pass.
    """

    @pytest.fixture
    def repository(self):
        """Subclasses must provide a repository implementation"""
        raise NotImplementedError("Subclasses must implement repository fixture")

    @pytest.fixture
    def sample_role(self):
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

    def test_save_and_find_by_id(self, repository, sample_role):
        """Should save role and retrieve by ID"""
        repository.save(sample_role)
        found = repository.find_by_id(sample_role.id)

        assert found is not None
        assert found.id == sample_role.id
        assert found.name == sample_role.name

    def test_find_by_id_returns_none_if_not_found(self, repository):
        """Should return None if role ID not found"""
        result = repository.find_by_id("nonexistent-id")
        assert result is None

    def test_find_by_name(self, repository, sample_role):
        """Should find role by name"""
        repository.save(sample_role)
        found = repository.find_by_name("admin")

        assert found is not None
        assert found.id == sample_role.id

    def test_find_by_name_returns_none_if_not_found(self, repository):
        """Should return None if role name not found"""
        result = repository.find_by_name("nonexistent")
        assert result is None

    def test_exists_by_name(self, repository, sample_role):
        """Should check if role name exists"""
        assert repository.exists_by_name("admin") is False
        repository.save(sample_role)
        assert repository.exists_by_name("admin") is True

    def test_find_all(self, repository):
        """Should find all roles"""
        roles = [
            Role(
                id=f"role-{i}",
                name=f"role{i}",
                description=f"Role {i}",
                permissions=[],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            for i in range(3)
        ]

        for role in roles:
            repository.save(role)

        found = repository.find_all()
        assert len(found) == 3

    def test_count(self, repository, sample_role):
        """Should count all roles"""
        assert repository.count() == 0
        repository.save(sample_role)
        assert repository.count() == 1

    def test_delete(self, repository, sample_role):
        """Should delete role"""
        repository.save(sample_role)
        result = repository.delete(sample_role.id)

        assert result is True
        assert repository.find_by_id(sample_role.id) is None

    def test_delete_nonexistent_role(self, repository):
        """Should return False when deleting nonexistent role"""
        result = repository.delete("nonexistent-id")
        assert result is False


# ============================================================================
# Concrete Test Classes
# ============================================================================

class TestInMemoryRoleRepository(RoleRepositoryContractTests):
    """Test in-memory repository against contract"""

    @pytest.fixture
    def repository(self):
        from rbac_core.adapters.repositories.memory import InMemoryRoleRepository
        return InMemoryRoleRepository()


class TestSQLAlchemyRoleRepository(RoleRepositoryContractTests):
    """Test SQLAlchemy repository against contract"""

    @pytest.fixture
    def repository(self, db_session):
        from rbac_core.adapters.repositories.sqlalchemy import SQLAlchemyRoleRepository
        return SQLAlchemyRoleRepository(db_session)


class TestMongoDBRoleRepository(RoleRepositoryContractTests):
    """Test MongoDB repository against contract"""

    @pytest.fixture
    def repository(self, mongo_db):
        from rbac_core.adapters.repositories.mongodb import MongoDBRoleRepository
        return MongoDBRoleRepository(mongo_db)
