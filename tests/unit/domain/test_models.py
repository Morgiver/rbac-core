"""Unit tests for domain models."""

from datetime import datetime, timedelta

import pytest

from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName


class TestRole:
    """Tests for Role domain model."""

    def test_create_role(self) -> None:
        """Test creating a role."""
        role = Role.create(name="admin", description="Administrator role")
        assert role.id is not None
        assert str(role.name) == "admin"
        assert role.description == "Administrator role"
        assert len(role.permissions) == 0

    def test_create_role_with_permissions(self) -> None:
        """Test creating a role with permissions."""
        perms = {Permission(resource="users", action="read")}
        role = Role.create(
            name="viewer", description="Read-only role", permissions=perms
        )
        assert len(role.permissions) == 1

    def test_add_permission(self) -> None:
        """Test adding permission to role."""
        role = Role.create(name="editor", description="Editor role")
        perm = Permission(resource="posts", action="create")

        original_updated_at = role.updated_at
        role.add_permission(perm)

        assert perm in role.permissions
        assert role.updated_at > original_updated_at

    def test_remove_permission(self) -> None:
        """Test removing permission from role."""
        perm = Permission(resource="posts", action="create")
        role = Role.create(
            name="editor", description="Editor role", permissions={perm}
        )

        role.remove_permission(perm)
        assert perm not in role.permissions

    def test_has_permission_exact(self) -> None:
        """Test checking for exact permission."""
        perm = Permission(resource="users", action="read")
        role = Role.create(
            name="viewer", description="Viewer role", permissions={perm}
        )

        assert role.has_permission(Permission(resource="users", action="read"))
        assert not role.has_permission(Permission(resource="users", action="write"))

    def test_has_permission_with_wildcard(self) -> None:
        """Test checking permission with wildcard."""
        wildcard = Permission(resource="*", action="*")
        role = Role.create(
            name="superadmin", description="Super admin", permissions={wildcard}
        )

        assert role.has_permission(Permission(resource="users", action="read"))
        assert role.has_permission(Permission(resource="posts", action="delete"))

    def test_role_equality(self) -> None:
        """Test role equality based on ID."""
        role1 = Role.create(name="admin", description="Admin")
        role2 = Role.create(name="admin", description="Admin")

        assert role1 != role2  # Different IDs

        # Same object
        assert role1 == role1


class TestPolicy:
    """Tests for Policy domain model."""

    def test_create_policy(self) -> None:
        """Test creating a policy."""
        policy = Policy.create(
            name="allow-read-users",
            description="Allow reading users",
            effect=PolicyEffect.allow(),
        )
        assert policy.id is not None
        assert policy.name == "allow-read-users"
        assert policy.effect.is_allow()

    def test_create_deny_policy(self) -> None:
        """Test creating a DENY policy."""
        policy = Policy.create(
            name="deny-delete-admin",
            description="Deny deleting admin users",
            effect=PolicyEffect.deny(),
            resources={"users"},
            actions={"delete"},
        )
        assert policy.effect.is_deny()

    def test_applies_to_subject(self) -> None:
        """Test checking if policy applies to subject."""
        policy = Policy.create(
            name="test",
            description="Test policy",
            effect=PolicyEffect.allow(),
            subjects={"user-123"},
        )
        assert policy.applies_to_subject("user-123")
        assert not policy.applies_to_subject("user-456")

    def test_applies_to_subject_wildcard(self) -> None:
        """Test policy with wildcard subject."""
        policy = Policy.create(
            name="test",
            description="Test policy",
            effect=PolicyEffect.allow(),
            subjects={"*"},
        )
        assert policy.applies_to_subject("anyone")

    def test_applies_to_resource(self) -> None:
        """Test checking if policy applies to resource."""
        policy = Policy.create(
            name="test",
            description="Test policy",
            effect=PolicyEffect.allow(),
            resources={"users"},
        )
        assert policy.applies_to_resource("users")
        assert not policy.applies_to_resource("posts")

    def test_applies_to_action(self) -> None:
        """Test checking if policy applies to action."""
        policy = Policy.create(
            name="test",
            description="Test policy",
            effect=PolicyEffect.allow(),
            actions={"read"},
        )
        assert policy.applies_to_action("read")
        assert not policy.applies_to_action("write")

    def test_policy_equality(self) -> None:
        """Test policy equality based on ID."""
        policy1 = Policy.create(
            name="test", description="Test", effect=PolicyEffect.allow()
        )
        policy2 = Policy.create(
            name="test", description="Test", effect=PolicyEffect.allow()
        )

        assert policy1 != policy2  # Different IDs
        assert policy1 == policy1  # Same object


class TestRoleAssignment:
    """Tests for RoleAssignment domain model."""

    def test_create_assignment(self) -> None:
        """Test creating a role assignment."""
        assignment = RoleAssignment.create(
            subject_id="user-123", role_id="role-456"
        )
        assert assignment.id is not None
        assert assignment.subject_id == "user-123"
        assert assignment.role_id == "role-456"

    def test_create_assignment_with_expiry(self) -> None:
        """Test creating assignment with expiration."""
        expires_at = datetime.utcnow() + timedelta(days=30)
        assignment = RoleAssignment.create(
            subject_id="user-123", role_id="role-456", expires_at=expires_at
        )
        assert assignment.expires_at == expires_at

    def test_assignment_not_expired(self) -> None:
        """Test that future expiry is not expired."""
        expires_at = datetime.utcnow() + timedelta(days=1)
        assignment = RoleAssignment.create(
            subject_id="user-123", role_id="role-456", expires_at=expires_at
        )
        assert not assignment.is_expired()
        assert assignment.is_active()

    def test_assignment_expired(self) -> None:
        """Test that past expiry is expired."""
        expires_at = datetime.utcnow() - timedelta(days=1)
        assignment = RoleAssignment.create(
            subject_id="user-123", role_id="role-456", expires_at=expires_at
        )
        assert assignment.is_expired()
        assert not assignment.is_active()

    def test_assignment_no_expiry(self) -> None:
        """Test that no expiry means never expired."""
        assignment = RoleAssignment.create(
            subject_id="user-123", role_id="role-456"
        )
        assert not assignment.is_expired()
        assert assignment.is_active()

    def test_assignment_equality(self) -> None:
        """Test assignment equality based on ID."""
        assignment1 = RoleAssignment.create(
            subject_id="user-123", role_id="role-456"
        )
        assignment2 = RoleAssignment.create(
            subject_id="user-123", role_id="role-456"
        )

        assert assignment1 != assignment2  # Different IDs
        assert assignment1 == assignment1  # Same object
