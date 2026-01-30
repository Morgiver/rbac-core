"""Unit tests for value objects."""

import pytest

from rbac_core.domain.exceptions import InvalidPermissionError, InvalidPolicyError, InvalidRoleNameError
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName


class TestPermission:
    """Tests for Permission value object."""

    def test_create_valid_permission(self) -> None:
        """Test creating a valid permission."""
        perm = Permission(resource="users", action="read")
        assert perm.resource == "users"
        assert perm.action == "read"

    def test_from_string_valid(self) -> None:
        """Test creating permission from string."""
        perm = Permission.from_string("posts:create")
        assert perm.resource == "posts"
        assert perm.action == "create"

    def test_from_string_invalid_format(self) -> None:
        """Test creating permission from invalid string."""
        with pytest.raises(InvalidPermissionError):
            Permission.from_string("invalid")

    def test_to_string(self) -> None:
        """Test converting permission to string."""
        perm = Permission(resource="documents", action="delete")
        assert perm.to_string() == "documents:delete"
        assert str(perm) == "documents:delete"

    def test_empty_resource_raises_error(self) -> None:
        """Test that empty resource raises error."""
        with pytest.raises(InvalidPermissionError):
            Permission(resource="", action="read")

    def test_empty_action_raises_error(self) -> None:
        """Test that empty action raises error."""
        with pytest.raises(InvalidPermissionError):
            Permission(resource="users", action="")

    def test_wildcard_permission(self) -> None:
        """Test wildcard permission."""
        perm = Permission(resource="*", action="*")
        assert perm.resource == "*"
        assert perm.action == "*"

    def test_matches_exact(self) -> None:
        """Test exact permission match."""
        perm1 = Permission(resource="users", action="read")
        perm2 = Permission(resource="users", action="read")
        assert perm1.matches(perm2)

    def test_matches_wildcard_resource(self) -> None:
        """Test wildcard resource matching."""
        wildcard = Permission(resource="*", action="read")
        specific = Permission(resource="users", action="read")
        assert wildcard.matches(specific)

    def test_matches_wildcard_action(self) -> None:
        """Test wildcard action matching."""
        wildcard = Permission(resource="users", action="*")
        specific = Permission(resource="users", action="read")
        assert wildcard.matches(specific)

    def test_does_not_match_different_resource(self) -> None:
        """Test that different resources don't match."""
        perm1 = Permission(resource="users", action="read")
        perm2 = Permission(resource="posts", action="read")
        assert not perm1.matches(perm2)

    def test_permission_immutable(self) -> None:
        """Test that permission is immutable."""
        perm = Permission(resource="users", action="read")
        with pytest.raises(Exception):  # FrozenInstanceError in Python 3.10+
            perm.resource = "posts"  # type: ignore

    def test_permission_hashable(self) -> None:
        """Test that permission is hashable."""
        perm1 = Permission(resource="users", action="read")
        perm2 = Permission(resource="users", action="read")
        perm_set = {perm1, perm2}
        assert len(perm_set) == 1  # Same permissions should hash to same value


class TestRoleName:
    """Tests for RoleName value object."""

    def test_create_valid_role_name(self) -> None:
        """Test creating valid role name."""
        name = RoleName("admin")
        assert str(name) == "admin"

    def test_role_name_normalized_to_lowercase(self) -> None:
        """Test that role name is normalized to lowercase."""
        name = RoleName("ADMIN")
        assert str(name) == "admin"

    def test_role_name_too_short(self) -> None:
        """Test that single character role name raises error."""
        with pytest.raises(InvalidRoleNameError):
            RoleName("a")

    def test_role_name_too_long(self) -> None:
        """Test that overly long role name raises error."""
        with pytest.raises(InvalidRoleNameError):
            RoleName("a" * 51)

    def test_role_name_empty(self) -> None:
        """Test that empty role name raises error."""
        with pytest.raises(InvalidRoleNameError):
            RoleName("")

    def test_role_name_with_hyphens_and_underscores(self) -> None:
        """Test role name with valid special characters."""
        name = RoleName("super-admin_user")
        assert str(name) == "super-admin_user"

    def test_role_name_invalid_characters(self) -> None:
        """Test that invalid characters raise error."""
        with pytest.raises(InvalidRoleNameError):
            RoleName("admin@user")

    def test_role_name_immutable(self) -> None:
        """Test that role name is immutable."""
        name = RoleName("admin")
        with pytest.raises(Exception):
            name.value = "user"  # type: ignore


class TestPolicyEffect:
    """Tests for PolicyEffect value object."""

    def test_create_allow_effect(self) -> None:
        """Test creating ALLOW effect."""
        effect = PolicyEffect("ALLOW")
        assert effect.is_allow()
        assert not effect.is_deny()

    def test_create_deny_effect(self) -> None:
        """Test creating DENY effect."""
        effect = PolicyEffect("DENY")
        assert effect.is_deny()
        assert not effect.is_allow()

    def test_effect_normalized_to_uppercase(self) -> None:
        """Test that effect is normalized to uppercase."""
        effect = PolicyEffect("allow")
        assert str(effect) == "ALLOW"

    def test_invalid_effect_raises_error(self) -> None:
        """Test that invalid effect raises error."""
        with pytest.raises(InvalidPolicyError):
            PolicyEffect("INVALID")

    def test_allow_factory_method(self) -> None:
        """Test ALLOW factory method."""
        effect = PolicyEffect.allow()
        assert effect.is_allow()

    def test_deny_factory_method(self) -> None:
        """Test DENY factory method."""
        effect = PolicyEffect.deny()
        assert effect.is_deny()

    def test_effect_immutable(self) -> None:
        """Test that policy effect is immutable."""
        effect = PolicyEffect.allow()
        with pytest.raises(Exception):
            effect.value = "DENY"  # type: ignore
