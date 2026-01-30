"""Value objects for RBAC domain."""

import re
from dataclasses import dataclass
from typing import Optional

from rbac_core.domain.exceptions import InvalidPermissionError


@dataclass(frozen=True)
class Permission:
    """
    Immutable permission value object.

    Format: resource:action
    Examples:
        - users:read
        - posts:create
        - documents:delete
        - *:* (wildcard - all permissions)
    """

    resource: str
    action: str

    def __post_init__(self) -> None:
        """Validate permission format."""
        if not self.resource:
            raise InvalidPermissionError(
                f"{self.resource}:{self.action}", "Resource cannot be empty"
            )
        if not self.action:
            raise InvalidPermissionError(
                f"{self.resource}:{self.action}", "Action cannot be empty"
            )

        # Validate format (alphanumeric, hyphens, underscores, or wildcard)
        pattern = r"^[a-zA-Z0-9_\-*]+$"
        if not re.match(pattern, self.resource):
            raise InvalidPermissionError(
                f"{self.resource}:{self.action}",
                "Resource must contain only alphanumeric characters, hyphens, underscores, or wildcard",
            )
        if not re.match(pattern, self.action):
            raise InvalidPermissionError(
                f"{self.resource}:{self.action}",
                "Action must contain only alphanumeric characters, hyphens, underscores, or wildcard",
            )

    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """
        Create Permission from string format.

        Args:
            permission_str: Permission in format "resource:action"

        Returns:
            Permission instance

        Raises:
            InvalidPermissionError: If format is invalid
        """
        if ":" not in permission_str:
            raise InvalidPermissionError(
                permission_str, "Permission must be in format 'resource:action'"
            )

        parts = permission_str.split(":", 1)
        if len(parts) != 2:
            raise InvalidPermissionError(
                permission_str, "Permission must be in format 'resource:action'"
            )

        return cls(resource=parts[0], action=parts[1])

    def to_string(self) -> str:
        """Convert permission to string format."""
        return f"{self.resource}:{self.action}"

    def matches(self, other: "Permission") -> bool:
        """
        Check if this permission matches another (supports wildcards).

        Args:
            other: Permission to match against

        Returns:
            True if permissions match (considering wildcards)
        """
        resource_match = self.resource == "*" or self.resource == other.resource
        action_match = self.action == "*" or self.action == other.action

        return resource_match and action_match

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"Permission('{self.to_string()}')"


@dataclass(frozen=True)
class RoleName:
    """
    Immutable role name value object.

    Rules:
        - Must be 2-50 characters
        - Alphanumeric, hyphens, underscores only
        - Case-insensitive (stored as lowercase)
    """

    value: str

    def __post_init__(self) -> None:
        """Validate role name."""
        from rbac_core.domain.exceptions import InvalidRoleNameError

        if not self.value:
            raise InvalidRoleNameError(self.value, "Role name cannot be empty")

        if len(self.value) < 2:
            raise InvalidRoleNameError(self.value, "Role name must be at least 2 characters")

        if len(self.value) > 50:
            raise InvalidRoleNameError(self.value, "Role name cannot exceed 50 characters")

        # Validate format
        pattern = r"^[a-zA-Z0-9_\-]+$"
        if not re.match(pattern, self.value):
            raise InvalidRoleNameError(
                self.value,
                "Role name must contain only alphanumeric characters, hyphens, or underscores",
            )

        # Normalize to lowercase
        object.__setattr__(self, "value", self.value.lower())

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"RoleName('{self.value}')"


@dataclass(frozen=True)
class PolicyEffect:
    """
    Immutable policy effect value object.

    Valid effects: ALLOW, DENY
    """

    value: str

    ALLOW = "ALLOW"
    DENY = "DENY"

    def __post_init__(self) -> None:
        """Validate policy effect."""
        from rbac_core.domain.exceptions import InvalidPolicyError

        normalized = self.value.upper()
        if normalized not in {self.ALLOW, self.DENY}:
            raise InvalidPolicyError(
                self.value, f"Effect must be either '{self.ALLOW}' or '{self.DENY}'"
            )

        object.__setattr__(self, "value", normalized)

    @classmethod
    def allow(cls) -> "PolicyEffect":
        """Create ALLOW effect."""
        return cls(cls.ALLOW)

    @classmethod
    def deny(cls) -> "PolicyEffect":
        """Create DENY effect."""
        return cls(cls.DENY)

    def is_allow(self) -> bool:
        """Check if effect is ALLOW."""
        return self.value == self.ALLOW

    def is_deny(self) -> bool:
        """Check if effect is DENY."""
        return self.value == self.DENY

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"PolicyEffect('{self.value}')"
