"""Domain models for RBAC."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Set

from rbac_core.domain.exceptions import (
    InvalidRoleNameError,
    RoleAlreadyAssignedError,
    RoleNotAssignedError,
)
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName


@dataclass
class Role:
    """
    Role entity representing a collection of permissions.

    A role can be assigned to subjects (users, services, etc.) and grants
    them a specific set of permissions.
    """

    id: str
    name: RoleName
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        name: str,
        description: str,
        permissions: Optional[Set[Permission]] = None,
        metadata: Optional[dict] = None,
    ) -> "Role":
        """
        Create a new role.

        Args:
            name: Role name (will be normalized)
            description: Human-readable description
            permissions: Initial set of permissions
            metadata: Additional metadata

        Returns:
            New Role instance
        """
        role_name = RoleName(name)
        return cls(
            id=str(uuid.uuid4()),
            name=role_name,
            description=description,
            permissions=permissions or set(),
            metadata=metadata or {},
        )

    def add_permission(self, permission: Permission) -> None:
        """
        Add a permission to this role.

        Args:
            permission: Permission to add
        """
        self.permissions.add(permission)
        self.updated_at = datetime.utcnow()

    def remove_permission(self, permission: Permission) -> None:
        """
        Remove a permission from this role.

        Args:
            permission: Permission to remove
        """
        self.permissions.discard(permission)
        self.updated_at = datetime.utcnow()

    def has_permission(self, permission: Permission) -> bool:
        """
        Check if role has a specific permission (supports wildcards).

        Args:
            permission: Permission to check

        Returns:
            True if role has the permission
        """
        for role_perm in self.permissions:
            if role_perm.matches(permission):
                return True
        return False

    def update_description(self, description: str) -> None:
        """Update role description."""
        self.description = description
        self.updated_at = datetime.utcnow()

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Role):
            return False
        return self.id == other.id


@dataclass
class Policy:
    """
    Policy entity representing an access control rule.

    Policies can be more complex than simple role-permission mappings,
    supporting conditions and contextual evaluation.
    """

    id: str
    name: str
    description: str
    effect: PolicyEffect
    resources: Set[str] = field(default_factory=set)
    actions: Set[str] = field(default_factory=set)
    subjects: Set[str] = field(default_factory=set)  # Can be role IDs, user IDs, etc.
    conditions: dict = field(default_factory=dict)  # JSON-based conditions
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        name: str,
        description: str,
        effect: PolicyEffect,
        resources: Optional[Set[str]] = None,
        actions: Optional[Set[str]] = None,
        subjects: Optional[Set[str]] = None,
        conditions: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> "Policy":
        """
        Create a new policy.

        Args:
            name: Policy name
            description: Human-readable description
            effect: ALLOW or DENY
            resources: Resources this policy applies to
            actions: Actions this policy applies to
            subjects: Subjects (roles, users) this policy applies to
            conditions: Conditional rules (e.g., time-based, IP-based)
            metadata: Additional metadata

        Returns:
            New Policy instance
        """
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            effect=effect,
            resources=resources or set(),
            actions=actions or set(),
            subjects=subjects or set(),
            conditions=conditions or {},
            metadata=metadata or {},
        )

    def applies_to_subject(self, subject_id: str) -> bool:
        """Check if policy applies to a subject."""
        return not self.subjects or subject_id in self.subjects or "*" in self.subjects

    def applies_to_resource(self, resource: str) -> bool:
        """Check if policy applies to a resource (supports wildcards)."""
        if not self.resources:
            return True
        return resource in self.resources or "*" in self.resources

    def applies_to_action(self, action: str) -> bool:
        """Check if policy applies to an action (supports wildcards)."""
        if not self.actions:
            return True
        return action in self.actions or "*" in self.actions

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Policy):
            return False
        return self.id == other.id


@dataclass
class RoleAssignment:
    """
    Role assignment entity linking a subject to a role.

    Tracks which subjects (users, services, etc.) have which roles.
    """

    id: str
    subject_id: str  # User ID, service ID, etc.
    role_id: str
    assigned_at: datetime = field(default_factory=datetime.utcnow)
    assigned_by: Optional[str] = None  # Who assigned this role
    expires_at: Optional[datetime] = None  # Optional expiration
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        subject_id: str,
        role_id: str,
        assigned_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict] = None,
    ) -> "RoleAssignment":
        """
        Create a new role assignment.

        Args:
            subject_id: Subject receiving the role
            role_id: Role being assigned
            assigned_by: Who is assigning the role
            expires_at: When this assignment expires (optional)
            metadata: Additional metadata

        Returns:
            New RoleAssignment instance
        """
        return cls(
            id=str(uuid.uuid4()),
            subject_id=subject_id,
            role_id=role_id,
            assigned_by=assigned_by,
            expires_at=expires_at,
            metadata=metadata or {},
        )

    def is_expired(self) -> bool:
        """Check if assignment has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_active(self) -> bool:
        """Check if assignment is currently active."""
        return not self.is_expired()

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RoleAssignment):
            return False
        return self.id == other.id
