"""Domain events for RBAC operations."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Set


@dataclass(frozen=True)
class RoleCreatedEvent:
    """Event published when a role is created."""

    role_id: str
    role_name: str
    permissions: Set[str]
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class RoleDeletedEvent:
    """Event published when a role is deleted."""

    role_id: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class PermissionAddedToRoleEvent:
    """Event published when a permission is added to a role."""

    role_id: str
    permission: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class PermissionRemovedFromRoleEvent:
    """Event published when a permission is removed from a role."""

    role_id: str
    permission: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class RoleAssignedEvent:
    """Event published when a role is assigned to a subject."""

    assignment_id: str
    subject_id: str
    role_id: str
    role_name: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class RoleRevokedEvent:
    """Event published when a role is revoked from a subject."""

    subject_id: str
    role_id: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class PolicyCreatedEvent:
    """Event published when a policy is created."""

    policy_id: str
    policy_name: str
    effect: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class PolicyDeletedEvent:
    """Event published when a policy is deleted."""

    policy_id: str
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class AccessGrantedEvent:
    """Event published when access is granted."""

    subject_id: str
    resource: str
    action: str
    granted_by: str  # "role" or "policy"
    timestamp: datetime = datetime.utcnow()


@dataclass(frozen=True)
class AccessDeniedEvent:
    """Event published when access is denied."""

    subject_id: str
    resource: str
    action: str
    reason: str
    timestamp: datetime = datetime.utcnow()
