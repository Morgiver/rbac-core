"""Response DTOs for RBAC operations."""

from datetime import datetime
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field


class PermissionResponse(BaseModel):
    """Permission response DTO."""

    resource: str
    action: str
    permission_string: str

    @classmethod
    def from_domain(cls, permission: "Permission") -> "PermissionResponse":  # type: ignore
        """Create from domain Permission."""
        return cls(
            resource=permission.resource,
            action=permission.action,
            permission_string=permission.to_string(),
        )


class RoleResponse(BaseModel):
    """Role response DTO."""

    id: str
    name: str
    description: str
    permissions: List[str]
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, str]

    @classmethod
    def from_domain(cls, role: "Role") -> "RoleResponse":  # type: ignore
        """Create from domain Role."""
        return cls(
            id=role.id,
            name=str(role.name),
            description=role.description,
            permissions=[p.to_string() for p in role.permissions],
            created_at=role.created_at,
            updated_at=role.updated_at,
            metadata=role.metadata,
        )


class RoleListResponse(BaseModel):
    """List of roles response DTO."""

    roles: List[RoleResponse]
    total: int


class RoleAssignmentResponse(BaseModel):
    """Role assignment response DTO."""

    id: str
    subject_id: str
    role_id: str
    assigned_at: datetime
    assigned_by: Optional[str]
    expires_at: Optional[datetime]
    is_active: bool
    metadata: Dict[str, str]

    @classmethod
    def from_domain(cls, assignment: "RoleAssignment") -> "RoleAssignmentResponse":  # type: ignore
        """Create from domain RoleAssignment."""
        return cls(
            id=assignment.id,
            subject_id=assignment.subject_id,
            role_id=assignment.role_id,
            assigned_at=assignment.assigned_at,
            assigned_by=assignment.assigned_by,
            expires_at=assignment.expires_at,
            is_active=assignment.is_active(),
            metadata=assignment.metadata,
        )


class SubjectRolesResponse(BaseModel):
    """Subject's roles response DTO."""

    subject_id: str
    roles: List[RoleResponse]
    permissions: List[str]


class PolicyResponse(BaseModel):
    """Policy response DTO."""

    id: str
    name: str
    description: str
    effect: str
    resources: List[str]
    actions: List[str]
    subjects: List[str]
    conditions: Dict[str, str]
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, str]

    @classmethod
    def from_domain(cls, policy: "Policy") -> "PolicyResponse":  # type: ignore
        """Create from domain Policy."""
        return cls(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            effect=str(policy.effect),
            resources=list(policy.resources),
            actions=list(policy.actions),
            subjects=list(policy.subjects),
            conditions=policy.conditions,
            created_at=policy.created_at,
            updated_at=policy.updated_at,
            metadata=policy.metadata,
        )


class PolicyListResponse(BaseModel):
    """List of policies response DTO."""

    policies: List[PolicyResponse]
    total: int


class PermissionCheckResponse(BaseModel):
    """Permission check response DTO."""

    subject_id: str
    resource: str
    action: str
    granted: bool
    reason: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class AuthorizationDecisionResponse(BaseModel):
    """Authorization decision response DTO."""

    allowed: bool
    decision: str  # "ALLOW" or "DENY"
    matched_policies: List[str] = Field(default_factory=list)
    reason: Optional[str] = None
