"""Request DTOs for RBAC operations."""

from datetime import datetime
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator


class CreateRoleRequest(BaseModel):
    """Request to create a new role."""

    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=1, max_length=500)
    permissions: Set[str] = Field(default_factory=set)
    metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate role name format."""
        import re

        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError(
                "Role name must contain only alphanumeric characters, hyphens, or underscores"
            )
        return v.lower()

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: Set[str]) -> Set[str]:
        """Validate permission format."""
        for perm in v:
            if ":" not in perm:
                raise ValueError(f"Permission '{perm}' must be in format 'resource:action'")
        return v


class UpdateRoleRequest(BaseModel):
    """Request to update a role."""

    description: Optional[str] = Field(None, min_length=1, max_length=500)
    metadata: Optional[Dict[str, str]] = None


class AddPermissionRequest(BaseModel):
    """Request to add a permission to a role."""

    permission: str = Field(..., pattern=r"^[a-zA-Z0-9_\-*]+:[a-zA-Z0-9_\-*]+$")


class RemovePermissionRequest(BaseModel):
    """Request to remove a permission from a role."""

    permission: str = Field(..., pattern=r"^[a-zA-Z0-9_\-*]+:[a-zA-Z0-9_\-*]+$")


class AssignRoleRequest(BaseModel):
    """Request to assign a role to a subject."""

    subject_id: str = Field(..., min_length=1)
    role_id: str = Field(..., min_length=1)
    assigned_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, str] = Field(default_factory=dict)


class RevokeRoleRequest(BaseModel):
    """Request to revoke a role from a subject."""

    subject_id: str = Field(..., min_length=1)
    role_id: str = Field(..., min_length=1)


class CheckPermissionRequest(BaseModel):
    """Request to check if a subject has a permission."""

    subject_id: str = Field(..., min_length=1)
    resource: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    context: Dict[str, str] = Field(default_factory=dict)


class CreatePolicyRequest(BaseModel):
    """Request to create a new policy."""

    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    effect: str = Field(..., pattern=r"^(ALLOW|DENY)$")
    resources: Set[str] = Field(default_factory=set)
    actions: Set[str] = Field(default_factory=set)
    subjects: Set[str] = Field(default_factory=set)
    conditions: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("effect")
    @classmethod
    def validate_effect(cls, v: str) -> str:
        """Normalize effect to uppercase."""
        return v.upper()


class UpdatePolicyRequest(BaseModel):
    """Request to update a policy."""

    description: Optional[str] = Field(None, min_length=1, max_length=500)
    effect: Optional[str] = Field(None, pattern=r"^(ALLOW|DENY)$")
    resources: Optional[Set[str]] = None
    actions: Optional[Set[str]] = None
    subjects: Optional[Set[str]] = None
    conditions: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, str]] = None
