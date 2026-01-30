"""
RBAC Core - Framework-agnostic Role-Based Access Control package.

This package provides a clean hexagonal architecture implementation for RBAC,
allowing you to manage roles, permissions, and policies in any application context.
"""

__version__ = "0.1.0"

# Domain models
from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName

# Domain services
from rbac_core.domain.services import (
    AuthorizationService,
    RoleAssignmentService,
    RoleService,
)

# Domain exceptions
from rbac_core.domain.exceptions import (
    InvalidPermissionError,
    InvalidPolicyError,
    InvalidRoleNameError,
    PermissionDeniedError,
    PolicyEvaluationError,
    RBACError,
    RoleAlreadyAssignedError,
    RoleAlreadyExistsError,
    RoleError,
    RoleNotAssignedError,
    RoleNotFoundError,
)

# Interfaces
from rbac_core.interfaces.repository import (
    IPolicyRepository,
    IRoleAssignmentRepository,
    IRoleRepository,
)
from rbac_core.interfaces.policy_evaluator import IEventBus, IPolicyEvaluator

# DTOs
from rbac_core.dto.requests import (
    AddPermissionRequest,
    AssignRoleRequest,
    CheckPermissionRequest,
    CreatePolicyRequest,
    CreateRoleRequest,
    RemovePermissionRequest,
    RevokeRoleRequest,
    UpdatePolicyRequest,
    UpdateRoleRequest,
)
from rbac_core.dto.responses import (
    AuthorizationDecisionResponse,
    PermissionCheckResponse,
    PermissionResponse,
    PolicyListResponse,
    PolicyResponse,
    RoleAssignmentResponse,
    RoleListResponse,
    RoleResponse,
    SubjectRolesResponse,
)

# Events
from rbac_core.events.events import (
    AccessDeniedEvent,
    AccessGrantedEvent,
    PermissionAddedToRoleEvent,
    PermissionRemovedFromRoleEvent,
    PolicyCreatedEvent,
    PolicyDeletedEvent,
    RoleAssignedEvent,
    RoleCreatedEvent,
    RoleDeletedEvent,
    RoleRevokedEvent,
)

__all__ = [
    # Version
    "__version__",
    # Domain models
    "Role",
    "Permission",
    "Policy",
    "RoleAssignment",
    "RoleName",
    "PolicyEffect",
    # Domain services
    "RoleService",
    "RoleAssignmentService",
    "AuthorizationService",
    # Exceptions
    "RBACError",
    "RoleError",
    "RoleAlreadyExistsError",
    "RoleNotFoundError",
    "InvalidRoleNameError",
    "InvalidPermissionError",
    "InvalidPolicyError",
    "PermissionDeniedError",
    "PolicyEvaluationError",
    "RoleAlreadyAssignedError",
    "RoleNotAssignedError",
    # Interfaces
    "IRoleRepository",
    "IPolicyRepository",
    "IRoleAssignmentRepository",
    "IPolicyEvaluator",
    "IEventBus",
    # DTOs - Requests
    "CreateRoleRequest",
    "UpdateRoleRequest",
    "AddPermissionRequest",
    "RemovePermissionRequest",
    "AssignRoleRequest",
    "RevokeRoleRequest",
    "CheckPermissionRequest",
    "CreatePolicyRequest",
    "UpdatePolicyRequest",
    # DTOs - Responses
    "RoleResponse",
    "RoleListResponse",
    "RoleAssignmentResponse",
    "SubjectRolesResponse",
    "PolicyResponse",
    "PolicyListResponse",
    "PermissionResponse",
    "PermissionCheckResponse",
    "AuthorizationDecisionResponse",
    # Events
    "RoleCreatedEvent",
    "RoleDeletedEvent",
    "PermissionAddedToRoleEvent",
    "PermissionRemovedFromRoleEvent",
    "RoleAssignedEvent",
    "RoleRevokedEvent",
    "PolicyCreatedEvent",
    "PolicyDeletedEvent",
    "AccessGrantedEvent",
    "AccessDeniedEvent",
]
