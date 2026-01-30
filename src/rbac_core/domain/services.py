"""Domain services for RBAC business logic."""

import logging
from typing import Any, Dict, List, Optional, Set

from rbac_core.domain.exceptions import (
    PermissionDeniedError,
    RoleAlreadyAssignedError,
    RoleAlreadyExistsError,
    RoleNotAssignedError,
    RoleNotFoundError,
)
from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.domain.value_objects import Permission, PolicyEffect
from rbac_core.interfaces.policy_evaluator import IEventBus, IPolicyEvaluator
from rbac_core.interfaces.repository import (
    IPolicyRepository,
    IRoleAssignmentRepository,
    IRoleRepository,
)

logger = logging.getLogger(__name__)


class RoleService:
    """Service for managing roles and permissions."""

    def __init__(
        self, role_repository: IRoleRepository, event_bus: Optional[IEventBus] = None
    ) -> None:
        """
        Initialize role service.

        Args:
            role_repository: Repository for role persistence
            event_bus: Optional event bus for publishing events
        """
        self.role_repository = role_repository
        self.event_bus = event_bus

    def create_role(
        self,
        name: str,
        description: str,
        permissions: Optional[Set[Permission]] = None,
        metadata: Optional[dict] = None,
    ) -> Role:
        """
        Create a new role.

        Args:
            name: Role name
            description: Role description
            permissions: Initial permissions
            metadata: Additional metadata

        Returns:
            Created role

        Raises:
            RoleAlreadyExistsError: If role with same name exists
        """
        # Check if role already exists
        if self.role_repository.exists_by_name(name):
            raise RoleAlreadyExistsError(name)

        # Create role
        role = Role.create(
            name=name, description=description, permissions=permissions, metadata=metadata
        )

        # Save role
        saved_role = self.role_repository.save(role)

        # Publish event
        if self.event_bus:
            from rbac_core.events.events import RoleCreatedEvent

            self.event_bus.publish(
                RoleCreatedEvent(
                    role_id=saved_role.id,
                    role_name=str(saved_role.name),
                    permissions={p.to_string() for p in saved_role.permissions},
                )
            )

        logger.info(f"Role created: {saved_role.name} (ID: {saved_role.id})")
        return saved_role

    def add_permission_to_role(self, role_id: str, permission: Permission) -> Role:
        """
        Add permission to a role.

        Args:
            role_id: Role ID
            permission: Permission to add

        Returns:
            Updated role

        Raises:
            RoleNotFoundError: If role not found
        """
        role = self.role_repository.find_by_id(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        role.add_permission(permission)
        updated_role = self.role_repository.save(role)

        # Publish event
        if self.event_bus:
            from rbac_core.events.events import PermissionAddedToRoleEvent

            self.event_bus.publish(
                PermissionAddedToRoleEvent(
                    role_id=role_id, permission=permission.to_string()
                )
            )

        logger.info(f"Permission {permission} added to role {role.name}")
        return updated_role

    def remove_permission_from_role(self, role_id: str, permission: Permission) -> Role:
        """
        Remove permission from a role.

        Args:
            role_id: Role ID
            permission: Permission to remove

        Returns:
            Updated role

        Raises:
            RoleNotFoundError: If role not found
        """
        role = self.role_repository.find_by_id(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        role.remove_permission(permission)
        updated_role = self.role_repository.save(role)

        # Publish event
        if self.event_bus:
            from rbac_core.events.events import PermissionRemovedFromRoleEvent

            self.event_bus.publish(
                PermissionRemovedFromRoleEvent(
                    role_id=role_id, permission=permission.to_string()
                )
            )

        logger.info(f"Permission {permission} removed from role {role.name}")
        return updated_role

    def get_role(self, role_id: str) -> Role:
        """
        Get role by ID.

        Args:
            role_id: Role ID

        Returns:
            Role

        Raises:
            RoleNotFoundError: If role not found
        """
        role = self.role_repository.find_by_id(role_id)
        if not role:
            raise RoleNotFoundError(role_id)
        return role

    def get_role_by_name(self, name: str) -> Role:
        """
        Get role by name.

        Args:
            name: Role name

        Returns:
            Role

        Raises:
            RoleNotFoundError: If role not found
        """
        role = self.role_repository.find_by_name(name)
        if not role:
            raise RoleNotFoundError(name)
        return role

    def list_roles(self) -> List[Role]:
        """
        List all roles.

        Returns:
            List of roles
        """
        return self.role_repository.find_all()

    def delete_role(self, role_id: str) -> bool:
        """
        Delete a role.

        Args:
            role_id: Role ID

        Returns:
            True if deleted

        Raises:
            RoleNotFoundError: If role not found
        """
        if not self.role_repository.find_by_id(role_id):
            raise RoleNotFoundError(role_id)

        deleted = self.role_repository.delete(role_id)

        # Publish event
        if deleted and self.event_bus:
            from rbac_core.events.events import RoleDeletedEvent

            self.event_bus.publish(RoleDeletedEvent(role_id=role_id))

        logger.info(f"Role deleted: {role_id}")
        return deleted


class RoleAssignmentService:
    """Service for managing role assignments."""

    def __init__(
        self,
        role_repository: IRoleRepository,
        assignment_repository: IRoleAssignmentRepository,
        event_bus: Optional[IEventBus] = None,
    ) -> None:
        """
        Initialize role assignment service.

        Args:
            role_repository: Repository for roles
            assignment_repository: Repository for assignments
            event_bus: Optional event bus for publishing events
        """
        self.role_repository = role_repository
        self.assignment_repository = assignment_repository
        self.event_bus = event_bus

    def assign_role(
        self,
        subject_id: str,
        role_id: str,
        assigned_by: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> RoleAssignment:
        """
        Assign a role to a subject.

        Args:
            subject_id: Subject ID (user, service, etc.)
            role_id: Role ID to assign
            assigned_by: Who is assigning the role
            metadata: Additional metadata

        Returns:
            Created assignment

        Raises:
            RoleNotFoundError: If role not found
            RoleAlreadyAssignedError: If role already assigned
        """
        # Verify role exists
        role = self.role_repository.find_by_id(role_id)
        if not role:
            raise RoleNotFoundError(role_id)

        # Check if already assigned
        existing = self.assignment_repository.find_by_subject_and_role(subject_id, role_id)
        if existing and existing.is_active():
            raise RoleAlreadyAssignedError(subject_id, role_id)

        # Create assignment
        assignment = RoleAssignment.create(
            subject_id=subject_id,
            role_id=role_id,
            assigned_by=assigned_by,
            metadata=metadata,
        )

        # Save assignment
        saved_assignment = self.assignment_repository.save(assignment)

        # Publish event
        if self.event_bus:
            from rbac_core.events.events import RoleAssignedEvent

            self.event_bus.publish(
                RoleAssignedEvent(
                    assignment_id=saved_assignment.id,
                    subject_id=subject_id,
                    role_id=role_id,
                    role_name=str(role.name),
                )
            )

        logger.info(f"Role {role.name} assigned to subject {subject_id}")
        return saved_assignment

    def revoke_role(self, subject_id: str, role_id: str) -> bool:
        """
        Revoke a role from a subject.

        Args:
            subject_id: Subject ID
            role_id: Role ID

        Returns:
            True if revoked

        Raises:
            RoleNotAssignedError: If role not assigned
        """
        # Check if assigned
        assignment = self.assignment_repository.find_by_subject_and_role(subject_id, role_id)
        if not assignment:
            raise RoleNotAssignedError(subject_id, role_id)

        # Delete assignment
        deleted = self.assignment_repository.delete_by_subject_and_role(subject_id, role_id)

        # Publish event
        if deleted and self.event_bus:
            from rbac_core.events.events import RoleRevokedEvent

            self.event_bus.publish(
                RoleRevokedEvent(subject_id=subject_id, role_id=role_id)
            )

        logger.info(f"Role {role_id} revoked from subject {subject_id}")
        return deleted

    def get_subject_roles(self, subject_id: str) -> List[Role]:
        """
        Get all active roles for a subject.

        Args:
            subject_id: Subject ID

        Returns:
            List of roles
        """
        assignments = self.assignment_repository.find_by_subject(subject_id)

        # Get only active assignments
        active_role_ids = [a.role_id for a in assignments if a.is_active()]

        # Fetch roles
        roles = []
        for role_id in active_role_ids:
            role = self.role_repository.find_by_id(role_id)
            if role:
                roles.append(role)

        return roles

    def get_subject_permissions(self, subject_id: str) -> Set[Permission]:
        """
        Get all permissions for a subject (aggregated from all roles).

        Args:
            subject_id: Subject ID

        Returns:
            Set of permissions
        """
        roles = self.get_subject_roles(subject_id)
        permissions: Set[Permission] = set()

        for role in roles:
            permissions.update(role.permissions)

        return permissions


class AuthorizationService:
    """Service for authorization decisions."""

    def __init__(
        self,
        role_assignment_service: RoleAssignmentService,
        policy_repository: Optional[IPolicyRepository] = None,
        policy_evaluator: Optional[IPolicyEvaluator] = None,
    ) -> None:
        """
        Initialize authorization service.

        Args:
            role_assignment_service: Service for role assignments
            policy_repository: Optional repository for policies
            policy_evaluator: Optional policy evaluator
        """
        self.role_assignment_service = role_assignment_service
        self.policy_repository = policy_repository
        self.policy_evaluator = policy_evaluator

    def check_permission(
        self, subject_id: str, permission: Permission, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if subject has a specific permission.

        Args:
            subject_id: Subject ID
            permission: Permission to check
            context: Additional context for policy evaluation

        Returns:
            True if authorized
        """
        # Get subject permissions from roles
        subject_permissions = self.role_assignment_service.get_subject_permissions(subject_id)

        # Check role-based permissions
        for perm in subject_permissions:
            if perm.matches(permission):
                logger.debug(f"Permission granted to {subject_id} for {permission} (role-based)")
                return True

        # If policy evaluator available, check policies
        if self.policy_repository and self.policy_evaluator:
            policies = self.policy_repository.find_by_subject(subject_id)
            if policies:
                result = self.policy_evaluator.evaluate(
                    policies, subject_id, permission, context or {}
                )
                if result:
                    logger.debug(
                        f"Permission granted to {subject_id} for {permission} (policy-based)"
                    )
                    return result

        logger.debug(f"Permission denied to {subject_id} for {permission}")
        return False

    def enforce_permission(
        self, subject_id: str, permission: Permission, context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Enforce permission check (raises exception if denied).

        Args:
            subject_id: Subject ID
            permission: Permission to check
            context: Additional context

        Raises:
            PermissionDeniedError: If permission denied
        """
        if not self.check_permission(subject_id, permission, context):
            raise PermissionDeniedError(subject_id, permission.resource, permission.action)
