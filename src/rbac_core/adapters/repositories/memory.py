"""In-memory repository implementations for RBAC."""

from typing import Dict, List, Optional

from rbac_core.domain.exceptions import RoleAlreadyExistsError
from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.interfaces.repository import (
    IPolicyRepository,
    IRoleAssignmentRepository,
    IRoleRepository,
)


class InMemoryRoleRepository(IRoleRepository):
    """In-memory implementation of role repository."""

    def __init__(self) -> None:
        self._roles: Dict[str, Role] = {}

    def save(self, role: Role) -> Role:
        """Save a role."""
        # Check for duplicate name (excluding same ID)
        for existing_role in self._roles.values():
            if existing_role.name == role.name and existing_role.id != role.id:
                raise RoleAlreadyExistsError(str(role.name))

        self._roles[role.id] = role
        return role

    def find_by_id(self, role_id: str) -> Optional[Role]:
        """Find role by ID."""
        return self._roles.get(role_id)

    def find_by_name(self, name: str) -> Optional[Role]:
        """Find role by name (case-insensitive)."""
        normalized_name = name.lower()
        for role in self._roles.values():
            if str(role.name) == normalized_name:
                return role
        return None

    def find_all(self) -> List[Role]:
        """Retrieve all roles."""
        return list(self._roles.values())

    def delete(self, role_id: str) -> bool:
        """Delete a role."""
        if role_id in self._roles:
            del self._roles[role_id]
            return True
        return False

    def exists_by_name(self, name: str) -> bool:
        """Check if role exists by name."""
        return self.find_by_name(name) is not None


class InMemoryPolicyRepository(IPolicyRepository):
    """In-memory implementation of policy repository."""

    def __init__(self) -> None:
        self._policies: Dict[str, Policy] = {}

    def save(self, policy: Policy) -> Policy:
        """Save a policy."""
        self._policies[policy.id] = policy
        return policy

    def find_by_id(self, policy_id: str) -> Optional[Policy]:
        """Find policy by ID."""
        return self._policies.get(policy_id)

    def find_by_subject(self, subject_id: str) -> List[Policy]:
        """Find all policies applicable to a subject."""
        return [
            policy
            for policy in self._policies.values()
            if policy.applies_to_subject(subject_id)
        ]

    def find_all(self) -> List[Policy]:
        """Retrieve all policies."""
        return list(self._policies.values())

    def delete(self, policy_id: str) -> bool:
        """Delete a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False


class InMemoryRoleAssignmentRepository(IRoleAssignmentRepository):
    """In-memory implementation of role assignment repository."""

    def __init__(self) -> None:
        self._assignments: Dict[str, RoleAssignment] = {}

    def save(self, assignment: RoleAssignment) -> RoleAssignment:
        """Save a role assignment."""
        self._assignments[assignment.id] = assignment
        return assignment

    def find_by_id(self, assignment_id: str) -> Optional[RoleAssignment]:
        """Find assignment by ID."""
        return self._assignments.get(assignment_id)

    def find_by_subject(self, subject_id: str) -> List[RoleAssignment]:
        """Find all role assignments for a subject."""
        return [
            assignment
            for assignment in self._assignments.values()
            if assignment.subject_id == subject_id
        ]

    def find_by_role(self, role_id: str) -> List[RoleAssignment]:
        """Find all assignments for a role."""
        return [
            assignment
            for assignment in self._assignments.values()
            if assignment.role_id == role_id
        ]

    def find_by_subject_and_role(
        self, subject_id: str, role_id: str
    ) -> Optional[RoleAssignment]:
        """Find assignment for a specific subject-role pair."""
        for assignment in self._assignments.values():
            if assignment.subject_id == subject_id and assignment.role_id == role_id:
                return assignment
        return None

    def delete(self, assignment_id: str) -> bool:
        """Delete a role assignment."""
        if assignment_id in self._assignments:
            del self._assignments[assignment_id]
            return True
        return False

    def delete_by_subject_and_role(self, subject_id: str, role_id: str) -> bool:
        """Delete assignment by subject-role pair."""
        assignment = self.find_by_subject_and_role(subject_id, role_id)
        if assignment:
            return self.delete(assignment.id)
        return False
