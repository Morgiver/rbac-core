"""Abstract repository interfaces for RBAC persistence."""

from abc import ABC, abstractmethod
from typing import List, Optional, Set

from rbac_core.domain.models import Policy, Role, RoleAssignment


class IRoleRepository(ABC):
    """Interface for role persistence."""

    @abstractmethod
    def save(self, role: Role) -> Role:
        """
        Save a role.

        Args:
            role: Role to save

        Returns:
            Saved role

        Raises:
            RoleAlreadyExistsError: If role with same name already exists
        """
        pass

    @abstractmethod
    def find_by_id(self, role_id: str) -> Optional[Role]:
        """
        Find role by ID.

        Args:
            role_id: Role ID

        Returns:
            Role if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_name(self, name: str) -> Optional[Role]:
        """
        Find role by name.

        Args:
            name: Role name (case-insensitive)

        Returns:
            Role if found, None otherwise
        """
        pass

    @abstractmethod
    def find_all(self) -> List[Role]:
        """
        Retrieve all roles.

        Returns:
            List of all roles
        """
        pass

    @abstractmethod
    def delete(self, role_id: str) -> bool:
        """
        Delete a role.

        Args:
            role_id: Role ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def exists_by_name(self, name: str) -> bool:
        """
        Check if role exists by name.

        Args:
            name: Role name

        Returns:
            True if exists
        """
        pass


class IPolicyRepository(ABC):
    """Interface for policy persistence."""

    @abstractmethod
    def save(self, policy: Policy) -> Policy:
        """
        Save a policy.

        Args:
            policy: Policy to save

        Returns:
            Saved policy
        """
        pass

    @abstractmethod
    def find_by_id(self, policy_id: str) -> Optional[Policy]:
        """
        Find policy by ID.

        Args:
            policy_id: Policy ID

        Returns:
            Policy if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_subject(self, subject_id: str) -> List[Policy]:
        """
        Find all policies applicable to a subject.

        Args:
            subject_id: Subject ID (user, role, etc.)

        Returns:
            List of applicable policies
        """
        pass

    @abstractmethod
    def find_all(self) -> List[Policy]:
        """
        Retrieve all policies.

        Returns:
            List of all policies
        """
        pass

    @abstractmethod
    def delete(self, policy_id: str) -> bool:
        """
        Delete a policy.

        Args:
            policy_id: Policy ID

        Returns:
            True if deleted, False if not found
        """
        pass


class IRoleAssignmentRepository(ABC):
    """Interface for role assignment persistence."""

    @abstractmethod
    def save(self, assignment: RoleAssignment) -> RoleAssignment:
        """
        Save a role assignment.

        Args:
            assignment: Assignment to save

        Returns:
            Saved assignment
        """
        pass

    @abstractmethod
    def find_by_id(self, assignment_id: str) -> Optional[RoleAssignment]:
        """
        Find assignment by ID.

        Args:
            assignment_id: Assignment ID

        Returns:
            Assignment if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_subject(self, subject_id: str) -> List[RoleAssignment]:
        """
        Find all role assignments for a subject.

        Args:
            subject_id: Subject ID

        Returns:
            List of role assignments
        """
        pass

    @abstractmethod
    def find_by_role(self, role_id: str) -> List[RoleAssignment]:
        """
        Find all assignments for a role.

        Args:
            role_id: Role ID

        Returns:
            List of assignments
        """
        pass

    @abstractmethod
    def find_by_subject_and_role(
        self, subject_id: str, role_id: str
    ) -> Optional[RoleAssignment]:
        """
        Find assignment for a specific subject-role pair.

        Args:
            subject_id: Subject ID
            role_id: Role ID

        Returns:
            Assignment if found, None otherwise
        """
        pass

    @abstractmethod
    def delete(self, assignment_id: str) -> bool:
        """
        Delete a role assignment.

        Args:
            assignment_id: Assignment ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def delete_by_subject_and_role(self, subject_id: str, role_id: str) -> bool:
        """
        Delete assignment by subject-role pair.

        Args:
            subject_id: Subject ID
            role_id: Role ID

        Returns:
            True if deleted, False if not found
        """
        pass
