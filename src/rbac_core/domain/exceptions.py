"""Domain exceptions for RBAC operations."""


class RBACError(Exception):
    """Base exception for all RBAC-related errors."""

    pass


class RoleError(RBACError):
    """Base exception for role-related errors."""

    pass


class RoleAlreadyExistsError(RoleError):
    """Raised when attempting to create a role that already exists."""

    def __init__(self, role_name: str) -> None:
        super().__init__(f"Role '{role_name}' already exists")
        self.role_name = role_name


class RoleNotFoundError(RoleError):
    """Raised when a role cannot be found."""

    def __init__(self, role_id: str) -> None:
        super().__init__(f"Role with ID '{role_id}' not found")
        self.role_id = role_id


class InvalidRoleNameError(RoleError):
    """Raised when a role name is invalid."""

    def __init__(self, role_name: str, reason: str) -> None:
        super().__init__(f"Invalid role name '{role_name}': {reason}")
        self.role_name = role_name
        self.reason = reason


class PermissionError(RBACError):
    """Base exception for permission-related errors."""

    pass


class InvalidPermissionError(PermissionError):
    """Raised when a permission format is invalid."""

    def __init__(self, permission: str, reason: str) -> None:
        super().__init__(f"Invalid permission '{permission}': {reason}")
        self.permission = permission
        self.reason = reason


class PermissionDeniedError(PermissionError):
    """Raised when access is denied."""

    def __init__(self, subject_id: str, resource: str, action: str) -> None:
        super().__init__(
            f"Permission denied: subject '{subject_id}' cannot '{action}' on '{resource}'"
        )
        self.subject_id = subject_id
        self.resource = resource
        self.action = action


class PolicyError(RBACError):
    """Base exception for policy-related errors."""

    pass


class InvalidPolicyError(PolicyError):
    """Raised when a policy is malformed or invalid."""

    def __init__(self, policy_id: str, reason: str) -> None:
        super().__init__(f"Invalid policy '{policy_id}': {reason}")
        self.policy_id = policy_id
        self.reason = reason


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation fails."""

    def __init__(self, policy_id: str, reason: str) -> None:
        super().__init__(f"Policy evaluation failed for '{policy_id}': {reason}")
        self.policy_id = policy_id
        self.reason = reason


class RoleAssignmentError(RBACError):
    """Base exception for role assignment errors."""

    pass


class RoleAlreadyAssignedError(RoleAssignmentError):
    """Raised when attempting to assign a role that's already assigned."""

    def __init__(self, subject_id: str, role_id: str) -> None:
        super().__init__(f"Role '{role_id}' is already assigned to subject '{subject_id}'")
        self.subject_id = subject_id
        self.role_id = role_id


class RoleNotAssignedError(RoleAssignmentError):
    """Raised when attempting to revoke a role that's not assigned."""

    def __init__(self, subject_id: str, role_id: str) -> None:
        super().__init__(f"Role '{role_id}' is not assigned to subject '{subject_id}'")
        self.subject_id = subject_id
        self.role_id = role_id
