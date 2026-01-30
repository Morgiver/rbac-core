"""
Basic RBAC example demonstrating role creation, assignment, and authorization.

This example shows how to:
1. Create roles with permissions
2. Assign roles to users
3. Check if users have specific permissions
"""

import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from rbac_core import (
    AuthorizationService,
    Permission,
    RoleAssignmentService,
    RoleService,
)
from rbac_core.adapters.repositories.memory import (
    InMemoryRoleAssignmentRepository,
    InMemoryRoleRepository,
)
from rbac_core.adapters.policy_evaluators.simple_evaluator import InMemoryEventBus


def main() -> None:
    """Run the basic RBAC example."""
    print("=" * 60)
    print("Basic RBAC Example")
    print("=" * 60)

    # Step 1: Initialize repositories
    print("\n[1] Initializing repositories...")
    role_repo = InMemoryRoleRepository()
    assignment_repo = InMemoryRoleAssignmentRepository()
    event_bus = InMemoryEventBus()

    # Step 2: Initialize services
    print("[2] Initializing services...")
    role_service = RoleService(role_repo, event_bus)
    assignment_service = RoleAssignmentService(role_repo, assignment_repo, event_bus)
    authz_service = AuthorizationService(assignment_service)

    # Step 3: Create roles
    print("\n[3] Creating roles...")

    # Admin role with full permissions
    admin_role = role_service.create_role(
        name="admin",
        description="Administrator with full access",
        permissions={
            Permission(resource="*", action="*"),  # Wildcard: all permissions
        },
    )
    print(f"   Created role: {admin_role.name} (ID: {admin_role.id})")

    # Editor role with write permissions
    editor_role = role_service.create_role(
        name="editor",
        description="Can create and edit content",
        permissions={
            Permission(resource="posts", action="create"),
            Permission(resource="posts", action="update"),
            Permission(resource="posts", action="read"),
        },
    )
    print(f"   Created role: {editor_role.name} (ID: {editor_role.id})")

    # Viewer role with read-only permissions
    viewer_role = role_service.create_role(
        name="viewer",
        description="Read-only access",
        permissions={
            Permission(resource="posts", action="read"),
            Permission(resource="users", action="read"),
        },
    )
    print(f"   Created role: {viewer_role.name} (ID: {viewer_role.id})")

    # Step 4: Assign roles to users
    print("\n[4] Assigning roles to users...")

    assignment_service.assign_role(
        subject_id="user-alice", role_id=admin_role.id, assigned_by="system"
    )
    print("   Assigned 'admin' role to user-alice")

    assignment_service.assign_role(
        subject_id="user-bob", role_id=editor_role.id, assigned_by="system"
    )
    print("   Assigned 'editor' role to user-bob")

    assignment_service.assign_role(
        subject_id="user-charlie", role_id=viewer_role.id, assigned_by="system"
    )
    print("   Assigned 'viewer' role to user-charlie")

    # Step 5: Check permissions
    print("\n[5] Checking permissions...")

    # Alice (admin) can do anything
    can_alice_delete = authz_service.check_permission(
        subject_id="user-alice", permission=Permission(resource="posts", action="delete")
    )
    print(f"   Can Alice delete posts? {can_alice_delete}")

    # Bob (editor) can create posts
    can_bob_create = authz_service.check_permission(
        subject_id="user-bob", permission=Permission(resource="posts", action="create")
    )
    print(f"   Can Bob create posts? {can_bob_create}")

    # Bob (editor) cannot delete posts
    can_bob_delete = authz_service.check_permission(
        subject_id="user-bob", permission=Permission(resource="posts", action="delete")
    )
    print(f"   Can Bob delete posts? {can_bob_delete}")

    # Charlie (viewer) can read posts
    can_charlie_read = authz_service.check_permission(
        subject_id="user-charlie",
        permission=Permission(resource="posts", action="read"),
    )
    print(f"   Can Charlie read posts? {can_charlie_read}")

    # Charlie (viewer) cannot create posts
    can_charlie_create = authz_service.check_permission(
        subject_id="user-charlie",
        permission=Permission(resource="posts", action="create"),
    )
    print(f"   Can Charlie create posts? {can_charlie_create}")

    # Step 6: Get user roles and permissions
    print("\n[6] Listing user roles and permissions...")

    bob_roles = assignment_service.get_subject_roles("user-bob")
    bob_permissions = assignment_service.get_subject_permissions("user-bob")

    print(f"   Bob's roles: {[str(r.name) for r in bob_roles]}")
    print(f"   Bob's permissions: {[p.to_string() for p in bob_permissions]}")

    # Step 7: Demonstrate enforced permission check
    print("\n[7] Demonstrating enforced permission check...")

    try:
        authz_service.enforce_permission(
            subject_id="user-charlie",
            permission=Permission(resource="posts", action="delete"),
        )
        print("   Charlie was allowed to delete posts")
    except Exception as e:
        print(f"   Permission denied: {e}")

    # Step 8: Check events
    print(f"\n[8] Events published: {len(event_bus.events)}")
    for i, event in enumerate(event_bus.events[:5], 1):
        print(f"   {i}. {type(event).__name__}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
