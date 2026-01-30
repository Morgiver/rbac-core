# RBAC Core

**Framework-agnostic Role-Based Access Control (RBAC) package** following hexagonal architecture and Domain-Driven Design principles.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Clean Architecture**: Hexagonal architecture with clear separation of concerns
- **Framework-Agnostic**: Use with FastAPI, Flask, Django, or any Python application
- **Domain-Driven Design**: Rich domain models with business logic
- **Flexible Permissions**: Support for resource-action permissions with wildcards
- **Policy-Based Control**: Advanced policies with conditions and context evaluation
- **Event-Driven**: Domain events for audit trails and inter-service communication
- **Extensible**: Easy to implement custom repositories and policy evaluators
- **Type-Safe**: Full type hints for better IDE support and type checking
- **Well-Tested**: Comprehensive test suite with unit, integration, and contract tests

## Installation

```bash
# Basic installation
pip install rbac-core

# With SQLAlchemy support
pip install rbac-core[sqlalchemy]

# With MongoDB support
pip install rbac-core[mongodb]

# All adapters
pip install rbac-core[all]
```

## Quick Start

```python
from rbac_core import (
    AuthorizationService,
    Permission,
    RoleAssignmentService,
    RoleService,
)
from rbac_core.adapters.repositories.memory import (
    InMemoryRoleRepository,
    InMemoryRoleAssignmentRepository,
)

# Initialize services
role_repo = InMemoryRoleRepository()
assignment_repo = InMemoryRoleAssignmentRepository()

role_service = RoleService(role_repo)
assignment_service = RoleAssignmentService(role_repo, assignment_repo)
authz_service = AuthorizationService(assignment_service)

# Create roles
admin_role = role_service.create_role(
    name="admin",
    description="Administrator",
    permissions={Permission(resource="*", action="*")}
)

editor_role = role_service.create_role(
    name="editor",
    description="Content editor",
    permissions={
        Permission(resource="posts", action="create"),
        Permission(resource="posts", action="update"),
        Permission(resource="posts", action="read"),
    }
)

# Assign roles to users
assignment_service.assign_role(
    subject_id="user-123",
    role_id=admin_role.id
)

assignment_service.assign_role(
    subject_id="user-456",
    role_id=editor_role.id
)

# Check permissions
can_delete = authz_service.check_permission(
    subject_id="user-456",
    permission=Permission(resource="posts", action="delete")
)
print(f"Can user-456 delete posts? {can_delete}")  # False

# Enforce permission (raises exception if denied)
authz_service.enforce_permission(
    subject_id="user-123",
    permission=Permission(resource="posts", action="delete")
)  # OK - admin has wildcard permission
```

## Core Concepts

### Permissions

Permissions follow the `resource:action` format:

```python
from rbac_core import Permission

# Specific permissions
read_users = Permission(resource="users", action="read")
create_posts = Permission(resource="posts", action="create")

# Wildcard permissions
all_on_users = Permission(resource="users", action="*")
all_permissions = Permission(resource="*", action="*")

# From string
perm = Permission.from_string("documents:delete")
```

### Roles

Roles are collections of permissions:

```python
role = role_service.create_role(
    name="moderator",
    description="Content moderator",
    permissions={
        Permission(resource="posts", action="read"),
        Permission(resource="posts", action="update"),
        Permission(resource="comments", action="delete"),
    }
)

# Add/remove permissions
role_service.add_permission_to_role(
    role_id=role.id,
    permission=Permission(resource="users", action="ban")
)
```

### Role Assignments

Assign roles to subjects (users, services, etc.):

```python
# Simple assignment
assignment = assignment_service.assign_role(
    subject_id="user-789",
    role_id=moderator_role.id,
    assigned_by="admin-user"
)

# Time-limited assignment
from datetime import datetime, timedelta

assignment = assignment_service.assign_role(
    subject_id="temp-user",
    role_id=role.id,
    expires_at=datetime.utcnow() + timedelta(days=7)
)

# Get user's roles and permissions
roles = assignment_service.get_subject_roles("user-789")
permissions = assignment_service.get_subject_permissions("user-789")
```

### Authorization

Check and enforce permissions:

```python
# Check permission (returns bool)
allowed = authz_service.check_permission(
    subject_id="user-123",
    permission=Permission(resource="posts", action="delete")
)

# Enforce permission (raises PermissionDeniedError if denied)
from rbac_core import PermissionDeniedError

try:
    authz_service.enforce_permission(
        subject_id="user-123",
        permission=Permission(resource="admin", action="access")
    )
except PermissionDeniedError as e:
    print(f"Access denied: {e}")
```

## Architecture

```
┌─────────────────────────────────────┐
│      Your Application Layer         │
│   (FastAPI, Flask, Django, etc.)    │
└──────────────┬──────────────────────┘
               │
        ┌──────▼──────┐
        │  Services   │  ← RoleService, AuthorizationService
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │   Domain    │  ← Role, Permission, Policy
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │ Interfaces  │  ← IRoleRepository, IPolicyEvaluator
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │  Adapters   │  ← InMemory, SQLAlchemy, MongoDB
        └─────────────┘
```

### Package Structure

```
rbac-core/
├── src/rbac_core/
│   ├── domain/              # Core business logic
│   │   ├── models.py           # Role, Policy, RoleAssignment
│   │   ├── value_objects.py    # Permission, RoleName, PolicyEffect
│   │   ├── services.py         # RoleService, AuthorizationService
│   │   └── exceptions.py       # Domain exceptions
│   │
│   ├── interfaces/          # Abstract contracts
│   │   ├── repository.py       # IRoleRepository, IPolicyRepository
│   │   └── policy_evaluator.py # IPolicyEvaluator
│   │
│   ├── dto/                 # Data Transfer Objects
│   │   ├── requests.py         # Request DTOs with validation
│   │   └── responses.py        # Response DTOs
│   │
│   ├── events/              # Domain events
│   │   └── events.py           # RoleCreatedEvent, etc.
│   │
│   └── adapters/            # Concrete implementations
│       ├── repositories/       # InMemory, SQLAlchemy, MongoDB
│       └── policy_evaluators/  # SimplePolicyEvaluator
│
├── tests/
│   ├── unit/                # Fast, isolated tests
│   ├── contracts/           # Interface compliance tests
│   └── e2e/                 # End-to-end scenarios
│
└── examples/
    └── 01_basic_rbac/       # Working examples
```

## Repository Adapters

RBAC-Core supports multiple storage backends through repository adapters.

### In-Memory (for testing/prototyping)

```python
from rbac_core.adapters.repositories.memory import (
    InMemoryRoleRepository,
    InMemoryPolicyRepository,
    InMemoryRoleAssignmentRepository,
)

role_repo = InMemoryRoleRepository()
policy_repo = InMemoryPolicyRepository()
assignment_repo = InMemoryRoleAssignmentRepository()
```

### SQLAlchemy (PostgreSQL, MySQL, SQLite, etc.)

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from rbac_core.adapters.repositories.sqlalchemy import (
    SQLAlchemyRoleRepository,
    SQLAlchemyPolicyRepository,
    SQLAlchemyRoleAssignmentRepository,
    Base,
)

# Setup database
engine = create_engine("postgresql://user:pass@localhost/dbname")
Base.metadata.create_all(engine)  # Create tables

# Create session
Session = sessionmaker(bind=engine)
session = Session()

# Initialize repositories
role_repo = SQLAlchemyRoleRepository(session)
policy_repo = SQLAlchemyPolicyRepository(session)
assignment_repo = SQLAlchemyRoleAssignmentRepository(session)

# Use with services
role_service = RoleService(role_repo)
```

### MongoDB

```python
from pymongo import MongoClient
from rbac_core.adapters.repositories.mongodb import (
    MongoDBRoleRepository,
    MongoDBPolicyRepository,
    MongoDBRoleAssignmentRepository,
)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["rbac_db"]

# Initialize repositories
role_repo = MongoDBRoleRepository(db)
policy_repo = MongoDBPolicyRepository(db)
assignment_repo = MongoDBRoleAssignmentRepository(db)

# Use with services
role_service = RoleService(role_repo)
```

### Custom Repository

Implement your own repository by extending the interface:

```python
from rbac_core.interfaces.repository import IRoleRepository
from rbac_core.domain.models import Role

class RedisRoleRepository(IRoleRepository):
    def __init__(self, redis_client):
        self.redis = redis_client

    def save(self, role: Role) -> Role:
        # Your Redis implementation
        pass

    def find_by_id(self, role_id: str) -> Optional[Role]:
        # Your implementation
        pass

    # ... implement all abstract methods
```

## Advanced Usage

### Policies with Conditions

```python
from rbac_core.domain.models import Policy
from rbac_core.domain.value_objects import PolicyEffect

# Create a policy with conditions
policy = Policy.create(
    name="office-hours-only",
    description="Allow access only during office hours",
    effect=PolicyEffect.allow(),
    resources={"documents"},
    actions={"edit"},
    subjects={"user-123"},
    conditions={
        "time_range": "09:00-17:00",
        "ip_range": "192.168.1.0/24"
    }
)

# Evaluate with context
allowed = authz_service.check_permission(
    subject_id="user-123",
    permission=Permission(resource="documents", action="edit"),
    context={
        "current_time": "14:30",
        "ip_address": "192.168.1.50"
    }
)
```

### Event-Driven Architecture

```python
from rbac_core.adapters.policy_evaluators.simple_evaluator import InMemoryEventBus

# Setup event bus
event_bus = InMemoryEventBus()
role_service = RoleService(role_repo, event_bus)

# Create role (publishes RoleCreatedEvent)
role = role_service.create_role(
    name="admin",
    description="Administrator"
)

# Check published events
for event in event_bus.events:
    print(f"Event: {type(event).__name__}")
```

### Custom Repository

Implement your own repository:

```python
from rbac_core.interfaces.repository import IRoleRepository
from rbac_core.domain.models import Role

class PostgreSQLRoleRepository(IRoleRepository):
    def __init__(self, connection_string: str):
        self.conn = connect(connection_string)

    def save(self, role: Role) -> Role:
        # Your PostgreSQL implementation
        pass

    def find_by_id(self, role_id: str) -> Optional[Role]:
        # Your implementation
        pass

    # ... implement all abstract methods
```

## Use Cases

### Web APIs

```python
from fastapi import FastAPI, Depends, HTTPException
from rbac_core import AuthorizationService, Permission, PermissionDeniedError

app = FastAPI()

def get_authz_service():
    # Your DI setup
    return authz_service

@app.delete("/posts/{post_id}")
async def delete_post(
    post_id: str,
    current_user_id: str = Depends(get_current_user),
    authz: AuthorizationService = Depends(get_authz_service)
):
    try:
        authz.enforce_permission(
            subject_id=current_user_id,
            permission=Permission(resource="posts", action="delete")
        )
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Delete post logic
    return {"status": "deleted"}
```

### Multi-Tenant Applications

```python
# Create tenant-specific roles
tenant_admin = role_service.create_role(
    name=f"tenant-{tenant_id}-admin",
    description=f"Admin for tenant {tenant_id}",
    permissions={
        Permission(resource=f"tenant-{tenant_id}-*", action="*")
    }
)

# Check tenant-scoped permissions
can_access = authz_service.check_permission(
    subject_id="user-123",
    permission=Permission(
        resource=f"tenant-{tenant_id}-documents",
        action="read"
    )
)
```

### Microservices

```python
# Service A publishes role assignments
event_bus.publish(RoleAssignedEvent(
    subject_id="user-123",
    role_id="role-456",
    role_name="editor"
))

# Service B subscribes and syncs permissions
def on_role_assigned(event: RoleAssignedEvent):
    # Sync permissions to local cache
    sync_user_permissions(event.subject_id)
```

## Examples

Check the `examples/` directory for complete working examples:

- `01_basic_rbac/` - Basic role creation and authorization
- More examples coming soon!

Run examples:

```bash
cd examples/01_basic_rbac
python main.py
```

## Development

### Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev,test]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/rbac_core --cov-report=html

# Run only unit tests
pytest tests/unit -v

# Run specific test file
pytest tests/unit/domain/test_models.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking
mypy src/
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details.

## Roadmap

- [ ] SQLAlchemy repository implementations
- [ ] MongoDB repository implementations
- [ ] Redis caching adapter
- [ ] ABAC (Attribute-Based Access Control) support
- [ ] Policy DSL for complex rules
- [ ] Performance benchmarks
- [ ] GraphQL example
- [ ] Django integration example

## Related Packages

This package is part of a series of domain-driven packages:

- `users-core` - User identity management
- `auth-core` - Authentication and credentials
- `rbac-core` - Role-based access control (this package)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/yourusername/rbac-core).
