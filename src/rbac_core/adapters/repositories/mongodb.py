"""MongoDB repository implementations for RBAC."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pymongo.collection import Collection
from pymongo.database import Database

from rbac_core.domain.exceptions import RoleAlreadyExistsError
from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName
from rbac_core.interfaces.repository import (
    IPolicyRepository,
    IRoleAssignmentRepository,
    IRoleRepository,
)


class MongoDBRoleRepository(IRoleRepository):
    """MongoDB implementation of role repository."""

    def __init__(self, database: Database) -> None:
        """
        Initialize repository.

        Args:
            database: MongoDB database instance
        """
        self.collection: Collection = database["roles"]
        # Create indexes
        self.collection.create_index("name", unique=True)
        self.collection.create_index("created_at")

    def _to_document(self, role: Role) -> Dict[str, Any]:
        """Convert Role to MongoDB document."""
        return {
            "_id": role.id,
            "name": str(role.name),
            "description": role.description,
            "permissions": [p.to_string() for p in role.permissions],
            "created_at": role.created_at,
            "updated_at": role.updated_at,
            "metadata": role.metadata,
        }

    def _from_document(self, doc: Dict[str, Any]) -> Role:
        """Convert MongoDB document to Role."""
        return Role(
            id=doc["_id"],
            name=doc["name"],  # Keep as string, domain model handles it
            description=doc["description"],
            permissions={Permission.from_string(p) for p in doc.get("permissions", [])},
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            metadata=doc.get("metadata", {}),
        )

    def save(self, role: Role) -> Role:
        """Save a role."""
        # Check for duplicate name (excluding same ID)
        existing = self.collection.find_one(
            {"name": str(role.name), "_id": {"$ne": role.id}}
        )
        if existing:
            raise RoleAlreadyExistsError(str(role.name))

        doc = self._to_document(role)
        self.collection.replace_one({"_id": role.id}, doc, upsert=True)
        return role

    def find_by_id(self, role_id: str) -> Optional[Role]:
        """Find role by ID."""
        doc = self.collection.find_one({"_id": role_id})
        return self._from_document(doc) if doc else None

    def find_by_name(self, name: str) -> Optional[Role]:
        """Find role by name (case-insensitive)."""
        doc = self.collection.find_one({"name": name.lower()})
        return self._from_document(doc) if doc else None

    def find_all(self) -> List[Role]:
        """Retrieve all roles."""
        docs = self.collection.find()
        return [self._from_document(doc) for doc in docs]

    def delete(self, role_id: str) -> bool:
        """Delete a role."""
        result = self.collection.delete_one({"_id": role_id})
        return result.deleted_count > 0

    def exists_by_name(self, name: str) -> bool:
        """Check if role exists by name."""
        return self.collection.find_one({"name": name.lower()}) is not None

    def count(self) -> int:
        """Count total number of roles."""
        return self.collection.count_documents({})


class MongoDBPolicyRepository(IPolicyRepository):
    """MongoDB implementation of policy repository."""

    def __init__(self, database: Database) -> None:
        """
        Initialize repository.

        Args:
            database: MongoDB database instance
        """
        self.collection: Collection = database["policies"]
        # Create indexes
        self.collection.create_index("name")
        self.collection.create_index("subjects")
        self.collection.create_index("created_at")

    def _to_document(self, policy: Policy) -> Dict[str, Any]:
        """Convert Policy to MongoDB document."""
        return {
            "_id": policy.id,
            "name": policy.name,
            "description": policy.description,
            "effect": str(policy.effect),
            "resources": list(policy.resources),
            "actions": list(policy.actions),
            "subjects": list(policy.subjects),
            "conditions": policy.conditions,
            "created_at": policy.created_at,
            "updated_at": policy.updated_at,
            "metadata": policy.metadata,
        }

    def _from_document(self, doc: Dict[str, Any]) -> Policy:
        """Convert MongoDB document to Policy."""
        return Policy(
            id=doc["_id"],
            name=doc["name"],
            description=doc["description"],
            effect=PolicyEffect(doc["effect"]),
            resources=set(doc.get("resources", [])),
            actions=set(doc.get("actions", [])),
            subjects=set(doc.get("subjects", [])),
            conditions=doc.get("conditions", {}),
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            metadata=doc.get("metadata", {}),
        )

    def save(self, policy: Policy) -> Policy:
        """Save a policy."""
        doc = self._to_document(policy)
        self.collection.replace_one({"_id": policy.id}, doc, upsert=True)
        return policy

    def find_by_id(self, policy_id: str) -> Optional[Policy]:
        """Find policy by ID."""
        doc = self.collection.find_one({"_id": policy_id})
        return self._from_document(doc) if doc else None

    def find_by_subject(self, subject_id: str) -> List[Policy]:
        """Find all policies applicable to a subject."""
        # Find policies where subjects is empty (applies to all) or contains subject_id or wildcard
        docs = self.collection.find(
            {
                "$or": [
                    {"subjects": {"$size": 0}},  # Empty subjects = applies to all
                    {"subjects": subject_id},  # Specific subject
                    {"subjects": "*"},  # Wildcard
                ]
            }
        )
        return [self._from_document(doc) for doc in docs]

    def find_all(self) -> List[Policy]:
        """Retrieve all policies."""
        docs = self.collection.find()
        return [self._from_document(doc) for doc in docs]

    def delete(self, policy_id: str) -> bool:
        """Delete a policy."""
        result = self.collection.delete_one({"_id": policy_id})
        return result.deleted_count > 0


class MongoDBRoleAssignmentRepository(IRoleAssignmentRepository):
    """MongoDB implementation of role assignment repository."""

    def __init__(self, database: Database) -> None:
        """
        Initialize repository.

        Args:
            database: MongoDB database instance
        """
        self.collection: Collection = database["role_assignments"]
        # Create indexes
        self.collection.create_index("subject_id")
        self.collection.create_index("role_id")
        self.collection.create_index([("subject_id", 1), ("role_id", 1)])
        self.collection.create_index("assigned_at")
        self.collection.create_index("expires_at")

    def _to_document(self, assignment: RoleAssignment) -> Dict[str, Any]:
        """Convert RoleAssignment to MongoDB document."""
        return {
            "_id": assignment.id,
            "subject_id": assignment.subject_id,
            "role_id": assignment.role_id,
            "assigned_at": assignment.assigned_at,
            "assigned_by": assignment.assigned_by,
            "expires_at": assignment.expires_at,
            "metadata": assignment.metadata,
        }

    def _from_document(self, doc: Dict[str, Any]) -> RoleAssignment:
        """Convert MongoDB document to RoleAssignment."""
        return RoleAssignment(
            id=doc["_id"],
            subject_id=doc["subject_id"],
            role_id=doc["role_id"],
            assigned_at=doc["assigned_at"],
            assigned_by=doc.get("assigned_by"),
            expires_at=doc.get("expires_at"),
            metadata=doc.get("metadata", {}),
        )

    def save(self, assignment: RoleAssignment) -> RoleAssignment:
        """Save a role assignment."""
        doc = self._to_document(assignment)
        self.collection.replace_one({"_id": assignment.id}, doc, upsert=True)
        return assignment

    def find_by_id(self, assignment_id: str) -> Optional[RoleAssignment]:
        """Find assignment by ID."""
        doc = self.collection.find_one({"_id": assignment_id})
        return self._from_document(doc) if doc else None

    def find_by_subject(self, subject_id: str) -> List[RoleAssignment]:
        """Find all role assignments for a subject."""
        docs = self.collection.find({"subject_id": subject_id})
        return [self._from_document(doc) for doc in docs]

    def find_by_role(self, role_id: str) -> List[RoleAssignment]:
        """Find all assignments for a role."""
        docs = self.collection.find({"role_id": role_id})
        return [self._from_document(doc) for doc in docs]

    def find_by_subject_and_role(
        self, subject_id: str, role_id: str
    ) -> Optional[RoleAssignment]:
        """Find assignment for a specific subject-role pair."""
        doc = self.collection.find_one({"subject_id": subject_id, "role_id": role_id})
        return self._from_document(doc) if doc else None

    def delete(self, assignment_id: str) -> bool:
        """Delete a role assignment."""
        result = self.collection.delete_one({"_id": assignment_id})
        return result.deleted_count > 0

    def delete_by_subject_and_role(self, subject_id: str, role_id: str) -> bool:
        """Delete assignment by subject-role pair."""
        result = self.collection.delete_one({"subject_id": subject_id, "role_id": role_id})
        return result.deleted_count > 0
