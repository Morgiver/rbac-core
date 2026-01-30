"""SQLAlchemy repository implementations for RBAC."""

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, String, Table, Text
from sqlalchemy.orm import Session, declarative_base, relationship

from rbac_core.domain.exceptions import RoleAlreadyExistsError
from rbac_core.domain.models import Policy, Role, RoleAssignment
from rbac_core.domain.value_objects import Permission, PolicyEffect, RoleName
from rbac_core.interfaces.repository import (
    IPolicyRepository,
    IRoleAssignmentRepository,
    IRoleRepository,
)

Base = declarative_base()


# Association table for Role-Permission many-to-many relationship
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", String(36), ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", String(36), ForeignKey("permissions.id"), primary_key=True),
)


class RoleModel(Base):
    """SQLAlchemy model for Role."""

    __tablename__ = "roles"

    id = Column(String(36), primary_key=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_json = Column("metadata", JSON, nullable=False, default=dict)

    # Relationship
    permissions = relationship(
        "PermissionModel",
        secondary=role_permissions,
        back_populates="roles",
        cascade="all, delete",
    )

    def to_domain(self) -> Role:
        """Convert to domain Role."""
        return Role(
            id=self.id,
            name=self.name,
            description=self.description,
            permissions={Permission.from_string(p.permission) for p in self.permissions},
            created_at=self.created_at,
            updated_at=self.updated_at,
            metadata=self.metadata_json or {},
        )

    @staticmethod
    def from_domain(role: Role) -> "RoleModel":
        """Create from domain Role."""
        return RoleModel(
            id=role.id,
            name=str(role.name),
            description=role.description,
            created_at=role.created_at,
            updated_at=role.updated_at,
            metadata_json=role.metadata,
        )


class PermissionModel(Base):
    """SQLAlchemy model for Permission (for many-to-many)."""

    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True)
    permission = Column(String(255), unique=True, nullable=False, index=True)

    # Relationship
    roles = relationship("RoleModel", secondary=role_permissions, back_populates="permissions")


class PolicyModel(Base):
    """SQLAlchemy model for Policy."""

    __tablename__ = "policies"

    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    effect = Column(String(10), nullable=False)
    resources = Column(JSON, nullable=False, default=list)
    actions = Column(JSON, nullable=False, default=list)
    subjects = Column(JSON, nullable=False, default=list)
    conditions = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_json = Column("metadata", JSON, nullable=False, default=dict)

    def to_domain(self) -> Policy:
        """Convert to domain Policy."""
        return Policy(
            id=self.id,
            name=self.name,
            description=self.description,
            effect=PolicyEffect(self.effect),
            resources=set(self.resources or []),
            actions=set(self.actions or []),
            subjects=set(self.subjects or []),
            conditions=self.conditions or {},
            created_at=self.created_at,
            updated_at=self.updated_at,
            metadata=self.metadata_json or {},
        )

    @staticmethod
    def from_domain(policy: Policy) -> "PolicyModel":
        """Create from domain Policy."""
        return PolicyModel(
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
            metadata_json=policy.metadata,
        )


class RoleAssignmentModel(Base):
    """SQLAlchemy model for RoleAssignment."""

    __tablename__ = "role_assignments"

    id = Column(String(36), primary_key=True)
    subject_id = Column(String(255), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False, index=True)
    assigned_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    assigned_by = Column(String(255), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    metadata_json = Column("metadata", JSON, nullable=False, default=dict)

    def to_domain(self) -> RoleAssignment:
        """Convert to domain RoleAssignment."""
        return RoleAssignment(
            id=self.id,
            subject_id=self.subject_id,
            role_id=self.role_id,
            assigned_at=self.assigned_at,
            assigned_by=self.assigned_by,
            expires_at=self.expires_at,
            metadata=self.metadata_json or {},
        )

    @staticmethod
    def from_domain(assignment: RoleAssignment) -> "RoleAssignmentModel":
        """Create from domain RoleAssignment."""
        return RoleAssignmentModel(
            id=assignment.id,
            subject_id=assignment.subject_id,
            role_id=assignment.role_id,
            assigned_at=assignment.assigned_at,
            assigned_by=assignment.assigned_by,
            expires_at=assignment.expires_at,
            metadata_json=assignment.metadata,
        )


class SQLAlchemyRoleRepository(IRoleRepository):
    """SQLAlchemy implementation of role repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, role: Role) -> Role:
        """Save a role."""
        # Check for duplicate name
        existing = (
            self.session.query(RoleModel)
            .filter(RoleModel.name == str(role.name), RoleModel.id != role.id)
            .first()
        )
        if existing:
            raise RoleAlreadyExistsError(str(role.name))

        # Find or create role model
        role_model = self.session.query(RoleModel).filter(RoleModel.id == role.id).first()

        if role_model:
            # Update existing
            role_model.name = str(role.name)
            role_model.description = role.description
            role_model.updated_at = role.updated_at
            role_model.metadata_json = role.metadata

            # Update permissions
            role_model.permissions = []
        else:
            # Create new
            role_model = RoleModel.from_domain(role)
            self.session.add(role_model)

        # Add permissions
        for perm in role.permissions:
            perm_str = perm.to_string()
            perm_model = (
                self.session.query(PermissionModel)
                .filter(PermissionModel.permission == perm_str)
                .first()
            )

            if not perm_model:
                import uuid

                perm_model = PermissionModel(id=str(uuid.uuid4()), permission=perm_str)
                self.session.add(perm_model)

            role_model.permissions.append(perm_model)

        self.session.commit()
        self.session.refresh(role_model)

        return role_model.to_domain()

    def find_by_id(self, role_id: str) -> Optional[Role]:
        """Find role by ID."""
        role_model = self.session.query(RoleModel).filter(RoleModel.id == role_id).first()
        return role_model.to_domain() if role_model else None

    def find_by_name(self, name: str) -> Optional[Role]:
        """Find role by name (case-insensitive)."""
        role_model = (
            self.session.query(RoleModel).filter(RoleModel.name == name.lower()).first()
        )
        return role_model.to_domain() if role_model else None

    def find_all(self) -> List[Role]:
        """Retrieve all roles."""
        role_models = self.session.query(RoleModel).all()
        return [role_model.to_domain() for role_model in role_models]

    def delete(self, role_id: str) -> bool:
        """Delete a role."""
        role_model = self.session.query(RoleModel).filter(RoleModel.id == role_id).first()
        if role_model:
            self.session.delete(role_model)
            self.session.commit()
            return True
        return False

    def exists_by_name(self, name: str) -> bool:
        """Check if role exists by name."""
        return (
            self.session.query(RoleModel).filter(RoleModel.name == name.lower()).first()
            is not None
        )

    def count(self) -> int:
        """Count total number of roles."""
        return self.session.query(RoleModel).count()


class SQLAlchemyPolicyRepository(IPolicyRepository):
    """SQLAlchemy implementation of policy repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, policy: Policy) -> Policy:
        """Save a policy."""
        policy_model = (
            self.session.query(PolicyModel).filter(PolicyModel.id == policy.id).first()
        )

        if policy_model:
            # Update existing
            policy_model.name = policy.name
            policy_model.description = policy.description
            policy_model.effect = str(policy.effect)
            policy_model.resources = list(policy.resources)
            policy_model.actions = list(policy.actions)
            policy_model.subjects = list(policy.subjects)
            policy_model.conditions = policy.conditions
            policy_model.updated_at = policy.updated_at
            policy_model.metadata_json = policy.metadata
        else:
            # Create new
            policy_model = PolicyModel.from_domain(policy)
            self.session.add(policy_model)

        self.session.commit()
        self.session.refresh(policy_model)

        return policy_model.to_domain()

    def find_by_id(self, policy_id: str) -> Optional[Policy]:
        """Find policy by ID."""
        policy_model = (
            self.session.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        )
        return policy_model.to_domain() if policy_model else None

    def find_by_subject(self, subject_id: str) -> List[Policy]:
        """Find all policies applicable to a subject."""
        # Note: This is a simple implementation. In production, you might want
        # to use database-specific JSON query capabilities for better performance
        policy_models = self.session.query(PolicyModel).all()
        policies = [pm.to_domain() for pm in policy_models]
        return [p for p in policies if p.applies_to_subject(subject_id)]

    def find_all(self) -> List[Policy]:
        """Retrieve all policies."""
        policy_models = self.session.query(PolicyModel).all()
        return [policy_model.to_domain() for policy_model in policy_models]

    def delete(self, policy_id: str) -> bool:
        """Delete a policy."""
        policy_model = (
            self.session.query(PolicyModel).filter(PolicyModel.id == policy_id).first()
        )
        if policy_model:
            self.session.delete(policy_model)
            self.session.commit()
            return True
        return False


class SQLAlchemyRoleAssignmentRepository(IRoleAssignmentRepository):
    """SQLAlchemy implementation of role assignment repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, assignment: RoleAssignment) -> RoleAssignment:
        """Save a role assignment."""
        assignment_model = (
            self.session.query(RoleAssignmentModel)
            .filter(RoleAssignmentModel.id == assignment.id)
            .first()
        )

        if assignment_model:
            # Update existing
            assignment_model.subject_id = assignment.subject_id
            assignment_model.role_id = assignment.role_id
            assignment_model.assigned_at = assignment.assigned_at
            assignment_model.assigned_by = assignment.assigned_by
            assignment_model.expires_at = assignment.expires_at
            assignment_model.metadata_json = assignment.metadata
        else:
            # Create new
            assignment_model = RoleAssignmentModel.from_domain(assignment)
            self.session.add(assignment_model)

        self.session.commit()
        self.session.refresh(assignment_model)

        return assignment_model.to_domain()

    def find_by_id(self, assignment_id: str) -> Optional[RoleAssignment]:
        """Find assignment by ID."""
        assignment_model = (
            self.session.query(RoleAssignmentModel)
            .filter(RoleAssignmentModel.id == assignment_id)
            .first()
        )
        return assignment_model.to_domain() if assignment_model else None

    def find_by_subject(self, subject_id: str) -> List[RoleAssignment]:
        """Find all role assignments for a subject."""
        assignment_models = (
            self.session.query(RoleAssignmentModel)
            .filter(RoleAssignmentModel.subject_id == subject_id)
            .all()
        )
        return [am.to_domain() for am in assignment_models]

    def find_by_role(self, role_id: str) -> List[RoleAssignment]:
        """Find all assignments for a role."""
        assignment_models = (
            self.session.query(RoleAssignmentModel)
            .filter(RoleAssignmentModel.role_id == role_id)
            .all()
        )
        return [am.to_domain() for am in assignment_models]

    def find_by_subject_and_role(
        self, subject_id: str, role_id: str
    ) -> Optional[RoleAssignment]:
        """Find assignment for a specific subject-role pair."""
        assignment_model = (
            self.session.query(RoleAssignmentModel)
            .filter(
                RoleAssignmentModel.subject_id == subject_id,
                RoleAssignmentModel.role_id == role_id,
            )
            .first()
        )
        return assignment_model.to_domain() if assignment_model else None

    def delete(self, assignment_id: str) -> bool:
        """Delete a role assignment."""
        assignment_model = (
            self.session.query(RoleAssignmentModel)
            .filter(RoleAssignmentModel.id == assignment_id)
            .first()
        )
        if assignment_model:
            self.session.delete(assignment_model)
            self.session.commit()
            return True
        return False

    def delete_by_subject_and_role(self, subject_id: str, role_id: str) -> bool:
        """Delete assignment by subject-role pair."""
        assignment_model = (
            self.session.query(RoleAssignmentModel)
            .filter(
                RoleAssignmentModel.subject_id == subject_id,
                RoleAssignmentModel.role_id == role_id,
            )
            .first()
        )
        if assignment_model:
            self.session.delete(assignment_model)
            self.session.commit()
            return True
        return False
