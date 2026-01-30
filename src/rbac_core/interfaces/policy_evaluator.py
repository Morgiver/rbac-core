"""Abstract interface for policy evaluation."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from rbac_core.domain.models import Policy
from rbac_core.domain.value_objects import Permission


class IPolicyEvaluator(ABC):
    """
    Interface for evaluating policies and making access control decisions.

    Policy evaluators can implement different strategies (e.g., ABAC, RBAC, etc.)
    """

    @abstractmethod
    def evaluate(
        self,
        policies: List[Policy],
        subject_id: str,
        permission: Permission,
        context: Dict[str, Any],
    ) -> bool:
        """
        Evaluate policies and determine if access should be granted.

        Args:
            policies: List of applicable policies
            subject_id: Subject requesting access
            permission: Permission being requested
            context: Additional context for evaluation (e.g., IP, time, resource attrs)

        Returns:
            True if access should be granted, False otherwise
        """
        pass


class IEventBus(ABC):
    """Interface for publishing domain events."""

    @abstractmethod
    def publish(self, event: Any) -> None:
        """
        Publish a domain event.

        Args:
            event: Event to publish
        """
        pass
