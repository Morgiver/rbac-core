"""Simple policy evaluator implementation."""

import logging
from typing import Any, Dict, List

from rbac_core.domain.models import Policy
from rbac_core.domain.value_objects import Permission
from rbac_core.interfaces.policy_evaluator import IPolicyEvaluator

logger = logging.getLogger(__name__)


class SimplePolicyEvaluator(IPolicyEvaluator):
    """
    Simple policy evaluator with basic ALLOW/DENY logic.

    Rules:
    1. Default: DENY (if no policies match)
    2. DENY policies take precedence over ALLOW
    3. Wildcards are supported in resources and actions
    """

    def evaluate(
        self,
        policies: List[Policy],
        subject_id: str,
        permission: Permission,
        context: Dict[str, Any],
    ) -> bool:
        """
        Evaluate policies for an access decision.

        Args:
            policies: List of applicable policies
            subject_id: Subject requesting access
            permission: Permission being requested
            context: Additional context

        Returns:
            True if access granted, False otherwise
        """
        if not policies:
            logger.debug("No policies found - default DENY")
            return False

        # Separate ALLOW and DENY policies
        allow_policies: List[Policy] = []
        deny_policies: List[Policy] = []

        for policy in policies:
            # Check if policy applies to this request
            if not policy.applies_to_subject(subject_id):
                continue
            if not policy.applies_to_resource(permission.resource):
                continue
            if not policy.applies_to_action(permission.action):
                continue

            # Check conditions (if any)
            if policy.conditions and not self._evaluate_conditions(policy.conditions, context):
                continue

            # Add to appropriate list
            if policy.effect.is_allow():
                allow_policies.append(policy)
            else:
                deny_policies.append(policy)

        # DENY takes precedence
        if deny_policies:
            logger.debug(
                f"Access denied by {len(deny_policies)} DENY policy/policies"
            )
            return False

        # ALLOW grants access
        if allow_policies:
            logger.debug(
                f"Access granted by {len(allow_policies)} ALLOW policy/policies"
            )
            return True

        # Default: DENY
        logger.debug("No matching policies - default DENY")
        return False

    def _evaluate_conditions(
        self, conditions: Dict[str, Any], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate policy conditions against context.

        Simple implementation: all conditions must match exactly.

        Args:
            conditions: Policy conditions
            context: Request context

        Returns:
            True if all conditions match
        """
        for key, expected_value in conditions.items():
            actual_value = context.get(key)
            if actual_value != expected_value:
                logger.debug(
                    f"Condition mismatch: {key}={actual_value} (expected: {expected_value})"
                )
                return False

        return True


class InMemoryEventBus:
    """Simple in-memory event bus for testing."""

    def __init__(self) -> None:
        self.events: List[Any] = []

    def publish(self, event: Any) -> None:
        """Publish event to memory."""
        self.events.append(event)
        logger.debug(f"Event published: {type(event).__name__}")

    def clear(self) -> None:
        """Clear all events."""
        self.events.clear()
