"""Evaluate IAM statements without pretending missing request context is known.

The evaluator preserves wildcard Allows plus narrower Denies so downstream checks
can decide a concrete action correctly. Conditions are retained and marked as
conditional; callers present those decisions as candidates unless request context
is available to resolve them.
"""

import fnmatch
from typing import Any, List, Tuple

from iam_model import PolicyStatement, PolicyEffect, EffectivePermission


def statement_to_dict(statement: PolicyStatement) -> dict:
    """Return an AWS-shaped copy suitable for evidence and policy review."""
    out = {"Effect": statement.effect.value}
    if statement.sid:
        out["Sid"] = statement.sid
    if statement.actions:
        out["Action"] = statement.actions[0] if len(statement.actions) == 1 else list(statement.actions)
    if statement.not_actions:
        out["NotAction"] = statement.not_actions[0] if len(statement.not_actions) == 1 else list(statement.not_actions)
    if statement.resources:
        out["Resource"] = statement.resources[0] if len(statement.resources) == 1 else list(statement.resources)
    if statement.not_resources:
        out["NotResource"] = statement.not_resources[0] if len(statement.not_resources) == 1 else list(statement.not_resources)
    if statement.principals:
        out["Principal"] = list(statement.principals)
    if statement.conditions:
        conditions = {}
        for condition in statement.conditions:
            values = condition.values[0] if len(condition.values) == 1 else list(condition.values)
            conditions.setdefault(condition.operator, {})[condition.key] = values
        out["Condition"] = conditions
    return out


class PolicyEvaluator:
    def effective_permissions(
        self,
        identity_arn: str,
        statements: List[Tuple[str, PolicyStatement]],
        all_policies: List[Any] = None,
    ) -> List[EffectivePermission]:
        allows = [(source, stmt) for source, stmt in statements if stmt.effect == PolicyEffect.ALLOW]
        denies = [(source, stmt) for source, stmt in statements if stmt.effect == PolicyEffect.DENY]
        effective: List[EffectivePermission] = []

        for source, allow_stmt in allows:
            actions = allow_stmt.actions or (["*"] if allow_stmt.not_actions else [])
            resources = allow_stmt.resources or (["*"] if allow_stmt.not_resources else [])
            for action in actions:
                for resource in resources:
                    if any(
                        not deny_stmt.conditions and self._deny_covers_allow(action, resource, deny_stmt)
                        for _, deny_stmt in denies
                    ):
                        continue
                    effective.append(EffectivePermission(
                        action=action,
                        resource=resource,
                        effect=PolicyEffect.ALLOW,
                        source_policy=source,
                        conditions=list(allow_stmt.conditions),
                        source_statement=statement_to_dict(allow_stmt),
                        excluded_actions=list(allow_stmt.not_actions),
                        excluded_resources=list(allow_stmt.not_resources),
                        conditional=bool(allow_stmt.conditions),
                    ))

                    # Narrow Denies cannot be subtracted from a broad wildcard as a
                    # string. Preserve them so concrete escalation checks honor them.
                    for deny_source, deny_stmt in denies:
                        if not self._could_overlap(action, resource, deny_stmt):
                            continue
                        for denied_action in deny_stmt.actions or (["*"] if deny_stmt.not_actions else []):
                            for denied_resource in deny_stmt.resources or (["*"] if deny_stmt.not_resources else []):
                                candidate = EffectivePermission(
                                    action=denied_action,
                                    resource=denied_resource,
                                    effect=PolicyEffect.DENY,
                                    source_policy=deny_source,
                                    conditions=list(deny_stmt.conditions),
                                    source_statement=statement_to_dict(deny_stmt),
                                    excluded_actions=list(deny_stmt.not_actions),
                                    excluded_resources=list(deny_stmt.not_resources),
                                    conditional=bool(deny_stmt.conditions),
                                )
                                if candidate not in effective:
                                    effective.append(candidate)
        return effective

    def _deny_covers_allow(self, action: str, resource: str, deny_stmt: PolicyStatement) -> bool:
        if deny_stmt.not_actions or deny_stmt.not_resources:
            return False
        return (
            any(self._pattern_covers(pattern, action, action=True) for pattern in deny_stmt.actions)
            and any(self._pattern_covers(pattern, resource, action=False) for pattern in deny_stmt.resources)
        )

    def _could_overlap(self, action: str, resource: str, deny_stmt: PolicyStatement) -> bool:
        deny_actions = deny_stmt.actions or ["*"]
        deny_resources = deny_stmt.resources or ["*"]
        action_overlap = any(
            self._pattern_covers(pattern, action, action=True)
            or self._pattern_covers(action, pattern, action=True)
            for pattern in deny_actions
        )
        resource_overlap = any(
            self._pattern_covers(pattern, resource, action=False)
            or self._pattern_covers(resource, pattern, action=False)
            for pattern in deny_resources
        )
        return action_overlap and resource_overlap

    @staticmethod
    def _pattern_covers(pattern: str, candidate: str, action: bool) -> bool:
        left = pattern.lower() if action else pattern
        right = candidate.lower() if action else candidate
        if left == "*" or left == right:
            return True
        if left.endswith("*") and not any(ch in left[:-1] for ch in "*?"):
            return right.startswith(left[:-1])
        return False

    @staticmethod
    def matches_action(pattern: str, action: str) -> bool:
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())

    @staticmethod
    def matches_resource(pattern: str, resource: str) -> bool:
        return fnmatch.fnmatchcase(resource, pattern)
