"""Evaluate IAM policy statements into effective (Allow) permissions.

Ported verbatim from adnannazirahmed/IAM-Visualizer (backend/src/policy_evaluator.py),
imports adjusted. Visualization-grade: expands every (action x resource) Allow pair
and drops those matched by a Deny. Not a request-context simulation.
"""

import fnmatch
from typing import List, Tuple, Any

from iam_model import PolicyStatement, PolicyEffect, EffectivePermission


class PolicyEvaluator:
    def effective_permissions(
        self,
        identity_arn: str,
        statements: List[Tuple[str, PolicyStatement]],
        all_policies: List[Any] = None,
    ) -> List[EffectivePermission]:
        allows = [(s, st) for s, st in statements if st.effect == PolicyEffect.ALLOW]
        denies = [(s, st) for s, st in statements if st.effect == PolicyEffect.DENY]

        effective_perms: List[EffectivePermission] = []
        for source, allow_stmt in allows:
            for action in allow_stmt.actions:
                for resource in allow_stmt.resources:
                    if any(self._matches_deny(action, resource, d) for _, d in denies):
                        continue
                    effective_perms.append(EffectivePermission(
                        action=action,
                        resource=resource,
                        effect=PolicyEffect.ALLOW,
                        source_policy=source,
                        conditions=allow_stmt.conditions,
                    ))
        return effective_perms

    def _matches_deny(self, action: str, resource: str, deny_stmt: PolicyStatement) -> bool:
        if deny_stmt.actions:
            action_match = any(self._match_pattern(action, p) for p in deny_stmt.actions)
        elif deny_stmt.not_actions:
            action_match = not any(self._match_pattern(action, p) for p in deny_stmt.not_actions)
        else:
            action_match = False
        if not action_match:
            return False

        if deny_stmt.resources:
            return any(self._match_pattern(resource, p) for p in deny_stmt.resources)
        if deny_stmt.not_resources:
            return not any(self._match_pattern(resource, p) for p in deny_stmt.not_resources)
        return False

    def _match_pattern(self, string: str, pattern: str) -> bool:
        # IAM is case-sensitive; fnmatchcase preserves case.
        return fnmatch.fnmatchcase(string, pattern)
