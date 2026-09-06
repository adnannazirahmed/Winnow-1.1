"""Tests for the ported IAM permission-graph + escalation engine.

Converted from adnannazirahmed/IAM-Visualizer's pytest suite
(tests/test_iam_parser.py, test_graph_builder.py, test_policy_evaluator.py,
test_escalation.py) to unittest, imports pointed at Winnow's flat modules.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import iam_ingest
import iam_graph
from policy_evaluator import PolicyEvaluator
from escalation import detect_escalation_paths
from iam_model import (
    GraphOutput, GraphNode, GraphLink, NodeType, RelationshipType, RiskLevel,
    PolicyStatement, PolicyEffect, EffectivePermission,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


class TestGaadParser(unittest.TestCase):
    def test_parse_simple_org(self):
        d = iam_ingest.parse_gaad(load_fixture("simple_org.json"), "123")
        self.assertEqual(len(d.users), 2)
        self.assertEqual(len(d.groups), 1)
        self.assertEqual(len(d.roles), 1)
        self.assertEqual(len(d.policies), 1)
        alice = next(u for u in d.users if u.user_name == "Alice")
        self.assertIn("Developers", alice.group_list)

    def test_parse_wildcard_inline(self):
        d = iam_ingest.parse_gaad(load_fixture("wildcard_policies.json"), "123")
        admin = next(u for u in d.users if u.user_name == "AdminUser")
        stmt = admin.inline_policies[0].document.statements[0]
        self.assertEqual(stmt.effect, PolicyEffect.ALLOW)
        self.assertIn("*", stmt.actions)
        self.assertIn("*", stmt.resources)

    def test_url_encoded_document(self):
        # GAAD often returns policy docs URL-encoded.
        raw = {"Policies": [{
            "PolicyName": "P", "Arn": "arn:aws:iam::123:policy/P",
            "PolicyVersionList": [{"IsDefaultVersion": True,
                                   "Document": "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3APassRole%22%2C%22Resource%22%3A%22*%22%7D%5D%7D"}],
        }]}
        d = iam_ingest.parse_gaad(raw, "123")
        self.assertEqual(d.policies[0].document.statements[0].actions, ["iam:PassRole"])


class TestGraphBuilder(unittest.TestCase):
    def test_simple_graph(self):
        d = iam_ingest.parse_gaad(load_fixture("simple_org.json"), "123")
        g = iam_graph.process_iam_data(d)
        ids = {n.id for n in g.nodes}
        self.assertIn("user::Alice", ids)
        self.assertIn("group::Developers", ids)
        link = next((l for l in g.links
                     if l.source == "user::Alice" and l.target == "group::Developers"), None)
        self.assertIsNotNone(link)
        self.assertEqual(link.relationship, RelationshipType.MEMBER_OF)
        self.assertEqual(g.metadata.escalation_count, 0)

    def test_cycle_detection(self):
        d = iam_ingest.parse_gaad(load_fixture("circular_roles.json"), "123")
        g = iam_graph.process_iam_data(d)
        nodes = {n.id: n for n in g.nodes}
        self.assertEqual(nodes["role::RoleA"].risk_level, RiskLevel.MEDIUM)
        self.assertEqual(nodes["role::RoleB"].risk_level, RiskLevel.MEDIUM)
        self.assertEqual(sum(1 for l in g.links if l.relationship == RelationshipType.CAN_ASSUME), 2)


class TestPolicyEvaluator(unittest.TestCase):
    def setUp(self):
        self.ev = PolicyEvaluator()

    def test_wildcard_matching(self):
        stmt = PolicyStatement(effect=PolicyEffect.ALLOW, actions=["s3:*", "iam:PassRole"], resources=["*"])
        perms = self.ev.effective_permissions("arn", [("A", stmt)])
        self.assertEqual({p.action for p in perms}, {"s3:*", "iam:PassRole"})

    def test_explicit_deny_overrides(self):
        allow = PolicyStatement(effect=PolicyEffect.ALLOW, actions=["s3:GetObject"], resources=["*"])
        deny = PolicyStatement(effect=PolicyEffect.DENY, actions=["s3:*"], resources=["*"])
        perms = self.ev.effective_permissions("arn", [("A", allow), ("D", deny)])
        self.assertEqual(perms, [])


class TestEscalation(unittest.TestCase):
    @staticmethod
    def _graph():
        g = GraphOutput()
        g.nodes = [
            GraphNode(id="user::benign", type=NodeType.USER, name="benign"),
            GraphNode(id="user::attacker", type=NodeType.USER, name="attacker"),
            GraphNode(id="role::attacker2", type=NodeType.ROLE, name="attacker2"),
            GraphNode(id="user::cyc", type=NodeType.USER, name="cyc"),
            GraphNode(id="group::cyc", type=NodeType.GROUP, name="cyc"),
        ]
        g.links = [
            GraphLink(source="user::cyc", target="group::cyc", relationship=RelationshipType.MEMBER_OF),
            GraphLink(source="group::cyc", target="user::cyc", relationship=RelationshipType.CAN_ASSUME),
        ]
        return g

    @staticmethod
    def _allow(a):
        return EffectivePermission(action=a, resource="*", effect=PolicyEffect.ALLOW)

    @staticmethod
    def _deny(a):
        return EffectivePermission(action=a, resource="*", effect=PolicyEffect.DENY)

    def test_benign(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {"user::benign": [self._allow("s3:GetObject")]})
        self.assertFalse(any(p.affected_identity == "user::benign" for p in paths))
        self.assertEqual(next(n for n in g.nodes if n.id == "user::benign").risk_level, RiskLevel.NONE)

    def test_critical_escalation(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {"user::attacker": [self._allow("iam:CreatePolicyVersion")]})
        node = next(n for n in g.nodes if n.id == "user::attacker")
        self.assertEqual(node.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(node.risk_score, 1.0)
        p = next(p for p in paths if p.affected_identity == "user::attacker")
        self.assertEqual(p.technique, "CreateNewPolicyVersion")

    def test_multi_action_rule(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {"role::attacker2": [self._allow("iam:PassRole"), self._allow("ec2:RunInstances")]})
        self.assertTrue(any(p.technique == "CreateEC2WithExistingIP" for p in paths))

    def test_wildcard_matches_many_rules(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {"user::attacker": [self._allow("iam:*")]})
        self.assertGreaterEqual(len(paths), 10)

    def test_deny_overrides(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {"user::attacker": [
            self._allow("iam:CreatePolicyVersion"), self._deny("iam:CreatePolicyVersion")]})
        self.assertEqual(len(paths), 0)

    def test_cycle_terminates(self):
        g = self._graph()
        paths = detect_escalation_paths(g, {
            "user::cyc": [self._allow("iam:PassRole"), self._allow("ssm:StartSession")],
            "group::cyc": [],
        })
        self.assertTrue(any(p.affected_identity == "user::cyc" for p in paths))

    def test_ids_deterministic(self):
        d = iam_ingest.parse_gaad(load_fixture("escalation_scenarios.json"), "123")
        a = [e.id for e in iam_graph.process_iam_data(d).escalation_paths]
        d2 = iam_ingest.parse_gaad(load_fixture("escalation_scenarios.json"), "123")
        b = [e.id for e in iam_graph.process_iam_data(d2).escalation_paths]
        self.assertEqual(a, b)
        self.assertTrue(all("::" in i for i in a))


class TestFalsePositiveFilters(unittest.TestCase):
    def test_service_only_role_not_a_start_point(self):
        raw = {"RoleDetailList": [{
            "RoleName": "SvcRole", "Arn": "arn:aws:iam::123:role/SvcRole",
            "AssumeRolePolicyDocument": {"Statement": [{
                "Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"Service": "ec2.amazonaws.com"}}]},
            "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}]}}],
        }]}
        d = iam_ingest.parse_gaad(raw, "123")
        g = iam_graph.process_iam_data(d)
        self.assertFalse(next(n for n in g.nodes if n.id == "role::SvcRole").reachable)
        self.assertEqual(g.metadata.escalation_count, 0)

    def test_service_linked_role_arn_scope_ignored(self):
        g = GraphOutput()
        g.nodes = [GraphNode(id="user::u", type=NodeType.USER, name="u")]
        perm = EffectivePermission(
            action="iam:AttachRolePolicy",
            resource="arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX",
            effect=PolicyEffect.ALLOW)
        paths = detect_escalation_paths(g, {"user::u": [perm]})
        self.assertEqual(paths, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
