"""Regression coverage for the evidence-first analysis workflow."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import iam_graph
import iam_ingest
from escalation import has_permission
from iam_model import PolicyEffect, PolicyStatement
from policy_evaluator import PolicyEvaluator
from remediator import Remediator


class TestTrustworthyImport(unittest.TestCase):
    def test_standard_terraform_plan_and_child_modules_are_imported(self):
        policy = {
            "type": "aws_iam_policy", "name": "danger",
            "values": {"name": "Danger", "policy": {
                "Statement": [{"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]
            }},
        }
        plan = {"format_version": "1.0", "resources": [], "planned_values": {"root_module": {
            "resources": [], "child_modules": [{"resources": [policy]}]
        }}}
        data = iam_ingest.config_to_iamdata(plan)
        self.assertEqual([item.policy_name for item in data.policies], ["Danger"])
        self.assertEqual(data.coverage.input_format, "terraform_plan")
        self.assertEqual(data.coverage.total_resources, 1)

    def test_duplicate_inline_policy_names_remain_owner_scoped(self):
        raw = {"UserDetailList": [
            {"UserName": "Alice", "Arn": "arn:aws:iam::1:user/Alice", "UserPolicyList": [{
                "PolicyName": "Shared", "PolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"
                }]}
            }]},
            {"UserName": "Bob", "Arn": "arn:aws:iam::1:user/Bob", "UserPolicyList": [{
                "PolicyName": "Shared", "PolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"
                }]}
            }]},
        ]}
        graph = iam_graph.process_iam_data(iam_ingest.parse_gaad(raw, "1"))
        alice = next(node for node in graph.nodes if node.id == "user::Alice")
        bob = next(node for node in graph.nodes if node.id == "user::Bob")
        self.assertTrue(any("s3:GetObject" in item for item in alice.effective_permissions))
        self.assertFalse(any("AttachUserPolicy" in item for item in alice.effective_permissions))
        self.assertTrue(any("AttachUserPolicy" in item for item in bob.effective_permissions))
        inline_nodes = [node.id for node in graph.nodes if "policy::inline" in node.id]
        self.assertEqual(len(inline_nodes), 2)


class TestPermissionEvidence(unittest.TestCase):
    def test_narrow_deny_blocks_concrete_action_from_wildcard_allow(self):
        allow = PolicyStatement(effect=PolicyEffect.ALLOW, actions=["iam:*"], resources=["*"])
        deny = PolicyStatement(effect=PolicyEffect.DENY, actions=["iam:AttachUserPolicy"], resources=["*"])
        permissions = PolicyEvaluator().effective_permissions("arn", [("allow", allow), ("deny", deny)])
        self.assertFalse(has_permission(permissions, "iam:AttachUserPolicy"))
        self.assertTrue(has_permission(permissions, "iam:PassRole"))

    def test_user_deny_survives_group_aggregation(self):
        raw = {
            "UserDetailList": [{
                "UserName": "Alice", "Arn": "arn:aws:iam::1:user/Alice",
                "GroupList": ["Admins"],
                "UserPolicyList": [{"PolicyName": "deny", "PolicyDocument": {"Statement": [{
                    "Effect": "Deny", "Action": "iam:AttachUserPolicy", "Resource": "*"
                }]}}],
            }],
            "GroupDetailList": [{
                "GroupName": "Admins", "Arn": "arn:aws:iam::1:group/Admins",
                "GroupPolicyList": [{"PolicyName": "allow", "PolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"
                }]}}],
            }],
        }
        graph = iam_graph.process_iam_data(iam_ingest.parse_gaad(raw, "1"))
        self.assertFalse(any(path.affected_identity == "user::Alice" for path in graph.escalation_paths))

    def test_explicit_assume_role_deny_removes_trust_edge(self):
        raw = {
            "UserDetailList": [{
                "UserName": "Alice", "Arn": "arn:aws:iam::1:user/Alice",
                "UserPolicyList": [{"PolicyName": "deny", "PolicyDocument": {"Statement": [{
                    "Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"
                }]}}],
            }],
            "RoleDetailList": [{
                "RoleName": "Target", "Arn": "arn:aws:iam::1:role/Target",
                "AssumeRolePolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "arn:aws:iam::1:user/Alice"}
                }]},
                "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"
                }]}}],
            }],
        }
        graph = iam_graph.process_iam_data(iam_ingest.parse_gaad(raw, "1"))
        self.assertFalse(any(link.relationship.value == "can_assume" for link in graph.links))
        self.assertFalse(any(path.affected_identity == "user::Alice" for path in graph.escalation_paths))

    def test_graph_finding_retains_source_statement_and_uncertainty(self):
        raw = {"UserDetailList": [{
            "UserName": "Alice", "Arn": "arn:aws:iam::1:user/Alice",
            "UserPolicyList": [{"PolicyName": "conditional", "PolicyDocument": {"Statement": [{
                "Sid": "AttachOnlyFromNetwork", "Effect": "Allow",
                "Action": "iam:AttachUserPolicy", "Resource": "arn:aws:iam::1:user/Bob",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
            }]}}],
        }]}
        graph = iam_graph.process_iam_data(iam_ingest.parse_gaad(raw, "1"))
        path = next(path for path in graph.escalation_paths if path.affected_identity == "user::Alice")
        self.assertEqual(path.decision, "candidate")
        statement = path.matched_permissions[0]["source_statement"]
        self.assertEqual(statement["Resource"], "arn:aws:iam::1:user/Bob")
        self.assertIn("Condition", statement)


class TestReviewableRemediation(unittest.TestCase):
    def setUp(self):
        os.environ.pop('ANTHROPIC_API_KEY', None)
        self.remediator = Remediator()

    def test_conditions_are_preserved_without_mutating_source(self):
        statement = {
            "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*",
            "Condition": {"StringEquals": {"sts:ExternalId": "pipeline"}},
        }
        original = copy.deepcopy(statement)
        vulnerability = {
            "id": "V-1", "pattern_id": "sts:AssumeRole", "title": "Assume",
            "severity": "HIGH", "resource_name": "Alice", "attack_path": ["Alice"],
            "policy_document": {"action": "sts:AssumeRole", "statement": statement},
        }
        result = self.remediator.get_remediation(vulnerability)
        self.assertEqual(statement, original)
        proposed = result["hardened_policy"]["Statement"][0]
        self.assertEqual(proposed["Condition"], original["Condition"])
        self.assertTrue(result["validation"]["conditions_preserved"])
        self.assertIn("AWS account ID", result["required_inputs"])

    def test_cache_does_not_reuse_another_identity_summary(self):
        base = {
            "pattern_id": "iam:PassRole", "title": "Pass role", "severity": "HIGH",
            "attack_path": ["identity"],
            "policy_document": {"action": "iam:PassRole", "statement": {
                "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"
            }},
        }
        alice = self.remediator.get_remediation(dict(base, id="A", resource_name="Alice"))
        bob = self.remediator.get_remediation(dict(base, id="B", resource_name="Bob"))
        self.assertIn("Alice", alice["summary"])
        self.assertIn("Bob", bob["summary"])


if __name__ == '__main__':
    unittest.main()
