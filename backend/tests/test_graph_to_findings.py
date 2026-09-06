"""The graph-engine -> Winnow-Vulnerability bridge, and its contract with the
remediator (every escalation technique must map to a remediation strategy)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import iam_ingest
import iam_graph
from graph_to_findings import graph_to_findings, TECHNIQUE_MAP
from escalation import RULES
from remediator import PATTERN_STRATEGY

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


class TestTechniqueContract(unittest.TestCase):
    def test_every_rule_has_a_technique_map_entry(self):
        for rule in RULES:
            self.assertIn(rule.name, TECHNIQUE_MAP, f"no TECHNIQUE_MAP entry for {rule.name}")

    def test_every_technique_pattern_id_has_a_strategy(self):
        for name, meta in TECHNIQUE_MAP.items():
            self.assertIn(meta["pattern_id"], PATTERN_STRATEGY,
                          f"{name} -> pattern_id {meta['pattern_id']} has no remediation strategy")

    def test_every_technique_has_mitre(self):
        for name, meta in TECHNIQUE_MAP.items():
            self.assertTrue(meta["mitre"], f"{name} has no MITRE technique")


class TestBridge(unittest.TestCase):
    def _findings(self, fixture):
        d = iam_ingest.parse_gaad(load_fixture(fixture), "123")
        return graph_to_findings(iam_graph.process_iam_data(d))

    def test_escalation_scenarios(self):
        findings = self._findings("escalation_scenarios.json")
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(f["detection_source"], "graph")
            self.assertTrue(f["pattern_id"])
            self.assertIn(f["severity"], {"CRITICAL", "HIGH", "MEDIUM", "LOW"})
            self.assertEqual(f["resource_name"], "BadActor1")
            self.assertIsInstance(f["attack_path"], list)
            self.assertTrue(f["mitre_techniques"])
        patterns = {f["pattern_id"] for f in findings}
        self.assertIn("iam:AttachUserPolicy", patterns)
        self.assertIn("iam:CreatePolicyVersion", patterns)

    def test_benign_org_yields_nothing(self):
        self.assertEqual(self._findings("simple_org.json"), [])

    def test_deny_fixture_yields_nothing(self):
        self.assertEqual(self._findings("explicit_denies.json"), [])

    def test_multi_hop_path_is_recorded(self):
        raw = {
            "UserDetailList": [{
                "UserName": "Dev", "Arn": "arn:aws:iam::123:user/Dev",
                "UserPolicyList": [{"PolicyName": "assume", "PolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}}],
            }],
            "RoleDetailList": [{
                "RoleName": "Powerful", "Arn": "arn:aws:iam::123:role/Powerful",
                "AssumeRolePolicyDocument": {"Statement": [{
                    "Effect": "Allow", "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "arn:aws:iam::123:user/Dev"}}]},
                "RolePolicyList": [{"PolicyName": "esc", "PolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}]}}],
            }],
        }
        d = iam_ingest.parse_gaad(raw, "123")
        findings = graph_to_findings(iam_graph.process_iam_data(d))
        dev = [f for f in findings if f["resource_name"] == "Dev"]
        self.assertTrue(dev, "Dev should reach Powerful's escalation via assume-role")
        self.assertTrue(any("Powerful" in step for step in dev[0]["attack_path"]))


if __name__ == '__main__':
    unittest.main(verbosity=2)
