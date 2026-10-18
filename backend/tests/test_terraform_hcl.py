"""Terraform source imports exercise the same IAM findings as JSON inputs."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import iam_graph
import iam_ingest
from iam_analyzer import IAMAnalyzer


SOURCE = Path(__file__).with_name('fixtures').joinpath('terraform_source.tf').read_text(encoding='utf-8')
POLICY = 'jsonencode({Statement=[{Effect="Allow", Action="*", Resource="*"}]})'
JSON_SOURCE = {
    'terraform': {'required_version': '>= 1.5.0'},
    'provider': {'aws': {'region': '${var.region}'}},
    'variable': {'region': {'type': 'string', 'default': 'us-east-1'}},
    'resource': {
        'aws_iam_policy': {'administrator': {
            'name_prefix': 'review-policy-', 'policy': '${' + POLICY + '}',
        }},
        'aws_iam_role': {'compute': {
            'name_prefix': 'review-role-',
            'assume_role_policy': '${jsonencode({Statement=[{Effect="Allow", Action="sts:AssumeRole", Principal={Service="ec2.amazonaws.com"}}]})}',
        }},
        'aws_iam_role_policy_attachment': {'administrator': {
            'role': '${aws_iam_role.compute.name}',
            'policy_arn': '${aws_iam_policy.administrator.arn}',
        }},
        'aws_security_group': {'open': {'name': 'open'}},
    },
}


def policy_source(expression=POLICY, extra=''):
    return f'''resource "aws_iam_policy" "test" {{
      name = "test-policy"
      policy = {expression}
      {extra}
    }}'''


class TestTerraformSource(unittest.TestCase):
    def test_user_example_detects_admin_and_reports_non_iam_resources(self):
        data = iam_ingest.config_to_iamdata(SOURCE)
        findings = IAMAnalyzer().scan_iamdata(data)
        self.assertTrue(any(f['pattern_id'] == 'full_admin' for f in findings))
        self.assertEqual(data.policies[0].policy_name, 'insecure-admin-policy')
        self.assertEqual(data.coverage.input_format, 'terraform_hcl')
        self.assertEqual(data.coverage.total_resources, 3)
        self.assertEqual(data.coverage.iam_resources, 1)
        self.assertEqual(data.coverage.skipped_resources, 2)
        self.assertFalse(data.coverage.complete)
        warnings = ' '.join(data.coverage.warnings)
        self.assertIn('aws_security_group', warnings)
        self.assertIn('aws_s3_bucket', warnings)

    def test_jsonencode_locals_defaults_and_condition_evidence(self):
        source = '''variable "config" { default = { action = "iam:PassRole" } }
        locals { actions = [var.config.action] }
        ''' + policy_source('''jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect = "Allow"
            Action = local.actions
            Resource = "*"
            Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
          }]
        })''')
        data = iam_ingest.config_to_iamdata(source)
        statement = data.policies[0].document.statements[0]
        self.assertEqual(statement.actions, ['iam:PassRole'])
        self.assertEqual(statement.conditions[0].key, 'aws:MultiFactorAuthPresent')
        self.assertTrue(data.coverage.conditions_present)
        self.assertIn('Used variable defaults for var.config', ' '.join(data.coverage.warnings))

    def test_heredoc_policy_and_escaped_iam_variables(self):
        source = policy_source('''<<POLICY
{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/$${aws:username}/*"}]}
POLICY
''')
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.policies[0].document.statements[0].resources,
                         ['arn:aws:s3:::bucket/${aws:username}/*'])

    def test_local_policy_and_identity_references_feed_the_graph(self):
        source = '''variable "prefix" { default = "review" }
        resource "aws_iam_user" "user" { name = "${var.prefix}-user" }
        resource "aws_iam_group" "group" { name = "review-group" }
        resource "aws_iam_group_membership" "members" {
          name = "members"
          group = aws_iam_group.group.name
          users = [aws_iam_user.user.name]
        }
        resource "aws_iam_group_policy_attachment" "attachment" {
          group = aws_iam_group.group.name
          policy_arn = aws_iam_policy.test.arn
        }
        ''' + policy_source()
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.users[0].group_list, ['review-group'])
        self.assertEqual(data.groups[0].attached_managed_policies[0].policy_arn, data.policies[0].arn)
        graph = iam_graph.process_iam_data(data)
        user = next(node for node in graph.nodes if node.id == 'user::review-user')
        self.assertTrue(user.effective_permissions)

    def test_role_trust_and_inline_policy_blocks(self):
        source = '''resource "aws_iam_role" "worker" {
          name = "worker"
          assume_role_policy = jsonencode({Statement=[{
            Effect="Allow", Action="sts:AssumeRole", Principal={Service="lambda.amazonaws.com"}
          }]})
          inline_policy {
            name="admin"
            policy=jsonencode({Statement=[{Effect="Allow",Action="*",Resource="*"}]})
          }
        }'''
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.roles[0].assume_role_policy_document.statements[0].principals,
                         ['lambda.amazonaws.com'])
        self.assertEqual(data.roles[0].inline_policies[0].document.statements[0].actions, ['*'])

    def test_unresolved_policy_is_skipped_instead_of_reported_as_safe(self):
        for expression in ('var.policy', 'data.aws_iam_policy_document.test.json',
                           'file("policy.json")', 'jsonencode({Statement=var.statements})'):
            with self.subTest(expression=expression):
                data = iam_ingest.config_to_iamdata(policy_source(expression))
                self.assertEqual(data.policies, [])
                self.assertEqual(data.coverage.skipped_resources, 1)
                self.assertFalse(data.coverage.complete)
                self.assertIn('Skipped aws_iam_policy.test', ' '.join(data.coverage.warnings))

    def test_circular_locals_are_reported_without_recursing_forever(self):
        source = 'locals { a=local.b\n b=local.a }\n' + policy_source('local.a')
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.policies, [])
        self.assertIn('circular', ' '.join(data.coverage.warnings))

    def test_dynamic_and_repeated_resources_require_plan(self):
        for extra in ('count=0', 'for_each={one="one"}', 'dynamic "statement" { for_each=[]\n content {} }'):
            with self.subTest(extra=extra):
                data = iam_ingest.config_to_iamdata(policy_source(extra=extra))
                self.assertEqual(data.policies, [])
                self.assertEqual(data.coverage.skipped_resources, 1)
                self.assertIn('require Terraform plan JSON', ' '.join(data.coverage.warnings))

    def test_module_and_data_source_coverage_is_explicit(self):
        source = 'module "external" { source="./module" }\ndata "aws_caller_identity" "current" {}\n' + policy_source()
        data = iam_ingest.config_to_iamdata(source)
        warnings = ' '.join(data.coverage.warnings)
        self.assertIn('Module contents are not loaded', warnings)
        self.assertIn('Data sources are not evaluated', warnings)

    def test_malformed_hcl_reports_location(self):
        with self.assertRaisesRegex(ValueError, 'Invalid Terraform syntax at line'):
            iam_ingest.config_to_iamdata('resource "aws_iam_policy" "bad" {')

    def test_duplicate_declarations_are_rejected(self):
        examples = (
            (SOURCE + SOURCE, 'Duplicate Terraform resource'),
            ('provider "aws" {}\nprovider "aws" {}', 'Duplicate Terraform provider'),
            ('variable "name" {}\nvariable "name" {}', 'Duplicate Terraform variable'),
            ('locals { a=1 }\nlocals { a=2 }', 'Duplicate Terraform local'),
            (policy_source(extra='name="duplicate"'), 'duplicate attributes'),
        )
        for source, message in examples:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                iam_ingest.config_to_iamdata(source)

    def test_only_non_iam_resources_does_not_claim_complete_analysis(self):
        data = iam_ingest.config_to_iamdata('resource "aws_s3_bucket" "test" { bucket="test" }')
        self.assertEqual(data.coverage.total_resources, 1)
        self.assertEqual(data.coverage.skipped_resources, 1)
        self.assertFalse(data.coverage.complete)
        warnings = ' '.join(data.coverage.warnings)
        self.assertIn('No supported IAM', warnings)
        self.assertNotIn('plan contains no resources', warnings)

    def test_json_string_and_bom_still_work(self):
        document = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
        for value in (document, json.dumps(document), '\ufeff' + json.dumps(document)):
            data = iam_ingest.config_to_iamdata(value)
            self.assertEqual(data.coverage.input_format, 'raw_policy')
            self.assertEqual(data.policies[0].document.statements[0].actions, ['*'])
        with self.assertRaisesRegex(ValueError, 'Invalid JSON at line'):
            iam_ingest.config_to_iamdata('{invalid json}')


class TestTerraformConfigurationJSON(unittest.TestCase):
    def test_configuration_json_string_and_object_import_the_same_iam_graph(self):
        for source in (JSON_SOURCE, json.dumps(JSON_SOURCE)):
            with self.subTest(source_type=type(source).__name__):
                data = iam_ingest.config_to_iamdata(source)
                self.assertEqual(data.coverage.input_format, 'terraform_json')
                self.assertEqual(data.coverage.total_resources, 4)
                self.assertEqual(data.coverage.skipped_resources, 1)
                self.assertEqual(data.coverage.iam_resources, 2)
                self.assertFalse(data.coverage.complete)
                self.assertEqual(data.roles[0].role_name, 'compute')
                self.assertEqual(data.roles[0].attached_managed_policies[0].policy_arn, data.policies[0].arn)
                findings = IAMAnalyzer().scan_iamdata(data)
                self.assertTrue(any(item['pattern_id'] == 'full_admin' for item in findings))
                graph = iam_graph.process_iam_data(data)
                role = next(node for node in graph.nodes if node.id == 'role::compute')
                self.assertTrue(role.effective_permissions)

    def test_json_locals_defaults_and_inline_policy_object(self):
        source = {
            'variable': {'action': {'default': 'iam:PassRole'}},
            'locals': {'actions': ['${var.action}']},
            'resource': {'aws_iam_user': {'test': {
                'name': 'test-user',
                'inline_policy': {
                    'name': 'inline',
                    'policy': '${jsonencode({Statement=[{Effect="Allow",Action=local.actions,Resource="*"}]})}',
                },
            }}},
        }
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.users[0].inline_policies[0].document.statements[0].actions, ['iam:PassRole'])

    def test_general_array_block_mapping_and_provider_aliases(self):
        source = {
            'provider': {'aws': [{'region': 'us-east-1'}, {'alias': 'west', 'region': 'us-west-2'}]},
            'resource': [{'aws_iam_policy': [
                {'first': {'name': 'first', 'policy': '${' + POLICY + '}'}},
                {'second': {'name': 'second', 'policy': '${' + POLICY + '}'}},
            ]}],
        }
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual([item.policy_name for item in data.policies], ['first', 'second'])

    def test_unresolved_configuration_json_policy_is_skipped(self):
        source = {'resource': {'aws_iam_policy': {'test': {'policy': '${var.policy}'}}}}
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.policies, [])
        self.assertEqual(data.coverage.skipped_resources, 1)
        self.assertIn('Skipped aws_iam_policy.test', ' '.join(data.coverage.warnings))

    def test_bad_configuration_json_shapes_produce_validation_errors(self):
        for source in ({'resource': 'invalid'}, {'resource': {'aws_iam_policy': {'test': 1}}}):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'Invalid Terraform configuration JSON'):
                iam_ingest.config_to_iamdata(source)

    def test_duplicate_resources_in_json_arrays_are_rejected(self):
        resource = {'aws_iam_policy': {'test': {'policy': '${' + POLICY + '}'}}}
        with self.assertRaisesRegex(ValueError, 'Duplicate Terraform resource'):
            iam_ingest.config_to_iamdata({'resource': [resource, resource]})

    def test_plan_json_is_still_a_plan(self):
        source = {'planned_values': {'root_module': {'resources': [{
            'type': 'aws_iam_policy', 'name': 'test', 'values': {
                'name': 'test-policy', 'policy': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]},
            },
        }]}}}
        data = iam_ingest.config_to_iamdata(source)
        self.assertEqual(data.coverage.input_format, 'terraform_plan')
        self.assertEqual(data.policies[0].document.statements[0].actions, ['*'])


class TestTerraformAPI(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.module = app_module
        self.client = app_module.app.test_client()
        self.enterContext(mock.patch.dict(app_module.app.config, TESTING=True))
        # Exercise the full deterministic pipeline without calling AI providers.
        self.enterContext(mock.patch.object(app_module, 'ai_detector', mock.Mock(enabled=False)))
        self.enterContext(mock.patch.object(app_module.remediator, 'batch_remediate',
                                           side_effect=lambda findings: [{} for _ in findings]))
        self.enterContext(mock.patch.object(app_module.risk_brief_generator, 'generate', return_value={}))

    def test_hcl_round_trip_returns_real_findings_and_source_metadata(self):
        response = self.client.post('/api/analyze', json={
            'iam_config': SOURCE, 'config_type': 'auto', 'source': 'upload', 'source_name': 'main.tf',
        })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['summary']['source_name'], 'main.tf')
        self.assertEqual(payload['summary']['coverage']['input_format'], 'terraform_hcl')
        finding = next(item for item in payload['vulnerabilities'] if item['pattern_id'] == 'full_admin')
        self.assertEqual(finding['severity'], 'CRITICAL')
        self.assertEqual(finding['resource_name'], 'insecure-admin-policy')

    def test_invalid_hcl_returns_actionable_400(self):
        response = self.client.post('/api/analyze', json={
            'iam_config': 'provider "aws" {', 'config_type': 'auto',
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn('line 1', response.get_json()['error'])

    def test_terraform_configuration_json_api_round_trip(self):
        for source in (JSON_SOURCE, json.dumps(JSON_SOURCE)):
            response = self.client.post('/api/analyze', json={
                'iam_config': source, 'source_name': 'main.tf.json',
            })
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload['summary']['coverage']['input_format'], 'terraform_json')
            self.assertEqual(payload['summary']['source_name'], 'main.tf.json')
            self.assertTrue(any(item['pattern_id'] == 'full_admin' for item in payload['vulnerabilities']))

    def test_invalid_configuration_json_shape_is_400_not_500(self):
        response = self.client.post('/api/analyze', json={'iam_config': {'resource': 'invalid'}})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Terraform configuration JSON', response.get_json()['error'])


if __name__ == '__main__':
    unittest.main()
