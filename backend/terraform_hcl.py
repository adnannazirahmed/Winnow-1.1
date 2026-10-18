"""Read IAM from Terraform source without executing Terraform or provider code.

Only static values, variable defaults, locals, jsonencode, and local IAM
name/ARN references are resolved. Anything requiring a plan is reported as
incomplete coverage instead of being guessed or treated as an empty policy.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

import hcl2
from lark.exceptions import UnexpectedInput, VisitError


class UnresolvedTerraform(ValueError):
    """A value needs Terraform evaluation beyond this static importer."""


@dataclass
class TerraformImport:
    config: dict
    total_resources: int
    skipped_resources: int
    warnings: list[str]


_REFERENCE = re.compile(r"[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)+")
_INTERPOLATION = re.compile(r"(?<!\$)\$\{([^{}]+)\}")
_IAM_ENTITIES = {
    "aws_iam_policy": "policy", "aws_iam_role": "role",
    "aws_iam_user": "user", "aws_iam_group": "group",
}
_IAM_FIELDS = {
    "name", "path", "policy", "assume_role_policy", "inline_policy",
    "managed_policy_arns", "permissions_boundary", "role", "user", "group",
    "roles", "users", "groups", "policy_arn",
}


def _load(source: str) -> dict:
    try:
        return hcl2.loads(source)
    except UnexpectedInput as exc:
        raise ValueError(
            f"Invalid Terraform syntax at line {exc.line}, column {exc.column}. "
            "Check the braces, quotes, and attribute values."
        ) from None
    except VisitError:
        raise ValueError(
            "Invalid Terraform source: check for duplicate attributes or blocks."
        ) from None


def _named_blocks(document: dict, kind: str) -> dict:
    result = {}
    for block in document.get(kind, []):
        for name, values in block.items():
            if name in result:
                raise ValueError(f"Duplicate Terraform {kind} declaration: {name}")
            result[name] = values
    return result


def _has_dynamic(value: Any) -> bool:
    if isinstance(value, dict):
        return "dynamic" in value or any(_has_dynamic(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_dynamic(item) for item in value)
    return False


class _StaticValues:
    def __init__(self, document: dict, resources: dict):
        self.variables = _named_blocks(document, "variable")
        self.locals = {}
        for block in document.get("locals", []):
            for name, value in block.items():
                if name in self.locals:
                    raise ValueError(f"Duplicate Terraform local declaration: {name}")
                self.locals[name] = value
        self.resources = resources
        self.used_defaults = set()

    def resolve(self, value: Any, stack: tuple = ()) -> Any:
        if len(stack) > 40:
            raise UnresolvedTerraform("expression nesting is too deep")
        if isinstance(value, dict):
            return {self.resolve(key, stack): self.resolve(item, stack)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [self.resolve(item, stack) for item in value]
        if not isinstance(value, str):
            return value
        if "%{" in value:
            raise UnresolvedTerraform("template directives require a Terraform plan")
        # A complete expression can return a list/object, not only a string.
        if value.startswith("${") and value.endswith("}"):
            expression = value[2:-1].strip()
            if expression.startswith("jsonencode(") and expression.endswith(")"):
                parsed = _load("value = " + expression[len("jsonencode("):-1])
                return json.dumps(self.resolve(parsed["value"], stack))
            if _REFERENCE.fullmatch(expression):
                return self.reference(expression, stack)

        def interpolate(match):
            expression = match.group(1).strip()
            if not _REFERENCE.fullmatch(expression):
                raise UnresolvedTerraform("unsupported expression; upload a Terraform plan JSON")
            resolved = self.reference(expression, stack)
            if not isinstance(resolved, (str, int, float, bool)):
                raise UnresolvedTerraform("a string interpolation requires a scalar value")
            return json.dumps(resolved) if isinstance(resolved, bool) else str(resolved)

        result = _INTERPOLATION.sub(interpolate, value)
        if re.search(r"(?<!\$)\$\{", result):
            raise UnresolvedTerraform("unsupported expression; upload a Terraform plan JSON")
        # Terraform's escaped IAM policy variables remain literal policy variables.
        return result.replace("$${", "${").replace("%%{", "%{")

    def reference(self, expression: str, stack: tuple) -> Any:
        if expression in stack:
            raise UnresolvedTerraform("circular Terraform reference")
        stack = stack + (expression,)
        parts = expression.split(".")
        if parts[0] == "var":
            variable = self.variables.get(parts[1], {})
            if "default" not in variable:
                raise UnresolvedTerraform(f"var.{parts[1]} needs a value; upload a Terraform plan JSON")
            self.used_defaults.add(parts[1])
            result = self.resolve(variable["default"], stack)
            tail = parts[2:]
        elif parts[0] == "local" and parts[1] in self.locals:
            result = self.resolve(self.locals[parts[1]], stack)
            tail = parts[2:]
        elif len(parts) == 3 and parts[0] in _IAM_ENTITIES:
            address = ".".join(parts[:2])
            resource = self.resources.get(address)
            if resource is None:
                raise UnresolvedTerraform(f"{address} is not in the supplied source")
            if any(key in resource for key in ("count", "for_each")):
                raise UnresolvedTerraform(f"{address} uses count/for_each; upload a Terraform plan JSON")
            name = self.resolve(resource.get("name", parts[1]), stack)
            if not isinstance(name, str):
                raise UnresolvedTerraform(f"{address} has an unresolved name")
            if parts[2] in ("name", "id"):
                return name
            if parts[2] == "arn":
                path = self.resolve(resource.get("path", "/"), stack)
                if not isinstance(path, str):
                    raise UnresolvedTerraform(f"{address} has an unresolved path")
                return f"arn:aws:iam::000000000000:{_IAM_ENTITIES[parts[0]]}/{path.strip('/') + '/' if path.strip('/') else ''}{name}"
            raise UnresolvedTerraform(f"{address}.{parts[2]} requires a Terraform plan")
        else:
            raise UnresolvedTerraform("unresolved Terraform reference; upload a Terraform plan JSON")
        for key in tail:
            if not isinstance(result, dict) or key not in result:
                raise UnresolvedTerraform("unresolved object attribute; upload a Terraform plan JSON")
            result = result[key]
        return result


def _validate_policy(value: Any) -> None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise UnresolvedTerraform("policy must resolve to a JSON document") from None
    if not isinstance(value, dict):
        raise UnresolvedTerraform("policy must resolve to a JSON object")


def parse_terraform_hcl(source: str, supported_types: set) -> TerraformImport:
    return _import_document(_load(source), supported_types)


def _json_blocks(value: Any, labels: int, location: str) -> list[dict]:
    """Normalize HCL JSON's object/array block mapping to python-hcl2 blocks."""
    blocks = []
    for item in value if isinstance(value, list) else [value]:
        if not isinstance(item, dict):
            raise ValueError(f"Invalid Terraform configuration JSON: {location} must contain objects.")
        if not labels:
            blocks.append(item)
            continue
        for label, body in item.items():
            if label == "//":
                continue
            for block in _json_blocks(body, labels - 1, location + "." + label):
                blocks.append({label: block})
    return blocks


def parse_terraform_json(source: dict, supported_types: set) -> TerraformImport:
    document = {}
    for kind, labels in (
        ("resource", 2), ("data", 2), ("provider", 1), ("variable", 1),
        ("module", 1), ("output", 1), ("locals", 0), ("terraform", 0),
    ):
        if kind in source:
            document[kind] = _json_blocks(source[kind], labels, kind)
    return _import_document(document, supported_types)


def _import_document(document: dict, supported_types: set) -> TerraformImport:
    if not any(key in document for key in (
        "resource", "provider", "terraform", "variable", "locals", "data", "module", "output"
    )):
        raise ValueError("Expected Terraform blocks or an IAM JSON document.")
    resources = {}
    for block in document.get("resource", []):
        for resource_type, instances in block.items():
            for name, values in instances.items():
                address = f"{resource_type}.{name}"
                if address in resources:
                    raise ValueError(f"Duplicate Terraform resource declaration: {address}")
                resources[address] = values
    # Catch the repeated default provider configuration from a duplicated file.
    providers = set()
    for block in document.get("provider", []):
        for name, values in block.items():
            key = (name, str(values.get("alias", "")))
            if key in providers:
                raise ValueError(f"Duplicate Terraform provider configuration: {name}")
            providers.add(key)
    resolver = _StaticValues(document, resources)
    warnings = [
        "Terraform source is analyzed statically; no providers or infrastructure changes are run. "
        "Local IAM references use placeholder account identifiers, not verified deployed ARNs."
    ]
    if document.get("module"):
        warnings.append("Module contents are not loaded; upload Terraform plan JSON for module resources.")
    if document.get("data"):
        warnings.append("Data sources are not evaluated; dependent IAM resources need Terraform plan JSON.")
    imported = []
    outside_scope = set()
    for address, raw in resources.items():
        resource_type, name = address.split(".", 1)
        if resource_type not in supported_types:
            outside_scope.add(resource_type)
            continue
        try:
            if any(key in raw for key in ("count", "for_each")) or _has_dynamic(raw):
                raise UnresolvedTerraform("count, for_each, or dynamic blocks require Terraform plan JSON")
            values = {key: resolver.resolve(value) for key, value in raw.items() if key in _IAM_FIELDS}
            if isinstance(values.get("inline_policy"), dict):
                values["inline_policy"] = [values["inline_policy"]]
            for key in ("policy", "assume_role_policy"):
                if key in values:
                    _validate_policy(values[key])
            for inline in values.get("inline_policy", []):
                _validate_policy(inline.get("policy"))
            if resource_type in _IAM_ENTITIES:
                values.setdefault("name", name)
                values["arn"] = resolver.reference(address + ".arn", ())
            imported.append({"type": resource_type, "name": name, "values": values})
        except UnresolvedTerraform as exc:
            warnings.append(f"Skipped {address}: {exc}.")
    if outside_scope:
        warnings.append("Resources outside supported IAM analysis were skipped: " + ", ".join(sorted(outside_scope)))
    if resolver.used_defaults:
        warnings.append(
            "Used variable defaults for " + ", ".join("var." + name for name in sorted(resolver.used_defaults))
            + "; .tfvars and other overrides are not loaded."
        )
    return TerraformImport(
        config={"resources": imported}, total_resources=len(resources),
        skipped_resources=len(resources) - len(imported), warnings=warnings,
    )
