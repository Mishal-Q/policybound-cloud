"""
Lambda entry point for the drift detector.

Two trigger paths wire into this handler (see docs/architecture.md):
  - fast path: EventBridge rule matching specific CloudTrail API calls
    (see modules/logging/main.tf: aws_cloudwatch_event_rule.security_mutations)
  - sweeper path: scheduled EventBridge rule, every 6 hours, that pulls
    the full AWS Config resource inventory for the governed resource types

Both paths converge on the same normalize -> diff -> classify pipeline,
which is exactly why the normalizer exists: without it, the fast path and
the sweeper path would need separate comparison logic.

This module intentionally does NOT call `terraform apply`, does NOT open
PRs itself with unreviewed content, and does NOT contain any Rego/OPA
evaluation logic inline -- policy_eval is expected to shell out to `opa
eval` (or call an OPA server) so the exact same compiled policies that
ran in CI also run here. See ADR 0005.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

import boto3

import aws_normalizer
import diff as diff_engine

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "classifier"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "remediation"))
from triage_classifier import classify  # noqa: E402
import exceptions as exceptions_module  # noqa: E402

DYNAMODB_TABLE = os.environ.get("DRIFT_EVENTS_TABLE", "drift-events")
DESIRED_STATE_KEY = os.environ.get("DESIRED_STATE_S3_KEY", "desired-state.json")
DESIRED_STATE_BUCKET = os.environ.get("DESIRED_STATE_S3_BUCKET", "")
OPA_BUNDLE_PATH = os.environ.get("OPA_BUNDLE_PATH", "/opt/policies")
# exceptions.yaml is packaged alongside the Lambda code (see
# Makefile:lambda-package, which now also copies remediation/ into the
# build directory) rather than fetched from S3 at invoke time. This
# means updating an exception requires a redeploy, which is a real
# trade-off -- the alternative (reading exceptions.yaml from S3 on every
# invocation) was left out for now since it adds a second source of
# truth to keep in sync with what's actually in git. Worth revisiting if
# exception turnaround time ever becomes a problem in practice.
EXCEPTIONS_PATH = os.environ.get("EXCEPTIONS_PATH", os.path.join(os.path.dirname(__file__), "exceptions.yaml"))


def load_desired_state(s3_client) -> list[dict]:
    """desired-state.json is written at successful `terraform apply` time
    (see drift/README.md) -- it is the already-normalized canonical
    snapshot of what Terraform believes it deployed, so the Lambda never
    needs to parse Terraform plan JSON itself."""
    obj = s3_client.get_object(Bucket=DESIRED_STATE_BUCKET, Key=DESIRED_STATE_KEY)
    return json.loads(obj["Body"].read())


def fetch_observed_state(config_client) -> list[dict]:
    governed_types = [
        "AWS::EC2::SecurityGroup",
        "AWS::RDS::DBInstance",
        "AWS::S3::Bucket",
        "AWS::IAM::Role",
        "AWS::EC2::RouteTable",
    ]
    config_items: list[dict] = []
    for rtype in governed_types:
        paginator = config_client.get_paginator("select_resource_config")
        query = f"SELECT resourceId, resourceType, configuration, supplementaryConfiguration, tags, accountId, awsRegion, configurationItemCaptureTime WHERE resourceType = '{rtype}'"
        for page in paginator.paginate(Expression=query):
            for result in page.get("Results", []):
                config_items.append(json.loads(result))
    return aws_normalizer.normalize(config_items)


def policy_eval_via_opa(event: dict, resources_context: list[dict], now_epoch: int) -> tuple[str | None, bool]:
    """Returns (policy_id_or_None, evaluation_error). Shells out to a
    local `opa eval` against the same policy bundle CI uses, passing the
    NEW value's resource plus injected evaluation_time_ns per doc4
    finding #4 (never call time.now_ns() inside Rego)."""
    input_doc = {
        "resources": resources_context,
        "context": {"evaluation_time_ns": now_epoch * 1_000_000_000},
        "exceptions": [],
    }
    try:
        proc = subprocess.run(
            ["opa", "eval", "-b", OPA_BUNDLE_PATH, "-i", "-", "-f", "json", "data.sentinel"],
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return None, True
        result = json.loads(proc.stdout)
        # Walk every package's `deny` set; first non-empty one wins for
        # this reference implementation (a resource is normally only in
        # scope for one policy category at a time given our 5-policy set).
        expressions = result.get("result", [{}])[0].get("expressions", [{}])
        value = expressions[0].get("value", {}) if expressions else {}
        for pkg, rules in value.items():
            deny = rules.get("deny", []) if isinstance(rules, dict) else []
            if deny:
                # policy_id is embedded in the message text by convention (e.g. "NET-DB-001 [...]")
                return deny[0].split(" ")[0], False
        return None, False
    except Exception:
        return None, True


def write_event(table, classification_result: dict, raw_event: dict):
    table.put_item(
        Item={
            "resource_id": classification_result["resource_urn"],
            "timestamp": str(int(time.time())),
            "resource_type": raw_event.get("resource_type", "unknown"),
            "changed_field": classification_result["field_changed"],
            "old_value": str(raw_event.get("old_value")),
            "new_value": str(raw_event.get("new_value")),
            "policy_id": classification_result.get("policy_id") or "none",
            "classification": classification_result["classification"],
            "action": classification_result["action"],
            "reason": classification_result["reason"],
            "detector_version": "0.1.0",
        }
    )


def handler(event: dict, context: Any) -> dict:
    session = boto3.session.Session()
    s3 = session.client("s3")
    config = session.client("config")
    dynamodb = session.resource("dynamodb").Table(DYNAMODB_TABLE)

    desired = load_desired_state(s3)
    observed = fetch_observed_state(config)
    divergences = diff_engine.diff_snapshots(desired, observed)

    now_epoch = int(time.time())
    results = []

    try:
        loaded_exceptions = exceptions_module.load_exceptions(EXCEPTIONS_PATH)
        lookup_exception = exceptions_module.make_lookup(loaded_exceptions)
    except (exceptions_module.ExceptionValidationError, FileNotFoundError):
        # A malformed or missing exceptions file must not silently mean
        # "nothing is excepted" -- that would make every currently-valid
        # exception's resource look freshly POLICY_VIOLATING or
        # SECURITY_CRITICAL and could page someone for something already
        # approved. Fail closed to "every divergence is UNDETERMINED"
        # instead of guessing either way; see ADR 0006 for why
        # UNDETERMINED exists rather than defaulting to a guess.
        lookup_exception = None

    for divergence in divergences:
        policy_id, eval_error = policy_eval_via_opa(divergence, observed, now_epoch)

        def _policy_eval(_e, _pid=policy_id):
            return _pid

        if lookup_exception is None:
            result = classify(
                divergence,
                policy_eval=_policy_eval,
                lookup_exception=lambda urn, pid: None,
                now_epoch=now_epoch,
                evaluation_error=True,
            )
        else:
            result = classify(
                divergence,
                policy_eval=_policy_eval,
                lookup_exception=lookup_exception,
                now_epoch=now_epoch,
                evaluation_error=eval_error,
            )
        write_event(dynamodb, result, divergence)
        results.append(result)

    return {"divergences_found": len(divergences), "results": results}
