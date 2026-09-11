# 0007. Compare a normalized canonical schema, not raw Terraform plan JSON against raw AWS Config

## Context

Terraform plan JSON and AWS Config configuration items describe the same
real-world facts using completely different shapes. A security group's
ingress rule looks like `{"protocol": "tcp", "from_port": 5432,
"cidr_blocks": ["0.0.0.0/0"]}` in Terraform plan JSON, and like
`{"ipProtocol": "tcp", "fromPort": 5432, "ipv4Ranges": [{"cidrIp":
"0.0.0.0/0"}]}` in an AWS Config configuration item -- same fact, three
different key names, one extra level of nesting.

Diffing these two representations directly produces garbage: every field
looks "changed" because the field names don't match, even when nothing
about the actual infrastructure diverged. Worse, if OPA policies are
written against Terraform's shape for CI and against Config's shape for
runtime drift checks, that's two independent copies of every policy that
have to be kept in sync by hand -- exactly the kind of duplication that
drifts apart the first time someone fixes a bug in one copy and forgets
the other.

## Decision

Define one canonical resource schema
(`drift/detector/schema.py:CanonicalResource`) that both the desired-
state normalizer (`drift/detector/desired_state.py`, reads Terraform plan
JSON) and the observed-state normalizer
(`drift/detector/aws_normalizer.py`, reads AWS Config configuration
items) must emit before anything downstream sees the data. `diff.py`
compares two canonical snapshots field-by-field. Every OPA policy is
written against the canonical shape (`input.resources[_].attributes...`)
and is evaluated identically whether it's running in CI against a
normalized Terraform plan or in the drift Lambda against normalized AWS
Config data.

If a normalizer can't populate every field a resource type's contract
requires (`ATTRIBUTE_CONTRACTS` in schema.py), it omits that resource
entirely rather than emitting a partially-filled one. A missing resource
becomes a diff event (`__resource_existence__`) the classifier can
reason about; a partially-filled resource would silently look compliant
on whatever fields happened to be missing, which is worse than not
reporting it at all.

## Consequences

- Exactly one Rego rule per Control, run in both CI and at runtime,
  verified by the same `_test.rego` fixtures.
- The normalizers carry all the AWS-specific and Terraform-specific
  parsing complexity, so a Control author never touches provider field
  names.
- Coverage is narrower on purpose: `ATTRIBUTE_CONTRACTS` currently
  covers five resource types (security_group, db_instance, s3_bucket,
  iam_role, route_table) with the specific fields the five existing
  Controls need. Adding a sixth Control that needs a new field means
  updating the contract and both normalizers together -- this is
  intentionally not automatic, so the two never quietly drift out of
  sync again the way the original identity-boundary logic almost did
  (see ADR 0005).

## Alternatives considered

**Normalize only at policy-evaluation time, inline inside each Rego
rule.** Rejected -- this is exactly the "duplicate the policy logic
twice" problem the decision above is trying to avoid, just moved inside
Rego instead of outside it.

**Skip normalization, run Terraform inside the drift Lambda to regenerate
a comparable plan.** Considered and rejected early. Terraform execution
inside a Lambda adds a large dependency surface (provider binaries,
state locking, credentials) for a comparison the canonical schema
already solves without needing Terraform to run a second time. See also
the "no Terraform inside Lambda" discussion this decision descends from.
