# Scope

## In

- Single AWS account, us-east-1, with account-boundary simulated via
  tags (`account-boundary = management|security|workload`) rather than
  real AWS Organizations accounts. See ADR 0001.
- A 3-tier VPC (public/app/data) with security-group-based
  microsegmentation. See ADR 0003.
- Five governance Controls, chosen because each demonstrates a distinct
  kind of check (single-attribute, cross-resource graph, existence/
  attachment, multi-condition, delta-based cost) rather than choosing
  fifteen shallow ones:
  - `NET-DB-001` -- database not publicly accessible
  - `NET-DB-002` -- database subnet has no default route to an internet
    gateway (the cross-resource invariant)
  - `IAM-BOUNDARY-001` -- non-admin IAM roles reference the approved
    permission boundary
  - `DATA-ENC-001` -- RDS and S3 use customer-managed KMS encryption
  - `COST-001` -- PR-introduced monthly cost delta stays under 25%
- A normalized drift-detection pipeline: canonical schema, Terraform-plan
  and AWS-Config normalizers, semantic diff, five-state risk classifier
  (`OUT_OF_SCOPE`, `BENIGN`, `AUTHORIZED_DRIFT`, `POLICY_VIOLATING`,
  `SECURITY_CRITICAL`, `UNDETERMINED`).
- A governed exception system: time-boxed, per-policy-approver-team,
  loaded from `remediation/exceptions.yaml`, with two policies
  (`NET-DB-002`, `DATA-ENC-001`) hardcoded as non-exceptable.
- Human-approved remediation only -- the drift Lambda proposes a PR, it
  never calls `terraform apply`. See ADR 0006.
- CI: Terraform validate/plan, Checkov, OPA policy tests, cost delta
  check, PR comment summary.
- CloudTrail + AWS Config, scoped to the five resource types the
  Controls actually evaluate, with a CloudTrail/EventBridge fast path so
  the live demo doesn't wait on Config's multi-minute delivery lag.

## Out

- Real multi-account AWS Organizations / SCPs. Documented as
  target-state in ADR 0001, not built.
- IAM Identity Center / SSO. Documented as target-state in ADR 0004, not
  built -- plain IAM roles demonstrate the same boundary/MFA invariants.
- Transit Gateway. See ADR 0002.
- Multi-region deployment.
- Real-time (sub-second) containment or automatic infrastructure
  mutation of any kind.
- Cross-cloud support (this is AWS-specific throughout: the normalizer,
  the Config integration, the IAM model).
- A general-purpose CSPM replacement. This project is a reference
  implementation of one governance architecture, not a competitor to
  Wiz, Prisma Cloud, or AWS Security Hub -- see `docs/limitations.md`
  for the longer version of that point.
