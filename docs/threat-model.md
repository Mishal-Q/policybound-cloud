# Threat model

STRIDE, applied to both the workload and the control plane itself. The
control-plane half matters more for this project than the workload half
-- see the note at the end.

| # | Category | Threat | Mitigation |
|---|---|---|---|
| 1 | Spoofing | Attacker obtains credentials and assumes the `operator` or `break_glass` role. | Trust policy requires `aws:MultiFactorAuthPresent = true`; break-glass session capped at 1 hour. |
| 2 | Tampering | Someone changes a security group rule directly in the console, bypassing Terraform. | Drift detection: the change shows up as a divergence on the next fast-path or sweeper run, gets classified, and (if it violates a Control) produces a remediation PR. Detection, not prevention -- the change did happen, this is about catching it fast. |
| 3 | Repudiation | No record of who made an infrastructure change or when. | Multi-region CloudTrail trail with log file validation, delivered to an S3 bucket whose policy denies `DeleteObject`/`DeleteBucket` from every principal except the CloudTrail service itself. |
| 4 | Information disclosure | Database becomes reachable from the internet, exposing data. | `NET-DB-001` (attribute check) and `NET-DB-002` (route-table check) both have to be satisfied; see docs/network-matrix.md for why one isn't enough on its own. |
| 5 | Denial of service | Public ALB gets overwhelmed. | ASG scales 2-4 instances. Partial mitigation only -- this doesn't defend against a sustained volumetric attack, and I'm not claiming it does. |
| 6 | Elevation of privilege | The `app` role's identity policy gets modified to grant broader access than intended. | Permission boundary caps effective permissions regardless of what the identity policy claims (see docs/identity-trust-model.md worked example). `IAM-BOUNDARY-001` checks the boundary is attached and correct. |
| 7 | Supply chain | A Terraform module dependency is compromised or silently updated to something malicious. | Module versions pinned in `required_providers` blocks; CI never runs `terraform init -upgrade`. |
| 8 | Policy bypass | Someone merges a change without CI running, or without the OPA gate passing. | GitHub branch protection requires the `pr-validate` check to pass before merge (configured in the repo, not in Terraform -- this is a GitHub setting you have to turn on yourself). |
| 9 | Exception abuse | Someone edits `exceptions.yaml` to grant themselves an unauthorized carve-out around a policy. | `remediation/exceptions.py` requires every exception to name an approver team on that specific policy's allowed list (`POLICY_APPROVER_TEAMS`), have an explicit expiration, and reference an approved PR number. `NET-DB-002` and `DATA-ENC-001` are hardcoded to never accept an exception regardless of what's written in the file. CODEOWNERS should route any PR touching `exceptions.yaml` to the security team for review (see runbooks/policy-exception-process.md) -- like branch protection, this is a GitHub-side setting, not something Terraform enforces. |
| 10 | Compromised drift detector | The drift Lambda's own execution role is compromised and used to read sensitive Config data or forge classifications. | Lambda execution role is read-only against Config, write-only (PutItem, not Query/Scan/DeleteItem) against the DynamoDB audit table, and has no `terraform:*` or `iam:*` permissions at all -- it cannot escalate its own access even if fully compromised. See `drift/terraform/main.tf:aws_iam_role.drift_lambda`. |

## Why the control-plane threats (7-10) matter more here than the workload threats (1-6)

Threats 1-6 are the kind any AWS security course covers, and the
mitigations are standard. Threats 7-10 are specific to this project's
actual contribution: a system that automatically evaluates and responds
to infrastructure changes is a new attack surface in its own right. If
someone can quietly poison the exception file, or compromise the
detector's own execution role, they've found a way to make the
governance system itself vouch for something it shouldn't. That's a more
interesting threat than "the database is public" because it's specific
to what this project actually built, rather than something any AWS
deployment would need to think about anyway.
