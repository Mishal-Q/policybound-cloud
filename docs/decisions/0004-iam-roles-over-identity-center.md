# 0004. Plain IAM roles instead of IAM Identity Center (SSO)

## Context

The original identity design used AWS IAM Identity Center permission
sets for Developer/Operator/Security roles, assumable via SSO. This is
how a real organization would likely do it.

The problem is that the Identity Center *instance itself* has to be
enabled through the AWS console, once, per AWS Organization -- it is not
something `terraform apply` can create from nothing. Terraform can
manage permission sets and account assignments once an instance already
exists, but getting to that starting point is a manual, non-automatable
step. For a project meant to be reproducible from a fresh AWS account by
running `terraform apply`, that's a hard blocker, not a minor
inconvenience.

## Decision

Use plain, directly-assumable IAM roles (`modules/identity/main.tf`:
`app`, `operator`, `break_glass`) instead of Identity Center permission
sets. Each role carries the same properties the original permission sets
were meant to demonstrate:

- least-privilege identity policies scoped to specific actions and
  resources
- a permissions boundary attached to every non-admin role
  (`aws_iam_policy.workload_boundary`)
- an MFA condition (`aws:MultiFactorAuthPresent`) on the trust policy for
  the operator and break-glass roles, matching the original Operator/
  Security permission sets' MFA requirement

## Consequences

- The whole identity module is Terraform-creatable from zero, no manual
  console step.
- No SSO session-duration semantics (4hr/2hr/1hr per permission set in
  the original spec) -- IAM role sessions use `max_session_duration`
  instead, which is set per-role but doesn't carry SSO's per-session
  browser/CLI login flow.
- If Identity Center is added later, these IAM roles map fairly directly
  onto permission sets: the identity policies and permission boundary
  can be reused as-is, only the "how does a human end up assuming this
  role" mechanism changes.

## Alternatives considered

**Build Identity Center anyway, accept the manual step.** Rejected --
this project is meant to be handed to someone with a fresh AWS account
and no prior manual setup, and a required console click before `terraform
apply` even starts undermines that.

**Skip MFA conditions entirely to simplify further.** Rejected -- the
MFA condition on privileged role assumption is one of the concrete,
checkable claims in the threat model (see docs/threat-model.md,
Spoofing), and it costs nothing extra to keep.
