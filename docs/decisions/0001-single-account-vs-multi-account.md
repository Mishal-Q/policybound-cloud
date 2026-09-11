# 0001. Single AWS account, not three (or five)

## Context

The original design called for a 3-account AWS Organizations layout
(management, security-logging, workload) as a compressed version of a
5-account enterprise pattern. The idea was to demonstrate cross-account
governance the way a real organization would structure it.

In practice, standing up three real AWS accounts means email
verification per account, billing setup per account, and cross-account
IAM trust plumbing before any of the actual governance logic gets
touched. None of that friction teaches anything about policy evaluation,
drift detection, or classification -- it's just account administration.

## Decision

Build and demonstrate on a single AWS account. Simulate account
boundaries with an `account-boundary` tag
(`management|security|workload`) and separate Terraform state files per
boundary, rather than separate AWS accounts.

The 3-account and 5-account layouts are documented here as the intended
target-state architecture, not built.

## Consequences

- Setup time goes from hours of account administration to zero.
- Cross-account IAM trust policies (`sts:AssumeRole` with
  `aws:PrincipalOrgID` conditions) can't be demonstrated against real
  account boundaries. The identity module still implements MFA
  conditions and permission boundaries, which are the parts of the
  identity story that actually matter for this project; the
  cross-account trust condition is written into the Terraform
  (`modules/identity/main.tf`) using a `trusted_account_arn` variable so
  the pattern is there, just pointed at one account instead of three.
- AWS Organizations SCPs are not demonstrated at all, since SCPs only
  exist at the Organization/OU level. This is a real gap versus the
  original spec, not a hidden one.

## Alternatives considered

**Three real accounts.** Rejected for the setup-friction reason above --
it doesn't strengthen the actual governance demonstration, it just adds
AWS console time.

**AWS Organizations with a single member account under a dummy root.**
Considered, since it would let SCPs be demonstrated. Rejected because
creating an Organization still requires a separate root account and adds
back most of the friction this decision is trying to avoid, for one
feature (SCPs) that's peripheral to the project's actual contribution
(the policy/drift engine).
