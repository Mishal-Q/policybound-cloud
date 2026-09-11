# Runbook: break-glass access

The `break_glass` IAM role (`modules/identity/main.tf`) is the one role
in this project tagged `privilege = admin` and exempt from
`IAM-BOUNDARY-001`'s boundary requirement. It exists for the scenario
where the normal identity model itself is part of the problem -- e.g. the
`operator` role's permissions turn out to be too narrow to fix an
active incident, or the CI pipeline that would normally deploy a fix is
itself down.

## What triggers legitimate use

- An active incident where the standard `operator` role's scoped
  permissions are blocking the fix, and waiting for a normal Terraform
  PR cycle would make the incident materially worse.
- The CI/CD pipeline is unavailable and a security-critical finding
  needs a manual fix faster than the pipeline can be restored.

Using break-glass access to skip the normal PR process because it's
slow, or to make a change you'd rather not have reviewed, is not a
legitimate use -- and every use is logged (CloudTrail records every API
call made under this role, same as any other role) and is expected to
be reviewed afterward regardless of the reason given at the time.

## Constraints already built in

- Trust policy requires `aws:MultiFactorAuthPresent = true` -- MFA is
  not optional for this role even in an emergency.
- `max_session_duration = 3600` -- one hour, no exceptions. If the
  incident takes longer than that, re-assume the role rather than
  expecting the session to persist.
- Credentials for whoever is allowed to assume this role should live in
  Secrets Manager with rotation enabled, not in a shared document or a
  password manager entry with no rotation. This project doesn't
  provision the human-facing credential distribution itself -- that's an
  organizational process decision outside Terraform's scope, but it
  needs to exist before this role is usable in practice.

## Mandatory post-use review

Every use of `break_glass` should trigger:

1. A CloudTrail query for every API call made under the assumed role's
   session during the incident window.
2. A written note (even a short one) of what the incident was and why
   the standard roles weren't sufficient.
3. If the standard `operator` role's permissions were genuinely too
   narrow, that's a signal to fix the `operator` role's scoped policy in
   `modules/identity/main.tf`, not a signal to use break-glass again next
   time the same situation comes up.
