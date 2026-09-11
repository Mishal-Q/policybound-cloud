# 0005. IAM-BOUNDARY-001 checks boundary attachment, not action-set subtraction

## Context

The first draft of this policy (originally `boundary_subset_check.rego`)
tried to enforce: for every IAM role with a permissions boundary
attached, deny if the role's identity policy grants any action not also
present in the boundary policy.

That's backwards. Permission boundaries are *designed* to be a superset
that an identity policy narrows via intersection:

```
EffectivePermissions = IdentityPolicy ∩ PermissionBoundary
```

An identity policy granting `s3:GetObject` and `s3:PutObject` while its
boundary allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` is
completely normal -- the boundary is doing its job by capping what the
identity policy *could* grant, and the identity policy is free to be
narrower than that cap. The original rule would have flagged the
boundary itself as the problem, which meant it would false-positive on
every correctly-configured role in the account and never actually catch
a real misconfiguration.

## Decision

Replace the subset-comparison logic entirely. `IAM-BOUNDARY-001`
(`policies/identity/iam_boundary_001.rego`) now checks two things
instead:

1. Every non-admin role has a permissions boundary attached at all.
2. The boundary ARN attached is the one approved boundary
   (`SentinelWorkloadBoundary`), not some other policy that happens to
   be attached.

Roles tagged `privilege=admin` (currently just the break-glass role) are
exempt from requiring a boundary, since an administrative role that's
itself boundary-constrained isn't meaningfully administrative anymore --
that exemption is deliberate and documented, not an oversight.

## Consequences

- The policy now tests something that can actually be wrong: a missing
  boundary, or the wrong boundary ARN. Both are represented in
  `policies/identity/iam_boundary_001_test.rego`.
- One real bug surfaced while writing the OPA test suite for this rule:
  the first version used `not resource.attributes.permissions_boundary_arn`
  to check for a missing boundary, which does not do what it looks like
  it does in Rego. `null` is a defined JSON value, not an absent one, so
  `not null` evaluates to false rather than true, and the missing-
  boundary test case silently passed when it should have failed.
  Fixed by checking `permissions_boundary_arn == null` explicitly. Kept
  as a reminder that Rego's `not` means "this expression is undefined,"
  not "this value is falsy" -- those are different things in a language
  where `null`, `false`, and `undefined` are three separate states.

## Alternatives considered

**Keep the subset check but invert the direction** (deny if the boundary
grants more than the identity policy needs). Rejected -- this describes
"least privilege at the boundary level," which is a real and reasonable
thing to eventually check, but it's a different, harder problem
(requires enumerating the boundary's *unused* headroom, not just
attachment) and wasn't what the original rule was trying to do anyway.
