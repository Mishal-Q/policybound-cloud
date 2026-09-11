# Identity trust model

Plain IAM roles, not Identity Center permission sets -- see ADR 0004.

| Role | Privilege tag | Trust condition | Notes |
|---|---|---|---|
| `app` | `standard` | EC2 service principal only | Instance profile role. Scoped to `s3:GetObject` on the config bucket and `secretsmanager:GetSecretValue` on one named secret. No human ever assumes this role directly. |
| `operator` | `standard` | Cross-account, requires `aws:MultiFactorAuthPresent = true` | Allowed `ec2:*` and `rds:Describe*`/`RebootDBInstance`, but explicitly denied `iam:CreateRole`/`AttachRolePolicy`/`PutRolePolicy` in its own identity policy, on top of the permission boundary also denying IAM escalation. Belt and suspenders deliberately. |
| `break_glass` | `admin` | Cross-account, requires MFA, 1-hour max session | The one role exempt from `IAM-BOUNDARY-001`'s boundary requirement, because an admin role that's boundary-constrained isn't actually an emergency-access role anymore. See `runbooks/break-glass-access.md` for what's supposed to happen every time this role is used. |

## Worked example: why the permission boundary matters even when the identity policy looks correct

This is the example ADR 0005 references. Say the `app` role's identity
policy grants:

```
s3:GetObject
s3:PutObject
```

on the deployment bucket, and its permission boundary
(`SentinelWorkloadBoundary`) allows:

```
s3:GetObject
s3:PutObject
secretsmanager:GetSecretValue
rds:Describe*
ec2:Describe*
```

Effective permissions are the intersection of the two, which here is
just `s3:GetObject` / `s3:PutObject` -- the boundary being broader than
the identity policy doesn't grant anything extra, because the identity
policy is the narrower of the two. This is normal and correct, and it's
exactly the scenario the original draft of `IAM-BOUNDARY-001` got wrong:
it treated "identity policy narrower than boundary" as a violation, when
it's actually the boundary doing its job.

The scenario that boundary *should* catch is different: someone attaches
a new, broader identity policy to the `app` role later -- say
`s3:DeleteObject` and `s3:*` on every bucket -- without anyone reviewing
it as carefully as the original policy. If the boundary is still
attached and still says `s3:GetObject`/`s3:PutObject` only, the
*effective* permissions stay capped at the original two actions
regardless of what the new identity policy claims to grant. The
boundary is the ceiling; the identity policy can move around underneath
it, but it can never punch through it. That's the property
`IAM-BOUNDARY-001` actually checks for: is the ceiling attached at all,
and is it the right ceiling -- not "does the identity policy match the
boundary exactly."
