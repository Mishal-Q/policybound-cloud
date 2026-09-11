# 0011. AZURE-IDENTITY-001 addresses IAM-BOUNDARY-001's intent by a different mechanism, not a port of it

## Context

AWS permission boundaries work by intersection: effective permissions
are the identity policy AND the boundary policy overlapping, so a
boundary caps what an identity policy can grant regardless of how
broadly that identity policy is written (see ADR 0005 and
`docs/identity-trust-model.md` for the worked example). Azure's RBAC
model has no equivalent construct -- there is no "boundary" resource type
that intersects with a role assignment the way an IAM permission
boundary intersects with an identity policy.

## Decision

`AZURE-IDENTITY-001` checks something structurally different: the SCOPE
a role assignment is granted at (subscription vs. resource-group vs.
single-resource), denying subscription-scoped assignments for any role
except Owner. The underlying governance intent -- cap what a privileged
identity can reach -- is the same as `IAM-BOUNDARY-001`. The mechanism
achieving it is not.

## Consequences

- Every place this project's documentation discusses
  `AZURE-IDENTITY-001` alongside `IAM-BOUNDARY-001` says "same
  governance intent, different control mechanism," explicitly, rather
  than implying equivalence. This is stated in the Rego file's own
  comment, the policy catalog entry, and
  `docs/cross-cloud-governance-model.md` -- not just here.
- This means the cross-cloud portability story for the identity
  invariant is weaker than for region/tags, and that's reported
  honestly rather than smoothed over. Of the six invariants, this one
  and network reachability are the two where "portable" means "same
  intent, independently implemented," not "same code, different
  normalizer."
- If Azure later adds a construct closer to a true boundary (Microsoft
  has discussed Azure Policy-based guardrails that intersect with role
  assignments in some configurations), this ADR is the place to revisit
  whether a tighter mapping becomes possible.

## Alternatives considered

**Claim Azure RBAC scope limiting IS a permission boundary.** Rejected
outright -- this was the specific case named in the instruction not to
claim equivalence where it doesn't exist, and it would have been a
factually incorrect claim about how either platform's access control
model works, not just an imprecise one.

**Skip an Azure identity invariant entirely, since no clean mapping
exists.** Considered. Rejected because "no clean 1:1 mapping" is itself
the finding worth demonstrating -- omitting it would have been the
easier path but a less honest and less interesting one, given the whole
point of the cross-cloud analysis is investigating where equivalence
does and doesn't hold, not just implementing the easy parts.
