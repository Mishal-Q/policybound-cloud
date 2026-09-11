# 0003. Security groups do the microsegmentation, not a NACL matrix

## Context

An earlier draft specified an explicit NACL rule matrix across all three
tiers (internet -> public: 443 only; public -> app: 8080 only; app ->
data: 5432 only; data -> anywhere: deny all; plus explicit deny rules
for internet -> data and internet -> app). NACLs are stateless, so each
of those needed a matching reverse-direction rule for ephemeral ports,
which roughly doubles the rule count and is easy to get subtly wrong --
the classic mistake is allowing the forward request through and then
silently dropping every response because the ephemeral-port return rule
was missed.

Security groups already enforce the same reachability constraints,
they're stateful (no separate reverse-rule bookkeeping), and they
support security-group-to-security-group references instead of CIDR
blocks, which is a strictly stronger invariant than a NACL's CIDR-only
matching: an SG rule that says "from sg-app" stays correct even if the
app tier's subnet CIDR changes, where a NACL rule keyed on
`10.0.10.0/24` does not.

## Decision

Use security groups as the sole mechanism for tier-to-tier traffic
control: `sg-alb -> sg-app -> sg-db`, each referencing the previous
tier's security group ID rather than a CIDR
(`modules/network/main.tf`). No NACL rules beyond the AWS default-allow
NACL are configured.

## Consequences

- Half the rule count and no stateless-return-traffic bugs to get wrong.
- Loses defense-in-depth: a security group misconfiguration is no longer
  backstopped by a NACL. This is a real trade-off, not a free win --
  in a production environment I'd want NACLs back as the second layer
  once the SG layer is solid, and I've said so explicitly rather than
  implying this is strictly better in every respect.
- `NET-DB-001` and `NET-DB-002` both inspect security-group-level and
  route-table-level state rather than NACL state, since NACLs no longer
  carry the isolation invariant here.

## Alternatives considered

**Full NACL matrix as originally specified.** Rejected for the
complexity/bug-surface reason above, given that SGs alone already
satisfy every invariant this project's policies actually check.

**NACLs only on the data tier, as a second layer specifically around the
database.** This remains a reasonable extension, but it was left outside the current scope because the existing security-group controls already enforce the project's network invariants.
