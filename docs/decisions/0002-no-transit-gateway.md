# 0002. No Transit Gateway

## Context

An earlier version of the network design included a Transit Gateway
sitting in the security-logging account, with the workload VPC attached
to it, and a TGW route table that propagated the public and app tier
CIDRs but deliberately did not propagate the data tier -- the idea being
that database isolation would hold even at the hub level, not just
inside the VPC.

That's a real invariant worth demonstrating, but only if there's
actually a hub with more than one spoke. With a single VPC and no second
account to connect it to, a Transit Gateway isn't connecting anything --
it's a network primitive sitting between a VPC and itself.

## Decision

No Transit Gateway. Route-table-based isolation lives entirely inside
the one VPC: the data-tier route table
(`modules/network/main.tf:aws_route_table.data`) has no 0.0.0.0/0 route
at all, to the Internet Gateway or otherwise. `NET-DB-002` checks this
route table directly.

## Consequences

- TGW per-attachment and per-GB charges are avoided entirely.
- The "isolation holds even at the hub level" story from the original
  design isn't demonstrated, because there's no hub. What's
  demonstrated instead is arguably a cleaner version of the same
  invariant: the data-tier route table has no path outside the VPC,
  full stop, and `NET-DB-002` verifies that directly by inspecting the
  route table's routes rather than inspecting TGW route propagation.
- If this project's target-state architecture (multiple VPCs, multiple
  accounts) is ever actually built, the same `NET-DB-002` rule extends
  to TGW route tables without changes -- a route table is a route table
  in the canonical schema (`drift/detector/schema.py`) regardless of
  whether the underlying AWS resource is a VPC route table or a TGW
  route table. That was a genuine design goal of writing NET-DB-002
  against a canonical `route_table` type instead of hardcoding
  `aws_route_table`.

## Alternatives considered

**Keep TGW with a single spoke, purely to demonstrate the pattern.**
Rejected. A TGW that connects a VPC to nothing is a diagram decoration,
not an architecture decision, and doc reviewers who know AWS will
recognize it as such.
