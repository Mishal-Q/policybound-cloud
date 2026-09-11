# 0012. AZURE-NET-001 checks for presence of a deny rule, not absence of an allow route

## Context

`NET-DB-002` (AWS) checks for the PRESENCE of something forbidden: a
route table entry sending 0.0.0.0/0 to an Internet Gateway, associated
with a subnet a database lives in. This works because AWS's default
network posture is deny-by-default -- nothing reaches the internet
without an explicit route enabling it, so finding that route is finding
the problem.

Azure's default NSG posture is different: without any rules at all, an
NSG still has Azure's own default rules, which are more permissive
inbound-from-VNet and deny-inbound-from-internet only implicitly through
default rules that can be overridden. A subnet with an NSG that has zero
custom rules is not automatically as locked-down as an AWS subnet with
no IGW route -- it depends on what default/custom rules are actually in
effect and their relative priority.

## Decision

`AZURE-NET-001` checks for the PRESENCE of an effective Deny rule for
Inbound traffic from Internet, at a priority that actually takes effect
(not shadowed by an earlier, lower-priority-number Allow rule for the
same traffic -- NSG rules evaluate in priority order and stop at first
match). Absence of that specific effective Deny rule is the failure
condition, which is the logical inverse of what `NET-DB-002` checks for.

## Consequences

- `azure_net_001.rego` contains real priority-ordering logic
  (`has_effective_internet_deny_rule`, `exists_lower_priority_allow`)
  that `net_db_002.rego` has no equivalent of, because AWS route tables
  don't have a "priority" concept the way Azure NSG rules do -- a route
  table either has the forbidden route or it doesn't, there's no
  ordering to reason about.
- This is real, additional complexity that exists specifically because
  the platforms' default security postures differ, not because the
  Azure policy author (this project) chose to make it more
  sophisticated for its own sake.
- The test suite includes a case specifically for a Deny rule that
  exists but is shadowed by an earlier Allow rule
  (`test_fail_deny_rule_present_but_shadowed_by_earlier_allow`) --
  included because a naive "does any Deny rule exist" check would pass
  this genuinely-misconfigured case, which would be a worse false
  negative than not having the check at all.

## Alternatives considered

**Copy NET-DB-002's route-table-presence logic onto Azure UDRs.**
Rejected -- Azure UDRs and NSGs are two separate mechanisms (routing vs.
firewall), and neither alone is Azure's real analog of "does this
subnet have a path to the internet." NSGs were chosen as the more direct
match for the actual governance question (can inbound internet traffic
reach this data tier), which UDRs don't answer on their own.
