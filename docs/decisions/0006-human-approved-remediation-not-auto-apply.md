# 0006. Remediation is a proposed PR, not an automatic apply

## Context

Once the drift detector classifies something as `POLICY_VIOLATING` or
`SECURITY_CRITICAL`, there are two ways to act on it: have the Lambda
generate and apply a Terraform change directly, or have it open a pull
request describing the proposed fix and wait for a person to merge it.

Automatic remediation is faster to react but has an obvious failure
mode: if the classifier is wrong -- misclassifies a legitimate
maintenance change as a violation, or the normalizer produces a bad
canonical resource from malformed AWS Config data -- an auto-apply
system doesn't just log an incorrect finding, it changes production
infrastructure based on that incorrect finding. Given the whole point of
this project is to reduce the gap between desired and actual state, an
automated system that can *introduce* unwanted state changes on a false
positive is working against its own goal.

## Decision

The drift Lambda never calls `terraform apply`. When a divergence is
classified as `POLICY_VIOLATING` or `SECURITY_CRITICAL`, the system's
job stops at producing a structured remediation proposal (current value,
desired value, violated policy, evidence) and opening a pull request
that a person has to review and merge before anything changes.

## Consequences

- Mean-time-to-remediation is bounded by human availability, not system
  speed. For `SECURITY_CRITICAL` findings this is mitigated by pairing
  the PR with a page/alert (see `triage_classifier.ACTIONS`), not by
  removing the human step.
- A misclassification produces an incorrect PR, which a reviewer can
  reject, rather than an incorrect infrastructure change that already
  happened.
- This is also why the classifier has an explicit `UNDETERMINED` state
  rather than defaulting to the nearest guess when evidence is
  incomplete -- the whole design assumes a human is in the loop to
  investigate `UNDETERMINED` cases, so there's no pressure to force a
  confident-sounding wrong answer out of incomplete data.

## Alternatives considered

**Auto-apply for `BENIGN`/`AUTHORIZED_DRIFT` only, human approval for
the rest.** This is close to what's actually implemented, except
`BENIGN` and `AUTHORIZED_DRIFT` don't get *any* infrastructure action --
they're log-only and governance-ticket respectively, because both
represent cases where nothing needs to change (the drift is either
irrelevant or already sanctioned). There was never a case in this design
where auto-apply made sense, since by construction the only states that
produce a remediation action are the ones where a human review is
exactly the point.
