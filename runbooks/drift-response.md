# Runbook: responding to a drift PR or governance ticket

## If you got paged for a SECURITY_CRITICAL finding

1. Open the DynamoDB `drift-events` record referenced in the alert.
   Check `resource_urn`, `changed_field`, `old_value`, `new_value`, and
   `policy_id`. This tells you exactly what changed and which Control it
   violates -- you shouldn't need to go look at the AWS console first.
2. Open the remediation PR the Lambda created. It contains the current
   value, the proposed (desired) value, and the policy that triggered it.
   Read it before touching AWS directly -- if the fix is straightforward,
   merging the PR is faster and leaves a clean audit trail; if it's not,
   at least you know what Terraform *thinks* should be true.
3. If the change was legitimate (a real operational need, not an
   accident or an attack), don't just merge and move on. Either revert
   the manual change and follow the proper Terraform PR path, or file an
   exception (see policy-exception-process.md below) so the same finding
   doesn't fire again every sweep.
4. If the change looks like it wasn't made by anyone on the team, treat
   it as a security incident, not a drift event -- escalate per your
   org's incident process. The drift engine only tells you *what*
   changed and *that* it's a problem; it does not attempt to determine
   *who* made an unauthorized change or why.
5. Merge the remediation PR once you've confirmed it's the right fix.
   The Lambda never applies this itself -- see ADR 0006 for why.

## If you got a governance ticket for AUTHORIZED_DRIFT

This means the divergence is covered by a valid, unexpired exception.
No action is required for the drift itself. Do check whether the
exception is close to expiring -- if the underlying need is ongoing,
renew it through the exception process rather than letting it lapse and
have the same resource flip to POLICY_VIOLATING on the next sweep.

## If you got a POLICY_VIOLATING finding (not security-critical)

Same as the SECURITY_CRITICAL flow above, minus the immediate page.
Triage it in your normal review cadence, not necessarily same-day.

## If a finding classified as UNDETERMINED

This means the system didn't have enough evidence to classify it and
deliberately didn't guess. Check:

- Is the desired-state snapshot in S3 stale (did the last `terraform
  apply` actually run the snapshot-write step)?
- Did the OPA evaluation itself error out (check the Lambda's
  CloudWatch logs for the `opa eval` subprocess call in
  `drift/detector/handler.py`)?
- Is the AWS Config data for this resource incomplete or malformed in a
  way the normalizer's `missing_required_fields` check caught?

Fix the underlying data/evaluation problem, then re-trigger the Lambda
manually rather than waiting for the next scheduled sweep.
