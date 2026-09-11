package sentinel.cost.cost_001

# --- policy metadata (informational) ---
# policy_id: COST-001
# version: 1.0
# severity: medium
# title: PR-introduced monthly cost delta must not exceed 25%
#
# Deliberately NOT a flat dollar ceiling ($50 good / $51 bad has no
# actual reasoning behind it). Instead this evaluates the percentage
# delta the PR introduces relative to the current baseline, with a soft
# absolute ceiling kept only as a safety backstop for near-zero baselines
# where a percentage alone is meaningless.
#
# input.cost.baseline_monthly_usd: current environment monthly cost
# input.cost.projected_monthly_usd: cost after this PR (from Infracost)
# input.cost.absolute_ceiling_usd: safety backstop for the environment
# input.cost.resource_urn: identifies which PR/change this cost gate run
#   is for. An earlier version of this rule checked only policy_id when
#   deciding whether an exception covered a cost violation, which meant
#   ANY currently-valid COST-001 exception -- approved for a completely
#   different resource -- would silently cover every other PR's cost
#   gate too. Caught by testing cost_gate.py against the real
#   exceptions.yaml fixture: a $51-vs-$38 (34%) delta that should have
#   failed instead passed, because an unrelated, legitimately-approved
#   exception for a different S3 bucket was enough to satisfy
#   exception_active. Fixed by requiring exc.resource_urn to match the
#   specific thing being evaluated, same as every other policy's
#   exception check already does.
# input.exceptions: list of {policy_id, resource_urn, approved,
#   approver_authorized, expires_at_epoch}
# input.context.evaluation_time_ns: injected by the caller (CI runner or
#   fixture), NEVER read from the system clock inside this policy --
#   see doc4 finding #4. This keeps `opa test` deterministic forever.

delta_pct := pct {
	baseline := input.cost.baseline_monthly_usd
	projected := input.cost.projected_monthly_usd
	baseline > 0
	pct := ((projected - baseline) / baseline) * 100
}

deny[msg] {
	delta_pct > 25
	not exception_active
	msg := sprintf(
		"COST-001 [MEDIUM]: monthly cost delta is %.1f%% (baseline $%.2f -> $%.2f), exceeds 25%% threshold",
		[delta_pct, input.cost.baseline_monthly_usd, input.cost.projected_monthly_usd],
	)
}

deny[msg] {
	input.cost.baseline_monthly_usd == 0
	input.cost.projected_monthly_usd > input.cost.absolute_ceiling_usd
	not exception_active
	msg := sprintf(
		"COST-001 [MEDIUM]: no baseline cost to compare against; projected $%.2f exceeds absolute ceiling $%.2f",
		[input.cost.projected_monthly_usd, input.cost.absolute_ceiling_usd],
	)
}

exception_active {
	some e
	exc := input.exceptions[e]
	exc.policy_id == "COST-001"
	exc.resource_urn == input.cost.resource_urn
	exc.approved == true
	exc.approver_authorized == true
	exc.expires_at_epoch > (input.context.evaluation_time_ns / 1000000000)
}
