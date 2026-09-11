package sentinel.cost.cost_001

test_pass_under_threshold {
	count(deny) == 0 with input as {
		"cost": {"baseline_monthly_usd": 145.00, "projected_monthly_usd": 168.00, "absolute_ceiling_usd": 200, "resource_urn": "pr/200"},
		"exceptions": [],
		"context": {"evaluation_time_ns": 1893456000000000000},
	}
}

test_fail_over_threshold {
	count(deny) == 1 with input as {
		"cost": {"baseline_monthly_usd": 38.00, "projected_monthly_usd": 51.00, "absolute_ceiling_usd": 200, "resource_urn": "pr/184"},
		"exceptions": [],
		"context": {"evaluation_time_ns": 1893456000000000000},
	}
}

test_fail_over_threshold_but_exception_expired {
	count(deny) == 1 with input as {
		"cost": {"baseline_monthly_usd": 38.00, "projected_monthly_usd": 51.00, "absolute_ceiling_usd": 200, "resource_urn": "pr/184"},
		"exceptions": [{
			"policy_id": "COST-001",
			"resource_urn": "pr/184",
			"approved": true,
			"approver_authorized": true,
			"expires_at_epoch": 1893455999,
		}],
		"context": {"evaluation_time_ns": 1893456000000000000},
	}
}

test_pass_over_threshold_with_valid_exception {
	count(deny) == 0 with input as {
		"cost": {"baseline_monthly_usd": 38.00, "projected_monthly_usd": 51.00, "absolute_ceiling_usd": 200, "resource_urn": "pr/184"},
		"exceptions": [{
			"policy_id": "COST-001",
			"resource_urn": "pr/184",
			"approved": true,
			"approver_authorized": true,
			"expires_at_epoch": 1893456100,
		}],
		"context": {"evaluation_time_ns": 1893456000000000000},
	}
}

# Regression test for a real bug: an earlier version of exception_active
# only checked policy_id, so a valid COST-001 exception approved for a
# completely different PR/resource silently covered this one too. Caught
# by running scripts/cost_gate.py against the actual exceptions.yaml
# fixture and seeing a 34% cost delta pass when it should have failed.
test_fail_unrelated_valid_exception_does_not_cover_this_resource {
	count(deny) == 1 with input as {
		"cost": {"baseline_monthly_usd": 38.00, "projected_monthly_usd": 51.00, "absolute_ceiling_usd": 200, "resource_urn": "pr/999"},
		"exceptions": [{
			"policy_id": "COST-001",
			"resource_urn": "pr/184",
			"approved": true,
			"approver_authorized": true,
			"expires_at_epoch": 1893456100,
		}],
		"context": {"evaluation_time_ns": 1893456000000000000},
	}
}
