package sentinel.network.net_db_002

test_pass_db_subnet_not_reachable_via_igw {
	count(deny) == 0 with input as {
		"resources": [{
			"resource_urn": "aws:us-east-1:111111111111:route_table/rtb-data",
			"resource_type": "route_table",
			"attributes": {
				"routes": [{"destination_cidr": "0.0.0.0/0", "target_type": "nat_gateway", "target_id": "nat-1"}],
				"associated_subnet_ids": ["subnet-data-a"],
			},
			"metadata": {"managed_by": "sentinel-iac"},
		}],
		"db_subnet_map": {"aws:us-east-1:111111111111:db_instance/app_db": ["subnet-data-a"]},
	}
}

test_fail_db_subnet_has_igw_default_route {
	count(deny) == 1 with input as {
		"resources": [{
			"resource_urn": "aws:us-east-1:111111111111:route_table/rtb-misconfigured",
			"resource_type": "route_table",
			"attributes": {
				"routes": [{"destination_cidr": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": "igw-1"}],
				"associated_subnet_ids": ["subnet-data-a"],
			},
			"metadata": {"managed_by": "sentinel-iac"},
		}],
		"db_subnet_map": {"aws:us-east-1:111111111111:db_instance/app_db": ["subnet-data-a"]},
	}
}

test_pass_igw_route_on_unrelated_subnet {
	# Public-tier route table legitimately has an IGW default route --
	# it just must not be associated with a subnet the database lives in.
	count(deny) == 0 with input as {
		"resources": [{
			"resource_urn": "aws:us-east-1:111111111111:route_table/rtb-public",
			"resource_type": "route_table",
			"attributes": {
				"routes": [{"destination_cidr": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": "igw-1"}],
				"associated_subnet_ids": ["subnet-public-a"],
			},
			"metadata": {"managed_by": "sentinel-iac"},
		}],
		"db_subnet_map": {"aws:us-east-1:111111111111:db_instance/app_db": ["subnet-data-a"]},
	}
}
