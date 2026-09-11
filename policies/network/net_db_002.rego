package sentinel.network.net_db_002

# --- policy metadata (informational) ---
# policy_id: NET-DB-002
# version: 1.0
# severity: critical
# title: Database subnet must not have a default route to an Internet Gateway
#
# This is the cross-resource "graph" invariant: it doesn't trust the
# db_instance's own publicly_accessible flag, it independently checks
# whether the subnet the database actually lives in is reachable via an
# Internet Gateway. Per doc4 finding #3, this rule is intentionally
# scoped to resources whose association graph is statically resolvable
# (route_table canonical resources built from configuration.root_module
# for already-existing infra, or from AWS Config for runtime), NOT from
# resource_changes on brand-new infrastructure where subnet/route-table
# IDs are "(known after apply)". The normalizer omits route_table
# resources it cannot fully resolve rather than emit a partial graph.
#
# input.resources: canonical resources, including route_table entries
#   attributes.routes: [{destination_cidr, target_type, target_id}, ...]
#   attributes.associated_subnet_ids: [...]
# input.db_subnet_map: {db_resource_urn: [subnet_id, ...]}  -- precomputed
#   by the caller from the db_instance's subnet_group, since that
#   relationship itself is a separate (also statically-resolvable) lookup.

deny[msg] {
	some rt_idx
	rt := input.resources[rt_idx]
	rt.resource_type == "route_table"

	some route_idx
	route := rt.attributes.routes[route_idx]
	route.destination_cidr == "0.0.0.0/0"
	route.target_type == "internet_gateway"

	some db_urn
	subnet_ids := input.db_subnet_map[db_urn]
	subnet_ids[_] == rt.attributes.associated_subnet_ids[_]

	msg := sprintf(
		"NET-DB-002 [CRITICAL]: %s's subnet is associated with route table %s, which has a default route to an Internet Gateway",
		[db_urn, rt.resource_urn],
	)
}
