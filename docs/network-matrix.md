# Network matrix

Security-group-based, not NACL-based -- see ADR 0003 for why.

| Source SG | Destination SG | Port | Protocol | Notes |
|---|---|---|---|---|
| `0.0.0.0/0` | `sg-alb` | 443 | TCP | Only rule in the whole design that uses a CIDR block instead of an SG reference, because the internet isn't a security group. |
| `sg-alb` | `sg-app` | 8080 | TCP | SG-to-SG reference, not a CIDR. If the app subnet's CIDR ever changes, this rule doesn't need to. |
| `sg-app` | `sg-db` | 5432 | TCP | Same reasoning. `NET-DB-001` doesn't check this rule directly -- it checks the db_instance's own `publicly_accessible` flag. `NET-DB-002` is the one that independently verifies the subnet-level route, in case the SG rule alone isn't the full story. |

## Route tables

| Tier | Default route (`0.0.0.0/0`) |
|---|---|
| Public | -> Internet Gateway |
| App | -> NAT Gateway, only if `enable_nat_gateway = true` (default `false` for dev/demo -- see `modules/network/variables.tf`) |
| Data | **none.** No route to IGW, no route to NAT. This is the resource `NET-DB-002` inspects. |

## Why NET-DB-001 and NET-DB-002 are both necessary

`NET-DB-001` trusts the database resource's own `publicly_accessible`
attribute. `NET-DB-002` doesn't trust anything the database says about
itself -- it independently walks the subnet and route table the
database actually sits in and checks whether that subnet has a path to
an Internet Gateway at all. A database could theoretically have
`publicly_accessible = false` set correctly while still sitting in a
subnet that, through a separate misconfiguration, has an IGW route --
`publicly_accessible` in RDS controls whether AWS assigns a public IP,
not whether the network path exists. `NET-DB-002` is what catches that
gap. This is also why it's the one policy this project intentionally
calls a "cross-resource graph invariant" instead of a single-attribute
check.
