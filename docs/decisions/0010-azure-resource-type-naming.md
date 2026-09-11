# 0010. Azure resources get their own canonical resource_type strings, not AWS ones

## Context

Four of the six cross-cloud invariants are resource-specific (public
exposure, network reachability, identity/privilege, encryption). Each
needs the Azure normalizer to emit a `resource_type` string that some
Rego policy checks against. The question: should an Azure Storage
Account normalize to `resource_type: "s3_bucket"` (reusing the existing
AWS canonical type, since both are "the bucket-shaped data resource" in
some loose sense), or get its own distinct type name?

## Decision

Azure resources get their own `resource_type` strings entirely:
`azure_storage_account`, `azure_network_security_group`,
`azure_role_assignment` -- added to `schema.py:CANONICAL_RESOURCE_TYPES`
alongside, not instead of, the five existing AWS types.

The two invariants that genuinely don't care about resource type at all
(`GOV-REGION-001`, `GOV-TAG-001`) don't check `resource_type` in their
Rego logic, so they apply to any of the eight types uniformly -- that's
where the real cross-cloud portability claim lives, demonstrated by one
shared file working against both clouds' output, not by pretending an
S3 bucket and a Storage Account are the same kind of resource.

## Consequences

- `AZURE-PUBLIC-001`, `AZURE-NET-001`, `AZURE-IDENTITY-001`, and
  `AZURE-DATA-ENC-001` are four new, separate Rego files in
  `azure/policies/`, each in an `azure_sentinel.*` package (not
  `sentinel.*`), evaluating Azure-specific resource types. None of them
  are "the Azure version of" an existing AWS file in the sense of
  sharing code -- `AZURE-NET-001` in particular has genuinely inverted
  logic from `NET-DB-002` (see ADR on that specific point, and the
  comment at the top of `azure_net_001.rego`).
- This avoids a subtler problem than just naming: an AWS `s3_bucket`'s
  `ATTRIBUTE_CONTRACTS` entry requires `encryption_algorithm` and
  `public_access_block`, fields an Azure Storage Account's provider API
  doesn't have in that shape at all. Reusing the AWS type name would
  have meant either fudging Azure data into an AWS-shaped contract or
  making the AWS contract's required fields optional to accommodate
  Azure -- both worse than just giving Azure its own contract entry.

## Alternatives considered

**Reuse AWS type names for loosely-similar Azure resources.** Rejected
for the reasons above -- it would have made `DATA-ENC-001` (which checks
`resource_type == "s3_bucket"`) either silently start evaluating Azure
resources it was never designed for, or need an AWS-specific guard added
to a file that previously didn't need one. Either way, touches tested
code to accommodate a resource type it wasn't written for.
