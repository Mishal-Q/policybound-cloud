# 0009. encryption_key_ref as an additive cross-cloud field, not a rename of kms_key_arn

## Context

`DATA-ENC-001` (AWS) checks `kms_key_arn` -- a tested, working field name
that's specifically AWS vocabulary (KMS is an AWS product). Adding Azure
encryption support (`AZURE-DATA-ENC-001`, checking a Key Vault key
reference) raised the question of what field the Azure normalizer should
populate, and whether the existing AWS field should be renamed to
something cloud-neutral first.

## Decision

Add `encryption_key_ref` as a new, additional field on `db_instance` and
`s3_bucket` (AWS) and `azure_storage_account` (Azure), populated
alongside the existing AWS-specific fields, not instead of them.

For AWS: `encryption_key_ref` is set to mirror `kms_key_arn` exactly
(same value, two field names) inside both `desired_state.py` and
`aws_normalizer.py`. `kms_key_arn` itself is completely untouched --
same name, same semantics, same tests, same `DATA-ENC-001` file. For
Azure: `encryption_key_ref` is populated from the Key Vault key URI,
and there is no `kms_key_arn` field on Azure resources at all, since
Azure genuinely has no KMS.

## Consequences

- Zero changes to `DATA-ENC-001` or its test file. The existing 6 tests
  for that policy are untouched, per the explicit instruction not to
  rename a field that's already part of tested, working code.
- `AZURE-DATA-ENC-001` reads `encryption_key_ref`, never `kms_key_arn`
  -- there is nothing for it to read on an Azure resource even if it
  tried, since the Azure normalizer never sets that field.
- Every AWS resource now carries two fields holding the same value
  (`kms_key_arn` and `encryption_key_ref`). That's deliberate
  redundancy, not an oversight -- see the code comment in `schema.py`.
  A resource-specific policy (`DATA-ENC-001`) reads the AWS-specific
  name; a genuinely cross-cloud comparison (if one is ever built) reads
  the semantic name. Two different consumers, two different fields,
  even though today they hold identical values on the AWS side.
- This does NOT imply AWS KMS and Azure Key Vault are equivalent
  services. They have different security models, different pricing,
  different API surfaces. `encryption_key_ref` only asserts "a
  reference to a customer-managed key protecting this resource exists,"
  nothing about how the two key-management systems compare beyond that.

## Alternatives considered

**Rename `kms_key_arn` to `encryption_key_ref` everywhere, single field.**
Explicitly rejected -- this was the original plan before an audit
caught that it would touch 4 already-tested files for a purely cosmetic
portability gain, and the instruction that followed was specific: do not
rename a working, tested AWS field just to make cross-cloud naming
prettier.

**Stuff the Azure Key Vault URI into the existing `kms_key_arn` field
name.** Rejected even more strongly -- a field named after a specific
AWS product holding an Azure value is actively misleading to anyone
reading the canonical schema later, not just untidy.
