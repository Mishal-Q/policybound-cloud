# 0008. Region and tags are canonical fields on every resource type, populated centrally

## Context

The AWS-side invariant audit found that region restriction and required
tagging were never implemented as executable policy -- only enforced by
Terraform convention (region hardcoded in provider blocks, tags applied
via `var.tags` merges with nothing checking they landed). Building
`GOV-REGION-001` and `GOV-TAG-001` required first deciding where in the
canonical schema these two facts should live, since neither existed as
a normalized attribute before this work.

Two real options existed: add `region`/`tags` to each resource type's
extractor function individually (`_extract_db_instance`,
`_extract_security_group`, etc. in `desired_state.py`), or add them once
in `normalize()`'s main loop, after the type-specific extractor runs but
using the same `change["change"]["after"]` dict every branch already has
access to.

## Decision

Add `region` and `tags` centrally in each normalizer's main loop
(`desired_state.py:normalize()`, `aws_normalizer.py:normalize_one()`),
not per-extractor. Both fields are now required in every entry of
`schema.py:ATTRIBUTE_CONTRACTS`, AWS and Azure alike.

This has to happen in the code BEFORE the `missing_required_fields`
check runs, not after -- both fields are now part of the completeness
contract, so checking completeness before adding them would make every
resource look incomplete and get silently dropped. This exact ordering
mistake happened while writing this code, was caught before it ever ran
against a test, and is called out in both files' comments so it doesn't
happen again in a future extractor.

## Consequences

- `GOV-REGION-001` and `GOV-TAG-001` don't check `resource_type` at all
  -- they read `attributes.region`/`attributes.tags` generically, which
  is what let the exact same two Rego files evaluate real Azure
  normalizer output correctly and unmodified (verified directly, not
  just claimed -- see the final implementation report).
- Every future resource type (AWS or Azure) added to `ATTRIBUTE_CONTRACTS`
  must supply region and tags or that resource silently doesn't
  normalize at all. This is a deliberate hard requirement, not an
  oversight -- a resource with no region on record shouldn't be treated
  as "compliant," it should fail to normalize and surface as
  `UNDETERMINED` further up the pipeline.

## Alternatives considered

**Add region/tags per-extractor.** Rejected -- five (now eight, with
Azure) extractor functions would each need to remember to do this
identically, which is exactly the kind of duplication that drifted out
of sync once already in this project (the IAM boundary logic almost
diverging between the loader and the classifier, mentioned in an earlier
session). One central point, one place to get it right.
