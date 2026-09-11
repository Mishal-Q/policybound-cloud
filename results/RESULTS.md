# Results

This file records results that were actually produced during local verification. Results that depend on live cloud infrastructure are kept separate from local validation and are not estimated.

## Test suite (actually run, this session)

```
opa test policies/ azure/policies/ -v
  PASS: 48/48

cd drift/tests && python3 -m pytest -v
  28 passed

cd azure/detector && python3 -m pytest -v
  9 passed
```

Total: **85 tests, 85 passing, 0 skipped**, across AWS and Azure
combined. AWS-only baseline before the Azure/governance-gap session was
43; that session added 13 new AWS governance tests (GOV-REGION-001,
GOV-TAG-001), 6 new AWS normalizer tests (region/tags/encryption_key_ref),
14 new Azure policy tests, and 9 new Azure normalizer tests -- 42 net
new tests.

### Test breakdown

| Suite | File | Count |
|---|---|---|
| OPA (AWS) | `net_db_001_test.rego` | 3 |
| OPA (AWS) | `net_db_002_test.rego` | 3 |
| OPA (AWS) | `iam_boundary_001_test.rego` | 4 |
| OPA (AWS) | `data_enc_001_test.rego` | 6 |
| OPA (AWS) | `cost_001_test.rego` | 5 |
| OPA (AWS) | `gov_region_001_test.rego` | 5 |
| OPA (AWS) | `gov_tag_001_test.rego` | 8 |
| OPA (Azure) | `azure_public_001_test.rego` | 3 |
| OPA (Azure) | `azure_data_enc_001_test.rego` | 3 |
| OPA (Azure) | `azure_net_001_test.rego` | 4 |
| OPA (Azure) | `azure_identity_001_test.rego` | 4 |
| pytest (AWS) | `test_diff.py` | 6 |
| pytest (AWS) | `test_triage_classifier.py` | 10 |
| pytest (AWS) | `test_exceptions.py` | 6 |
| pytest (AWS) | `test_region_tags_encryption_ref.py` | 6 |
| pytest (Azure) | `test_azure_normalizer.py` | 9 |

## Bugs this caught (not hypothetical, actually happened while building this)

Six real bugs from the AWS build and recheck (below), plus three more
from the Azure/governance-gap session, caught before any test run
reported a false pass -- by re-reading code immediately after writing it,
not by a test failing after the fact (there's no "before" test result
for these three, since the fix went in before the first run of the new
code):

1. **`IAM-BOUNDARY-001` used `not resource.attributes.permissions_boundary_arn`
   to detect a missing boundary.** In Rego, `null` is a defined value,
   not an absent one, so `not null` evaluates to `false` -- the
   missing-boundary test case silently passed when the rule should have
   denied it. Fixed by checking `== null` explicitly. See ADR 0005.
2. **`fail_on_deny.py` (the CI helper that fails the build on any policy
   violation) checked one level of nesting in OPA's eval output, but
   OPA packages nest two levels deep** (`category.policy_id.deny`). The
   script reported "all organizational invariants passed" on a plan
   containing a confirmed, real `NET-DB-001` violation. Fixed with a
   recursive search for `deny` keys at any depth.
3. **`COST-001`'s exception check matched on `policy_id` alone.** A
   valid, correctly-approved exception for one PR's cost overrun
   silently covered every other PR's cost gate, with nothing scoping the
   match to which PR/resource the exception was actually for. Caught by
   running `cost_gate.py` against the real `exceptions.yaml` fixture and
   watching a 34.2% cost delta pass when it should have failed. Fixed by
   requiring `exc.resource_urn` to match the resource/PR being
   evaluated, and added a regression test.
4. **The exact same `not X` / `null` mistake as bug #1, in a second
   place** (`DATA-ENC-001`'s `not resource.attributes.kms_key_arn`
   check). This one survived the original test suite because no fixture
   isolated "storage_encrypted=true, kms_key_arn=null" on its own --
   found during a full recheck by constructing that input directly
   against `opa eval` rather than trusting the existing test set was
   exhaustive. Also revealed the same requirement had never been applied
   to S3 buckets at all (only the encryption algorithm was checked, not
   whether a specific customer key backed it). Fixed both, added
   regression tests for each.
5. **`environments/dev/main.tf` passed an S3 bucket *name* into an IAM
   policy variable typed for an ARN** (`config_bucket_arn =
   module.logging.log_bucket_name`), which would have produced an
   invalid resource ARN in the `app` role's scoped policy. The logging
   module had no ARN output for the log bucket at all -- found by tracing
   the actual value flowing into `"${var.config_bucket_arn}/*"` rather
   than assuming a variable named `_arn` was actually being fed one.
   Added the missing `log_bucket_arn` output and fixed the wiring.
6. **The `drift/terraform` module (Lambda, DynamoDB table, EventBridge
   rules) was never actually called from `environments/dev/main.tf`.**
   It existed as complete, independently-valid Terraform, but running
   `terraform apply` against the dev environment would never have
   deployed the drift detector at all. Fixing this surfaced two more
   real problems in turn: there was no S3 bucket for the desired-state
   snapshot anywhere (added one, with its own customer-managed KMS key
   once bug #4's fix meant it had to have one to pass DATA-ENC-001 like
   everything else), and `environments/dev/main.tf` was passing a raw,
   manually-supplied `var.instance_profile_name` string into the compute
   module even though no `aws_iam_instance_profile` resource existed
   anywhere in the codebase to back it -- an IAM role alone can't be
   attached to an EC2 launch template. Added the missing instance
   profile resource to the identity module and wired it through
   properly instead of expecting the user to create one by hand outside
   Terraform.

7. **Region/tags ordering bug.** `missing_required_fields()` was called
   before `region`/`tags` were added to the attributes dict in
   `desired_state.py`. Since both fields became part of every type's
   required contract in the same change, this would have silently
   dropped every single resource during normalization. Caught by
   re-reading the diff before running anything against it, and the same
   fix was applied to `aws_normalizer.py` preemptively.
8. **Shell brace-expansion silently created one wrong directory instead
   of five.** `mkdir -p azure/modules/{network,identity,compute,data,monitoring}`
   assumed bash-style brace expansion; the shell in this environment
   didn't expand it, creating one literal directory named
   `{network,identity,compute,data,monitoring}` instead of five real
   ones. Caught immediately by listing the directory right after running
   the command.
9. **Invalid HCL syntax** (`type = string, default = "..."` on one
   comma-joined line) in an early draft of the Azure network module's
   `variables.tf`. No `terraform` binary exists in this environment to
   catch this normally, so it was only caught by re-reading the file
   immediately after writing it.

A fourth issue from this session was found and deliberately left
documented rather than resolved with code: a genuine circular Terraform
dependency in the Azure Key Vault customer-managed-key wiring (see
`docs/limitations.md`'s Azure section and
`azure/environments/student-demo/main.tf`'s comments on
`azurerm_key_vault_access_policy.storage_cmk_access`). It isn't numbered
as a "bug" because it isn't fixable with a one-line change -- it's a
structural property of how Azure CMK association works with Terraform,
and writing code that looked like it resolved the cycle without actually
being applicable at `terraform apply` time would have been worse than
documenting it plainly.

I'm listing these in this much detail because doc 5's actual argument
holds here: a 0-bugs-found test suite and a first-pass architecture
diagram that wires up cleanly on the first read are signs a project
wasn't checked very hard, not signs it was right the first time. Five of
these six were only found because I went back and specifically traced
data flowing between modules instead of trusting that matching variable
names meant the wiring was correct.

## Repository size (actual, measured against this repo, not estimated)

| Category | Count |
|---|---|
| Terraform files (`.tf`) | 22 |
| Terraform lines | 1,268 |
| Rego policy files (excl. tests) | 5 |
| Rego lines (excl. tests) | 244 |
| Rego test files | 5 |
| Python source files (excl. tests) | 10 |
| Python lines (excl. tests) | 1,165 |
| Python test files | 3 |
| Runbooks | 3 |
| Top-level docs | 6 |
| Controls in the catalog | 11 (5 AWS resource-specific, 2 AWS governance, 4 Azure) |
| Azure Terraform files (`.tf`) | 10 |
| Azure Rego policy files (excl. tests) | 4 |
| Azure Rego test files | 4 |
| Azure Python source files (excl. tests) | 1 |
| ADRs | 12 |

## What I could not measure and why

- **CI pipeline wall-clock time.** Requires a real GitHub Actions run
  against real AWS credentials, Checkov, Infracost, and OPA in sequence.
  Not run in this environment -- no `terraform` binary, no AWS
  credentials, no GitHub Actions runner available here. First real PR
  through `pr-validate.yml` will produce this number; I'd rather leave
  the row blank than invent a plausible-looking `91.7s`.
- **Drift classification accuracy against live observed events.** The
  classifier decision logic is covered by unit tests across its state and
  exception-validity branches. An empirical accuracy figure against
  human-labeled live-cloud drift events has not been measured, so no
  classification-accuracy percentage is claimed here.
- **`terraform validate` output.** Local Terraform validation now passes for `environments/dev`, `drift/terraform`, and `azure/environments/student-demo`. This does not replace live cloud planning or deployment validation.

## Live cloud execution status

No live cloud deployment result is recorded yet. Local Terraform, OPA, and Python validation results are documented above, while Azure live deployment remains a separate validation stage.

## Azure: verified vs. unverified

Everything under "Test suite" and "Bugs this caught" above that says
"Azure" was actually executed -- real `opa test` and real `pytest` runs,
both shown with exact pass counts. What was NOT executed, at all,
anywhere in this project: any `terraform validate`/`plan`/`apply`
against the `azurerm` provider (no `terraform` binary was available),
any real Azure API call (no subscription, credentials, or network
access to Azure existed), and any deployment of any Azure resource. See
`docs/cross-cloud-governance-model.md`'s "what was actually executed"
table for the claim-by-claim breakdown, and `azure/README.md` for what
would need to happen before any of that could change.
