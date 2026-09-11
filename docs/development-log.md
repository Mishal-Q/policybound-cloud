# Development notes

Kept as I went, not reconstructed afterward. Numbered by build session,
not calendar day, since this wasn't built on a fixed daily schedule.

## Session 1: scoping

Started from a much larger spec: three real AWS accounts, IAM Identity
Center, a Transit Gateway, fifteen OPA policies, a full stateless-NACL
matrix on top of security groups. Went through it control by control and
asked, for each piece, "does building this teach me anything the
five-policy version doesn't, or is it just more AWS services in the
diagram."

Cut, with reasons written up as ADRs rather than just deleted silently:

- Three accounts -> one account, tag-simulated boundaries (ADR 0001).
  Reason: account creation is pure administrative overhead, not
  governance logic.
- Identity Center -> plain IAM roles (ADR 0004). Reason: the SSO
  instance itself can't be created by Terraform, it's a manual console
  step, which breaks "clone this repo and `terraform apply`."
- Transit Gateway -> removed entirely (ADR 0002). Reason: a hub with one
  spoke isn't demonstrating a hub-and-spoke pattern, it's decoration.
- NACL matrix -> security groups only (ADR 0003). Reason: NACLs are
  stateless, so the original matrix needed a mirrored return-traffic
  rule for every forward rule, which is exactly the kind of thing that's
  easy to get subtly wrong (allow the request, forget the ephemeral-port
  response, silently break the connection). SGs are stateful and support
  SG-to-SG references instead of CIDR blocks, which is strictly better
  for this project's purposes.
- Fifteen policies -> five. Reason: fifteen shallow policies prove I can
  copy a pattern fifteen times. Five policies, one of which (NET-DB-002)
  is a genuine cross-resource graph check, prove the taxonomy and the
  normalization approach actually work. Depth over breadth.

## Session 2: the drift engine core

Built the canonical schema first, before writing either normalizer,
because the whole point of ADR 0007 is that both normalizers have to
agree on the target shape or the exercise is pointless. Wrote
`schema.py` with an explicit `ATTRIBUTE_CONTRACTS` dict per resource
type, so a normalizer that can't populate a required field has a
concrete thing to check against instead of guessing at completeness.

Wrote the classifier (`triage_classifier.py`) with six states instead of
the four I started with. Added `UNDETERMINED` after realizing that
"drift detected, policy evaluation failed" was falling through to a
default branch that looked like a confident answer. A classifier that
picks BENIGN or POLICY_VIOLATING when it doesn't actually know is worse
than one that says "I don't know, someone should look at this" -- see
ADR 0006 for the same reasoning applied to remediation.

Wrote 16 unit tests against the classifier and diff engine before
touching the Rego policies, specifically so I could verify the taxonomy
logic in isolation from OPA. All 16 passed on first run, which felt
suspicious enough that I went back and added the exception-expiry and
unauthorized-approver test cases explicitly, since those were the
easiest branches to get "accidentally correct" without actually
checking. They passed too, but for the right reasons this time
(traced through the logic by hand to confirm, not just re-run).

## Session 3: OPA, and the first real bug

Downloaded a real `opa` binary (v0.68.0) instead of writing Rego I'd
just have to assume worked. First `opa test policies/` run: 5 parse
errors, all from the same mistake -- I'd written `# METADATA` as a plain
descriptive comment header above each policy, not realizing OPA
interprets a comment block starting with exactly that string as a YAML
annotation block it tries to parse. Every one of my "just documentation"
prose comments under that header broke YAML parsing. Renamed the header
to something that isn't a reserved OPA keyword and reran.

Second run: `count(deny) == 1` failed on `test_fail_role_missing_boundary`.
Root cause: `not resource.attributes.permissions_boundary_arn` in
`iam_boundary_001.rego`. I'd assumed `not` meant "this is falsy," the
way it does in Python. In Rego it means "this expression is undefined."
`null` is a real, defined value in Rego -- `not null` is `false`, not
`true`. The missing-boundary case in my fixture had
`permissions_boundary_arn: null`, which the rule was silently treating
as present. Fixed by checking `== null` explicitly instead of relying on
`not`. Wrote this up as ADR 0005 because it's a real, specific
Rego-semantics mistake worth remembering, not a typo.

Also hit a compile error in `net_db_002.rego`: `some db_urn, subnet_ids`
followed by a separate assignment to `subnet_ids` -- Rego's compiler
rejected this as "var subnet_ids declared above" because I was trying to
both destructure it via `some` and assign it via `:=` in the same rule
body. Restructured to only declare `db_urn` via `some` and derive
`subnet_ids` from it with a plain assignment.

After both fixes: 18/18.

## Session 4: exceptions, and the second and third real bugs

Built `remediation/exceptions.py` to load `exceptions.yaml` into the
same `Exception_` dataclass the classifier already expected, specifically
because I'd started writing the "is this exception valid" logic a second
time inside the exceptions loader before catching myself -- if the
loader and the classifier each independently decided what counts as a
valid exception, they could disagree, and they very nearly did (I had
`approver_authorized` computed one way in a draft of the loader and
another way in the classifier's docstring before reconciling them to
one definition, which now lives only in the classifier).

Wrote the CI helper scripts (`normalize_plan_for_ci.py`, `fail_on_deny.py`,
`cost_gate.py`) and then, instead of trusting they worked because they
looked right, ran them against real `opa eval` output.

`fail_on_deny.py` reported "All organizational invariants passed" on an
input I'd deliberately constructed with `publicly_accessible: true` --
a confirmed NET-DB-001 violation that showed up correctly in the raw
`opa eval` JSON but that my script completely missed. The bug: OPA's
`data.sentinel` evaluation nests results two levels deep
(`network.net_db_001.deny`, since the package path is
`sentinel.network.net_db_001`), and my script only checked one level
(`rules.get("deny", [])` directly on the top-level value). Rewrote it as
a recursive search for `deny` keys at any depth instead of assuming a
fixed nesting level. Reran against both a known-fail and a known-pass
input to confirm both directions actually work now, not just the one I
was debugging.

Then tested `cost_gate.py` against the real `exceptions.yaml` file (not
a synthetic fixture -- the actual file this repo ships with) and got a
result I didn't expect: a $38 -> $51 change (34.2% delta, should fail
the 25% threshold) came back as "within threshold or covered by a valid
exception." `exceptions.yaml` does contain one real, currently-valid,
correctly-approved COST-001 exception -- but for a completely different
resource (a one-time S3 data export job, unrelated to whatever I was
testing). The Rego rule's `exception_active` check only looked at
`policy_id == "COST-001"`, with no check on which resource or PR the
exception actually covered. Any valid COST-001 exception, anywhere,
covered every COST-001 evaluation. Fixed by adding `resource_urn`
matching to the exception check (same requirement every other policy's
exception logic already had -- this was the one place I'd left it out),
added a regression test for exactly this scenario, and updated
`cost_gate.py` to require a `--resource-urn` argument rather than
letting it silently run without one.

Final count after all three fixes: 19 OPA tests, 22 pytest tests, all
passing.

## What I'd do next if I kept going

- Get a real `terraform` binary and AWS credentials somewhere and
  actually validate the Terraform, which is the single biggest
  unverified piece of this project right now (see docs/limitations.md).
- Generate the Terraform-plan-JSON normalizer fixtures for real, per
  `tests/fixtures/README.md`, instead of leaving that as a documented
  gap.
- Deploy to a real (single) AWS account, run the actual demo script, and
  fill in the blank rows in `results/RESULTS.md` -- CI wall-clock time
  and classifier accuracy against real synthetic drift events -- with
  real numbers instead of leaving them honestly blank.

## Session 5: full recheck, three more real bugs

Went back through the whole repo specifically tracing actual data flow
between files instead of re-reading each file in isolation and assuming
it was fine on its own -- the kind of check that catches wiring problems
rather than logic problems, since wiring problems only show up when you
follow a value from where it's produced to where it's consumed.

**Bug four: the same `not X` mistake as ADR 0005, in a second file.**
`DATA-ENC-001` had `not resource.attributes.kms_key_arn` in its
db_instance check -- identical mistake to the IAM boundary bug, `null`
being a defined value rather than an absent one. It survived the
original test suite because no fixture isolated `storage_encrypted:
true` combined with `kms_key_arn: null` on its own; the existing
`test_fail_unencrypted_db` fixture had `storage_encrypted: false`, which
triggers a different deny rule entirely and never exercises the
null-check line. Constructed that specific input by hand against `opa
eval` and confirmed `deny` came back empty when it should not have. Also
noticed, while fixing this, that the S3 bucket check only verified the
encryption *algorithm* string equals `aws:kms` and never checked whether
a specific customer key ARN was actually set -- meaning a bucket
defaulting to the AWS-managed `aws/s3` key would pass, which contradicts
what the original spec asked for ("customer KMS key... require aws:kms
with a specific key ARN," not just the algorithm name). Fixed both,
added two regression tests, one per resource type, since they're
independent code paths that could each drift back into the same mistake
separately.

**Bug five: name where an ARN was expected.**
`environments/dev/main.tf` had `config_bucket_arn =
module.logging.log_bucket_name` -- passing the bucket's *name* into a
variable that gets interpolated as `"${var.config_bucket_arn}/*"` inside
an IAM policy statement's `resources` list in `modules/identity/main.tf`.
That produces a string like `sentinel-iac-dev-audit-logs-111111111111/*`
instead of a real ARN. Found by grepping for every place a `_arn`-named
variable was actually assigned and checking the right-hand side wasn't
secretly just an `_name` output -- which it was here, because the
logging module had never exposed an ARN output for the bucket at all,
only its name (needed elsewhere for the AWS Config delivery channel).
Added `log_bucket_arn` as its own output and fixed the assignment.

**Bug six: a whole module that was written but never actually deployed.**
`drift/terraform/main.tf` -- the Lambda, the DynamoDB audit table, both
EventBridge rules -- is complete, internally consistent Terraform. It is
also never referenced anywhere in `environments/dev/main.tf`. Running
`terraform apply` against the only environment this project ships would
never have created any of it. I'd written the module and moved on to the
next piece without ever actually calling it from the environment that's
supposed to use it, and nothing caught that until I went looking for
every `module.drift` reference and found none.

Wiring it in surfaced two more problems immediately, both of the same
kind: things the drift module's variables expected that nothing in the
rest of the codebase actually produced.

- No S3 bucket existed anywhere for the desired-state snapshot
  (`desired_state_bucket_arn`/`_name`) that `drift/detector/handler.py`
  reads from. Added one directly in `environments/dev/main.tf`, and
  because of the bug-four fix above, had to give it its own
  customer-managed KMS key too, or it would fail its own project's
  `DATA-ENC-001` check the moment it got normalized and evaluated like
  any other resource -- which felt like a reasonable consistency check
  in itself, even if it wasn't the point of the exercise.
- `environments/dev/main.tf` was passing a raw
  `var.instance_profile_name` string (a manually-typed name in
  `terraform.tfvars.example`) into the compute module's launch template,
  but no `aws_iam_instance_profile` resource existed anywhere in the
  codebase to actually create that profile. An IAM role by itself can't
  be attached to an EC2 instance; a launch template needs an instance
  profile, which is a separate resource wrapping the role. This would
  have meant either the apply failing outright (referencing a
  non-existent profile) or, if someone created one by hand to make the
  error go away, a permanent manual step nobody documented. Added the
  missing `aws_iam_instance_profile` resource to the identity module,
  wired its name through as a proper module output, and removed the
  now-unnecessary manual variable entirely.

While in there, also wired the drift Lambda's exception handling for
real. It had been left as an honestly-labeled stub
(`lookup_exception=lambda urn, pid: None`, with a comment saying so) --
meaning at runtime, no exception would ever apply, even a correctly
approved one, and every excepted resource would misclassify as
`POLICY_VIOLATING` or `SECURITY_CRITICAL` on the next sweep. Loaded
`remediation/exceptions.py` into the handler for real, packaged
`exceptions.yaml` alongside the Lambda code (see the Makefile's
`lambda-package` target), and added a fail-closed path: if the
exceptions file is missing or fails validation at Lambda cold-start,
every classification becomes `UNDETERMINED` rather than silently
behaving as if no exceptions exist -- an exceptions file that failed to
load isn't the same fact as "there are no exceptions," and treating them
the same would misclassify every currently-approved exception's resource
as a fresh violation. Tested this end to end: imported the handler
module directly, pointed it at the real `exceptions.yaml`, and confirmed
`lookup_exception` correctly resolved the one real COST-001 exception in
that file and correctly returned `None` for an unrelated resource.

Final count after this session: 21 OPA tests (two new), 22 pytest tests
(unchanged), 43 total, all passing.

## Session 6: AWS gap closure, Azure cross-cloud layer

Started from an explicit instruction to close the AWS-side governance
gaps found in the invariant audit (region, tags) before writing any
Azure code, and to select roughly 6 cross-cloud invariants based on what
those gaps actually showed rather than the original plan's assumptions.

**Region and tags, for real.** Added `region`, `tags`, and
`encryption_key_ref` as canonical fields in `schema.py`. Immediately hit
an ordering bug while wiring them into `desired_state.py`: the
completeness check (`missing_required_fields`) ran BEFORE the new fields
were populated, which -- now that region/tags are part of every type's
required contract -- would have made every single resource look
incomplete and get silently dropped. Caught this before it ever touched
a test, by re-reading my own diff before running anything, and moved the
population code above the check instead of below it. Same fix applied
to `aws_normalizer.py` preemptively, having just made the mistake once.

Wrote `GOV-REGION-001` and `GOV-TAG-001` deliberately without checking
`resource_type` at all in either rule -- both read `attributes.region`/
`attributes.tags` generically off any canonical resource. This wasn't
obviously the right call going in; it became one once I noticed it
meant these two policies would evaluate Azure resources with zero
changes, which turned into the strongest single piece of evidence in
the whole Azure exercise (see below).

For `GOV-TAG-001`'s required tag set, went back to `environments/dev/main.tf`
and `modules/database/main.tf` to check what's actually tagged today
rather than inventing a "reasonable-sounding" set. Found
`ManagedBy`/`owner`/`cost-center` applied everywhere via
`local.common_tags`, but `data-classification` only ever applied to the
RDS instance specifically. Scoped the policy to match: base three tags
required everywhere, `data-classification` required only on
`db_instance`/`s3_bucket`. Wrote every "presence" check in this file
using `object.get(dict, key, "__MISSING__")` with a sentinel default,
specifically instead of `not dict.key`, because `not` on a possibly-null
value is the exact bug class already found twice this project
(IAM-BOUNDARY-001, then DATA-ENC-001) -- decided to structurally avoid
the whole bug class in new code rather than rely on remembering to write
`== null` correctly every single time.

**Encryption field, without touching what already worked.** Added
`encryption_key_ref` alongside (not instead of) `kms_key_arn`, mirrored
for AWS resources, populated from Key Vault URIs for Azure ones.
Confirmed `DATA-ENC-001` and its 6 existing tests needed zero changes --
ran them before and after this addition specifically to prove that, not
just assumed it from reading the diff.

**Azure normalizer and policies.** Built `azure/detector/azure_normalizer.py`
against documented `azurerm` provider field names, explicitly flagged in
its own docstring that the exact JSON nesting hasn't been confirmed
against real Terraform or Azure output, since neither was available.
Wrote four Azure Rego policies. `AZURE-NET-001` took longer than the
other three because it isn't a port of `NET-DB-002` -- AWS's
deny-by-default network posture means NET-DB-002 checks for the
PRESENCE of a forbidden route, but Azure's NSG model is priority-ordered
and more permissive by default, so the Azure equivalent has to check for
the ABSENCE of an effective blocking rule, accounting for the
possibility that a Deny rule exists but is shadowed by an earlier,
lower-priority-number Allow rule for the same traffic. Wrote a
regression test for exactly that shadowing case
(`test_fail_deny_rule_present_but_shadowed_by_earlier_allow`) because a
naive "does any Deny rule exist" check would have passed it, and that
would have been a worse false negative than not writing the check at
all.

**The actual cross-cloud proof.** Rather than just assert in a doc that
`GOV-REGION-001`/`GOV-TAG-001` are portable, ran real Azure normalizer
output through both files via `opa eval` with zero modification to
either Rego file, and watched them correctly flag a `westeurope`
resource as disallowed and a resource missing `cost-center` as
non-compliant. This is the one piece of evidence in the whole Azure
layer that's actually a demonstrated fact rather than an architecture
claim resting on an assumed-correct normalizer.

**A directory-creation mistake, caught immediately.** Tried to scaffold
`azure/modules/{network,identity,compute,data,monitoring}` with one
`mkdir -p` using brace expansion. The shell in this environment doesn't
expand braces (likely `/bin/sh`/dash, not bash), so it silently created
one literal directory named `{network,identity,compute,data,monitoring}`
instead of five real ones. Caught by listing the directory right after
and seeing the literal brace-string sitting there, before writing any
files into the wrong place. Removed it, recreated the five directories
explicitly, one `mkdir` per directory.

**An HCL syntax mistake, also caught immediately.** Wrote a Terraform
variable block as `variable "vnet_cidr" { type = string, default = "..." }`
on one line with a comma -- not valid HCL, variable block arguments go
on separate lines, no comma. There's no `terraform` binary in this
environment to catch this the normal way, so it was only caught by
re-reading the file I'd just written before moving on, not by any tool.
Fixed by rewriting with each argument on its own line, correct syntax.

**A genuine circular dependency, found and left honestly documented,
not silently hidden.** Wiring `azure/environments/student-demo/main.tf`,
the Key Vault access policy needed the storage account module's managed-
identity principal ID as an output, which only exists once the storage
account is created -- but the storage account module's own
customer-managed-key association needs that same access policy to exist
first. This is a real, well-known Azure Terraform ordering problem, not
a mistake unique to this code, and the standard fix is a two-apply
sequence. Rather than write something that looks like it resolves the
cycle but wouldn't actually work at `terraform apply` time, left a
detailed comment explaining the problem and the real fix, in the file
itself and cross-referenced in `docs/limitations.md`. This felt like
the more important instinct to keep than making the file look finished.

Final count after this session: 48 OPA tests (21 AWS baseline + 13 new
AWS governance + 14 new Azure), 37 pytest tests (22 AWS baseline + 6 new
AWS normalizer + 9 new Azure normalizer), 85 total, all passing. Zero
AWS resources, zero Azure resources, created anywhere. No git commit,
no git push -- this repository was never a git repository to begin with,
confirmed at the start of this session before touching anything.
