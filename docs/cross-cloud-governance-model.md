# Cross-cloud governance model

**Read this before reading anything else in this file**: the Azure `student-demo` implementation has now been exercised against a real Azure subscription. The live run covered deployment, Azure Resource Graph observation, canonical normalization, the four Azure OPA policies used by the environment, an adversarial mutation of observed state, and teardown. This does not mean every Azure-native control or every possible Azure behavior has been tested. In particular, native Azure Policy enforcement, external network reachability, PIM behavior, and the Terraform-plan/desired-state normalization path remain outside the live validation. See the "what was actually executed" table at the very end of this document for the precise distinction.

## The six invariants

For each: cloud-independent requirement, AWS implementation, AWS evidence, Azure implementation, Azure-native control, OPA role, what's testable locally, what needs real Azure, exact evidence to capture, and the portability limitation.

---

### 1. Public exposure

| Field | Detail |
|---|---|
| Cloud-independent requirement | A resource holding customer data must not be directly reachable from the public internet. |
| AWS implementation | `NET-DB-001` (`policies/network/net_db_001.rego`) -- checks `db_instance.publicly_accessible`. `modules/database/main.tf` hardcodes this false. |
| AWS evidence | 3 OPA tests, `net_db_001_test.rego`, run against a real `opa` binary (v0.68.0). |
| Azure implementation | `AZURE-PUBLIC-001` (`azure/policies/data/azure_public_001.rego`) -- checks `azure_storage_account.public_network_access_enabled`. `azure/modules/data/main.tf` hardcodes this false. |
| Azure-native control | Azure Policy has a built-in definition auditing/denying public network access on Storage Accounts -- genuinely redundant with OPA here, both are viable. |
| OPA role | Fully appropriate on both clouds -- this is the cleanest 1:1 mapping of the six. |
| Testable locally | Yes, completely -- 3 real OPA tests exist for the Azure side too (`azure_public_001_test.rego`), passing. |
| Needs real Azure | Native Azure Policy enforcement remains untested. The actual observed Storage Account Resource Graph shape has now been verified through a real deployment and observation run. |
| Exact evidence to capture | Real Azure: attempt to deploy a Storage Account with `public_network_access_enabled = true`, show either Azure Policy or the OPA-based CI gate rejecting it, in that specific order (policy config existing is not the same claim as a resource actually being blocked). |
| Portability limitation | Field name and default-value semantics need verification against current `azurerm` provider docs -- not assumed stable, since no real `terraform init` against the azurerm provider was possible here. |

---

### 2. Network reachability (data-tier isolation)

| Field | Detail |
|---|---|
| Cloud-independent requirement | A resource holding customer data must have no network path reachable from the public internet, independent of what the resource itself claims about its own exposure. |
| AWS implementation | `NET-DB-002` (`policies/network/net_db_002.rego`) -- cross-resource: checks for the PRESENCE of a route-table entry sending `0.0.0.0/0` to an Internet Gateway, associated with a data-tier subnet. |
| AWS evidence | 3 OPA tests, `net_db_002_test.rego`. |
| Azure implementation | `AZURE-NET-001` (`azure/policies/network/azure_net_001.rego`) -- checks for the ABSENCE of an effective Deny rule (accounting for NSG rule priority ordering) blocking inbound internet traffic to a data-tier NSG. **Structurally inverted logic from NET-DB-002, not a port of it** -- see ADR 0012. |
| Azure-native control | Azure Policy can audit NSG rule configuration, but the "does this subnet have a path to the internet" determination genuinely needs the priority-aware logic this policy implements -- a simpler native check would miss the rule-shadowing case this project's own test suite specifically covers. |
| OPA role | Necessary, not just useful -- Azure's NSG priority-ordering semantics (first-match-wins) require real logic a simple presence/absence policy definition can't express as precisely. |
| Testable locally | Yes -- 4 OPA tests, including a genuinely non-trivial case (`test_fail_deny_rule_present_but_shadowed_by_earlier_allow`) proving a Deny rule that exists but is shadowed by an earlier, lower-priority-number Allow rule for the same traffic is correctly still flagged as a failure. |
| Needs real Azure | Deploying a data-tier subnet both with and without an effective blocking NSG rule, confirming real Azure network behavior actually matches the rule-priority model this policy assumes. |
| Exact evidence to capture | Real Azure: two deployments (blocked, not blocked), actual network reachability test from a public endpoint against each, not just policy-evaluation output. |
| Portability limitation | This is the clearest genuine architectural difference of the six. AWS requires an explicit opt-in before anything reaches the internet (deny-by-default); Azure's default posture is more permissive and depends on which default/custom NSG rules are in effect and their relative priority. The two policies check for opposite conditions (presence vs. absence) because the platforms' defaults are opposite. This is a research finding, not a limitation to apologize for -- see ADR 0012. |

---

### 3. Identity / privilege ceiling

| Field | Detail |
|---|---|
| Cloud-independent requirement | A privileged identity's effective reach must be capped by an organization-controlled boundary, independent of what its own assigned policy claims to grant. |
| AWS implementation | `IAM-BOUNDARY-001` (`policies/identity/iam_boundary_001.rego`) -- checks that non-admin IAM roles reference the approved permission boundary policy ARN. |
| AWS evidence | 4 OPA tests, `iam_boundary_001_test.rego`. |
| Azure implementation | `AZURE-IDENTITY-001` (`azure/policies/identity/azure_identity_001.rego`) -- checks that RBAC role assignments aren't scoped broader than the resource group (subscription-scope denied except for the Owner role). |
| Azure-native control | Azure Policy's `deny` effect can restrict role-assignment scope; Microsoft Entra Privileged Identity Management (PIM) adds time-bound elevation, a concept AWS's model doesn't have an equivalent of either. |
| OPA role | Appropriate for the scope check itself; PIM's time-bound elevation isn't something a static policy evaluation captures, and isn't claimed to be covered here. |
| Testable locally | Yes -- 4 OPA tests, including a genuine positive case (Owner exempted at subscription scope, mirroring how `IAM-BOUNDARY-001` exempts `privilege=admin` roles). |
| Needs real Azure | PIM interaction remains out of scope. The deployed resource-group-scoped Contributor assignment was checked against the live Azure RBAC state and the identity policy passed against the observed canonical state. |
| Exact evidence to capture | Real Azure: assign a non-Owner role at subscription scope, show it flagged; assign the same role at resource-group scope, show it passing. |
| Portability limitation | **This is not a portable mechanism, only a portable intent.** AWS permission boundaries work by policy intersection; Azure RBAC has no equivalent construct. `AZURE-IDENTITY-001` is a genuinely separate control addressing the same governance goal by the only mechanism Azure actually offers -- see ADR 0011. Do not read the existence of both policies as proof the underlying access-control models are equivalent; they are not. |

---

### 4. Customer-managed encryption at rest

| Field | Detail |
|---|---|
| Cloud-independent requirement | Persistent storage holding customer data must be encrypted with a customer-managed key, not a cloud-provider-managed default. |
| AWS implementation | `DATA-ENC-001` (`policies/data/data_enc_001.rego`) -- checks RDS `storage_encrypted` + non-null `kms_key_arn`; S3 `encryption_algorithm == "aws:kms"` + non-null `kms_key_arn`. **Completely unmodified by this work** -- see ADR 0009. |
| AWS evidence | 6 OPA tests, `data_enc_001_test.rego` (unchanged from before this session). |
| Azure implementation | `AZURE-DATA-ENC-001` (`azure/policies/data/azure_data_enc_001.rego`) -- checks `azure_storage_account.encryption_key_ref` is non-null. Uses the new cloud-neutral `encryption_key_ref` field, never `kms_key_arn` (Azure has no KMS). |
| Azure-native control | Azure Policy has a built-in definition requiring customer-managed keys on Storage Accounts. |
| OPA role | Appropriate on both clouds. |
| Testable locally | Yes -- 3 OPA tests for the Azure side, plus 2 new pytest tests (`test_normalize_plan_storage_account_with_cmk`, `test_normalize_observed_storage_account`) proving the normalizer correctly populates `encryption_key_ref` from a Key Vault key reference. |
| Needs real Azure | Testing the Microsoft-managed-key case as a negative live deployment remains outside this run. The customer-managed-key path was deployed successfully against a real Azure subscription, and the resulting Resource Graph state exposed the versioned Key Vault key identifier used by the normalizer. |
| Exact evidence to capture | Real Azure: both encryption states, actual `az storage account show` output for each, not just Terraform plan output. |
| Portability limitation | Genuinely the most portable concept of the six (both platforms have a real customer-managed-key mechanism), but the two key-management systems (KMS, Key Vault) are different products with different security models, pricing, and API surfaces. `encryption_key_ref` asserts only "a reference to a customer-managed key exists," nothing about service equivalence beyond that -- see ADR 0009. |

---

### 5. Approved deployment regions

| Field | Detail |
|---|---|
| Cloud-independent requirement | Resources must be deployed only within an approved set of geographic regions/locations. |
| AWS implementation | `GOV-REGION-001` (`policies/governance/gov_region_001.rego`) -- **new this session**, closing a gap the AWS-side audit found (region was previously only a Terraform provider default, never policy-checked). Reads `attributes.region`, checked against `policies/governance/config.rego`'s `approved_regions` set. Does not check `resource_type` at all. |
| AWS evidence | 5 OPA tests, `gov_region_001_test.rego`, including one that feeds an Azure-typed resource through the same rule (see below). |
| Azure implementation | **The same file, unmodified.** No separate Azure Rego policy exists for this invariant because none was needed. |
| Azure-native control | Azure Policy's built-in "Allowed locations" definition is arguably a stronger native fit than anything OPA offers here -- worth using natively in a real deployment even with OPA also checking it. |
| OPA role | Demonstrated as genuinely portable, not just claimed -- see "what was actually executed" below for the concrete proof. |
| Testable locally | Yes, and this is the strongest local evidence in the whole set: real Azure normalizer output (`azure_normalizer.normalize_plan()`, not a hand-built fixture) was piped directly into `gov_region_001.rego` with zero modification to that file, and it correctly flagged a `westeurope` resource as outside the approved region set. |
| Needs real Azure | Deploying to a disallowed region, confirming Azure Policy's native "Allowed locations" definition blocks it independent of the OPA-side check. |
| Exact evidence to capture | Real Azure: deployment attempt to a disallowed region, native Azure Policy block, separately also show the OPA-side CI gate would have caught it pre-deployment. |
| Portability limitation | None found. This is the cleanest result of the whole exercise -- genuinely the same code, same logic, same file, both clouds. The asymmetry worth noting is that Azure's native mechanism is arguably better-suited to this specific check than a custom OPA rule is, which is a point in Azure's favor, not a limitation. |

---

### 6. Required governance metadata (tags)

| Field | Detail |
|---|---|
| Cloud-independent requirement | Every governed resource must carry a minimum set of ownership/cost/classification metadata. |
| AWS implementation | `GOV-TAG-001` (`policies/governance/gov_tag_001.rego`) -- **new this session**, closing a second gap the audit found. Base set (`ManagedBy`, `owner`, `cost-center`) required on any resource type; `data-classification` required additionally on `db_instance`/`s3_bucket` only, based on actual repository tagging convention, not an invented requirement. Case-sensitive exact-match, documented as a deliberate decision. |
| AWS evidence | 8 OPA tests, `gov_tag_001_test.rego`, including a dedicated case-sensitivity test and a distinct-empty-vs-missing test. |
| Azure implementation | **The same file, unmodified**, same as region. |
| Azure-native control | Azure Policy's "require tag" built-in definitions are a close native equivalent. |
| OPA role | Same portable-by-construction result as region. |
| Testable locally | Yes, same real-normalizer-output proof as region: the same Azure `azurerm_storage_account` plan fed into `gov_tag_001.rego` unmodified correctly flagged a missing `cost-center` tag. |
| Needs real Azure | Deploying a resource missing a required tag, confirming detection against real Azure Resource Graph output rather than a synthetic fixture. |
| Exact evidence to capture | Real Azure: untagged resource, actual `az resource show` output, OPA evaluation result against the real normalized output. |
| Portability limitation | Lowest of the six. Both platforms have first-class key-value tags with materially similar semantics. The only real caveat: Azure tag keys have a 512-character limit and slightly different reserved-character rules than AWS tags, neither of which affects the four required keys used here. |

---

## What was actually executed

| Claim | Status |
|---|---|
| GOV-REGION-001 / GOV-TAG-001 Rego logic is correct | **Verified.** The governance policy tests were run against OPA 0.68.0 and passed. |
| The four Azure Rego policies correctly evaluate canonical fixtures | **Verified.** The Azure policy tests passed against canonical fixtures. |
| The Azure student-demo Terraform environment can deploy to a real Azure subscription | **Verified.** The environment was successfully deployed to a real Azure subscription. |
| The deployed Azure resources can be observed through Azure Resource Graph | **Verified.** A live Resource Graph response was captured for the student-demo resources. |
| The Azure normalizer handles the observed Resource Graph shape | **Verified for the observed resource types.** The live run exposed a Storage Account encryption field-shape mismatch. The normalizer was corrected to use `keyvaultproperties.currentVersionedKeyIdentifier`, and the normalizer test fixture was updated accordingly. |
| Live canonical Azure state can be evaluated by the Azure OPA policies | **Verified.** The observed state was normalized into the canonical schema and evaluated by the four Azure policy namespaces with no findings. |
| The Azure identity policy matches the deployed RBAC scope | **Verified.** The live resource-group-scoped Contributor assignment was checked against Azure RBAC state and the identity policy passed. |
| The Azure network policy matches the deployed data-tier NSG configuration | **Verified for the observed configuration.** The live data-tier NSG contained the expected inbound Internet deny rule and the policy evaluation passed. This does not constitute an external reachability experiment. |
| The Azure encryption policy matches the deployed customer-managed-key configuration | **Verified.** The live Storage Account used a Key Vault customer-managed key and the normalized encryption reference was populated. |
| The Azure public-access policy detects an insecure mutation | **Verified.** A local mutation of the live observed canonical Storage Account state setting `public_network_access_enabled=true` was rejected by `AZURE-PUBLIC-001`. |
| Azure-native Policy enforcement was tested | **Not tested.** The experiment evaluated the project's OPA policies. It did not attempt to prove that Azure Policy itself blocked an insecure deployment. |
| External network reachability was tested | **Not tested.** No public-endpoint reachability experiment was performed against the data-tier configuration. |
| PIM behavior was tested | **Not tested.** PIM remains outside the scope of this implementation. |
| Microsoft-managed encryption was deployed as a negative live case | **Not tested.** The live run validated the customer-managed-key path; it did not deploy a separate Microsoft-managed-key negative case. |
| Disallowed-region native Azure Policy enforcement was tested | **Not tested.** The project did not perform a native Azure Policy block experiment for an invalid region. |
| Missing-tag native Azure Policy enforcement was tested | **Not tested.** The live run observed the deployed tags, but did not intentionally deploy an untagged resource to test native Azure Policy enforcement. |
| Terraform-plan / desired-state normalization was validated against live `terraform show -json` output | **Not yet verified.** The live experiment validated the observed Azure Resource Graph path. The desired-state/plan normalization path remains fixture-based. |
| Azure resources were destroyed after validation | **Verified.** Terraform reported 17 resources destroyed. |
| The Azure resource group was removed | **Verified independently.** `az group exists --name sentinel-iac-demo-rg` returned `false`. |
| Terraform state was empty after teardown | **Verified.** `terraform state list` returned no resources. |
| The protected Key Vault was permanently purged | **Not claimed.** The Key Vault remained soft-deleted with purge protection enabled, with Azure reporting its scheduled purge date. |
| Python tests pass after the current implementation changes | **Verified.** The full Python test suite completed with 37/37 tests passing after the live-state field correction and documentation changes. |
| The repository OPA policy suite passes after the current changes | **Verified.** OPA 0.68.0 completed the AWS and Azure policy suite with 48/48 tests passing. The repository currently uses pre-Rego-v1 syntax, so the globally installed OPA 1.20.2 is not a compatible evaluator without a syntax migration. |
| Terraform configuration validation passes after the current changes | **Verified.** `terraform validate` succeeded for `environments/dev`, `drift/terraform`, and `azure/environments/student-demo`, and `terraform fmt -check -recursive` completed cleanly after formatting the local student-demo tfvars file. |

The evidence above distinguishes the live Azure student-demo path from controls that were deliberately left outside the experiment. In particular, successful OPA evaluation against observed state is not presented as proof of native Azure Policy enforcement or external network reachability.
