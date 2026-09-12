# Known limitations

These aren't hedges, they're the actual boundaries of what this system
does. If any of these are the part you're most interested in, they're
also the most obvious places to extend the project.

- **Terraform validation is local, not deployment validation.** The three
  Terraform roots (`environments/dev`, `drift/terraform`, and
  `azure/environments/student-demo`) pass formatting, provider
  initialization with the backend disabled, and `terraform validate`.
  This checks configuration syntax and provider-schema compatibility,
  but does not demonstrate that the infrastructure can be successfully
  planned or deployed against a live cloud account.

- **Fixtures for the Terraform-plan normalizer don't exist yet.** The
  Rego policy tests (34/34 for AWS alone, run against a real `opa`
  binary -- see results/RESULTS.md for the current combined AWS+Azure
  total) use inline
  canonical-schema fixtures, which prove the policies themselves are
  correct. What's missing is a fixture proving `desired_state.normalize()`
  correctly turns *real* `terraform show -json` output into that
  canonical shape -- see `tests/fixtures/README.md` for the remaining fixture work and
  the reason synthetic provider output is not used as a substitute.
- **AWS Config coverage is scoped to five resource types on purpose**
  (security groups, RDS instances, S3 buckets, IAM roles, route
  tables) -- the ones the five existing Controls evaluate. Adding a
  sixth Control means extending `ATTRIBUTE_CONTRACTS` in
  `drift/detector/schema.py`, both normalizers, and the Config recorder's
  `resource_types` list together. This is deliberate, not an oversight
  (see ADR 0007), but it does mean the drift engine has zero visibility
  into any resource type outside that list.
- **The normalizer drops resources it can't fully populate rather than
  guessing.** This is the right failure mode (a partially-populated
  resource that looks compliant on its missing fields is worse than not
  reporting it), but it means a normalizer bug shows up as *silence*,
  not an error. There's no current alerting on "the normalizer skipped N
  resources this run". This missing visibility is a known gap and would need to be addressed
  before using the detector in a production environment.
- **`NET-DB-002`'s cross-resource graph check only works on already-
  existing infrastructure.** On a brand-new deployment where the VPC,
  subnets, and database are all being created in the same
  `terraform apply`, the subnet and route-table IDs in
  `resource_changes` are `(known after apply)` and the association graph
  can't be resolved from plan JSON alone. The policy is written to
  operate on the canonical `route_table` resources the normalizer
  produces, which the normalizer should only emit when the graph is
  actually resolvable. This specific case has not yet been tested against a real
  "everything created together" plan, so the normalizer's omission
  behavior for unresolved graphs remains unverified.
- **Cost delta calculation (`COST-001`) needs a real baseline to be
  meaningful.** On a from-scratch environment with a $0 baseline, the
  percentage-delta math is undefined (division by zero), which is why
  there's a separate absolute-ceiling fallback rule for that case. The
  absolute ceiling is a placeholder value in the current config and
  needs a real number chosen for whatever environment this actually
  runs in.
- **This is a reference implementation, not a CSPM replacement.** It
  doesn't compete with Wiz, Prisma Cloud, or AWS Security Hub on
  coverage, scale, or maturity. What it demonstrates is one way to wire
  desired state, observed state, organizational policy, exceptions, and
  human-approved remediation into a single coherent pipeline with an
  auditable identity for every decision. That's a narrower and more
  specific claim than "cloud security platform," and it's the actual
  claim being made here.
- **Single-region, single-account.** No cross-region drift detection,
  no cross-account governance beyond what's tag-simulated. See ADR 0001.

## Azure layer

- **Live Azure behavior has now been verified for the student-demo path.** The environment was deployed to a real Azure subscription and then destroyed. The live run verified the Storage Account security settings, data-tier NSG rule, resource tags, resource-group-scoped RBAC assignment, Resource Graph observation and normalization, and OPA evaluation against the observed canonical state. The environment was not left running after validation.

- **The Key Vault CMK dependency was verified during the live Azure run.** The storage-account customer-managed-key association was sequenced after the required Key Vault access policy, and the deployment completed successfully. The live run also showed that customer-managed-key use requires Key Vault purge protection in this configuration.

- **Azure-specific Terraform behavior was exercised against Azure APIs.** The live run exposed Storage provider authentication behavior and the Key Vault purge-protection requirement. The Storage diagnostic setting configuration also deployed successfully. These findings are now reflected in the Azure environment configuration and live-validation record.

- **The Azure normalizer has now been tested against observed live Azure Resource Graph output.** The live run exposed a field-shape mismatch in the Storage Account encryption data: Azure returned `keyvaultproperties.currentVersionedKeyIdentifier`, which differed from the original fixture assumption. The normalizer was corrected to use the observed field, the fixture was updated, and the Azure normalizer tests pass. The Terraform-plan/desired-state normalization path remains fixture-based.

- **`AZURE-IDENTITY-001` preserves the governance intent of `IAM-BOUNDARY-001`, not the AWS mechanism.** Azure RBAC scoping and AWS permission boundaries are different controls. ADR 0011 documents this distinction.

- **Logging-enabled-per-resource was deliberately deferred** for both AWS and Azure. The final governance model retains six cross-cloud invariants and does not claim this seventh candidate as implemented.
