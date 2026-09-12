# Sentinel-IaC

A policy-governed, drift-aware control plane for AWS infrastructure.
Terraform defines what the infrastructure *should* look like. AWS Config
and CloudTrail observe what it *actually* looks like. A normalizer turns
both into the same canonical shape, a diff engine compares them, and OPA
policies re-evaluated against that same canonical shape decide whether
any divergence is benign, authorized, a policy violation, or security
critical. Nothing gets auto-remediated -- the system proposes a fix as a
pull request, a person merges it.

## Why this exists

The starting question was: Terraform guarantees what you *intended* to
deploy. It says nothing about whether the infrastructure stays that way
after someone -- or something -- changes a security group in the console
six weeks later. Checkov and most CSPM tools check a Terraform plan or a
point-in-time snapshot; they don't continuously re-check the same
organizational rules against both the desired and the observed state
using one shared definition of "compliant."

That's the actual thing this project builds: one set of policies,
written once, evaluated identically whether the input is a Terraform
plan in CI or a live AWS Config snapshot at 3am. See
`docs/decisions/0007-normalized-canonical-schema.md` for why that's
harder than it sounds and what it took to get there.

## Current project status

The repository now has a reproducible local validation baseline across the AWS-oriented and Azure layers.

Verified locally:

- Terraform formatting, initialization, and validation for `environments/dev`
- Terraform formatting, initialization, and validation for `drift/terraform`
- Terraform formatting, initialization, and validation for `azure/environments/student-demo`
- 28 drift-engine Python tests passing
- 9 Azure detector tests passing
- 48 OPA policy tests passing with OPA 0.68.0

That gives a current automated test baseline of 85 passing Python and OPA tests.

The GitHub Actions workflow is credential-free for validation. It does not require an AWS account or Azure login to run Terraform validation, OPA tests, or Python tests.

## Quick start

The repository can be validated without AWS or Azure credentials.

Create a virtual environment and install the Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r drift/detector/requirements.txt
python -m pip install -r scripts/requirements.txt
python -m pip install pytest
```

Run the Python tests:

```bash
python -m pytest -q
```

Expected result: `37 passed`.

Validate the Terraform configurations:

```bash
terraform -chdir=environments/dev init -backend=false -input=false
terraform -chdir=environments/dev validate

terraform -chdir=drift/terraform init -backend=false -input=false
terraform -chdir=drift/terraform validate

terraform -chdir=azure/environments/student-demo init -backend=false -input=false
terraform -chdir=azure/environments/student-demo validate

terraform fmt -check -recursive
```

The policy tests use pre-Rego-v1 syntax and are currently verified with OPA 0.68.0. OPA 1.x requires a Rego syntax migration before running this policy set directly.

With OPA 0.68.0 installed:

```bash
opa test policies azure/policies -v
```

Expected result: `PASS: 48/48`.

## Cloud execution status

The AWS implementation is used as the broader infrastructure and governance model, but a real AWS deployment is not required to reproduce the project tests.

The Azure `student-demo` environment was deployed to a live Azure subscription and then destroyed after validation. The live run verified the Storage Account security settings, data-tier NSG rule, resource tags, resource-group-scoped RBAC assignment, Resource Graph normalization, and OPA evaluation against observed Azure state.

The live Azure validation was performed using a constrained student subscription. The environment was destroyed after testing, with the resource group removed and Terraform state left empty. The protected Key Vault was left in Azure soft-deleted state after teardown as expected.

## Limitations

Local Terraform validation is still kept as a fast check, but the student demo has also completed a real Azure apply and teardown. The live run exposed several issues that local validation could not catch, including Storage provider authentication behavior, the Key Vault purge-protection requirement for customer-managed keys, and a Resource Graph field-shape mismatch in the normalizer.

The repository also does not claim that LocalStack is equivalent to AWS or that credential-free CI proves real cloud behavior.

See `docs/limitations.md` for the detailed limitations and assumptions.

## License

See `LICENSE`.
