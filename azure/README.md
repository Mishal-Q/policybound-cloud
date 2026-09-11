# Azure cross-cloud validation layer

This directory tests whether the project's governance model -- canonical schema, normalization, and OPA policy evaluation -- can be applied beyond the AWS implementation. It is not intended to reproduce the full AWS architecture on a second cloud.

See `docs/cross-cloud-governance-model.md` for the mapping between the AWS and Azure controls.

## Current status

The Azure policy and normalization layers have been tested locally:

- 14 Azure-specific OPA policy tests pass with OPA 0.68.0.
- 9 Azure normalizer tests pass with pytest.
- `azure/environments/student-demo` passes `terraform fmt -check`.
- `terraform init -backend=false` completes successfully.
- `terraform validate` reports a valid configuration.

These checks validate the Terraform configuration and local policy logic. They do not prove that the environment will deploy successfully to Azure.

No live Azure deployment has been completed yet.

## Layout

    azure/
      detector/       Azure resource data -> shared canonical schema
      policies/       Azure-specific OPA controls and tests
      modules/        network, identity, data, and monitoring
      environments/
        student-demo/ small Azure environment used for real-cloud validation

The compute module is intentionally excluded from the current student demo. See `modules/compute/README.md` for the scope decision.

## Student demo

`environments/student-demo` is the real-cloud validation target. It provides a small environment for testing the controls against actual Azure resources without turning the Azure layer into a second full landing-zone implementation.

The Terraform configuration includes the dependency corrections made during local review, including the Key Vault encryption-key wiring.

## Remaining Azure validation

The next stage is a controlled deployment to an Azure student subscription.

The live validation will:

1. Deploy the `student-demo` environment.
2. Confirm the expected resources and security configuration in Azure.
3. Collect observed Azure resource data.
4. Normalize that data through `azure_normalizer.py`.
5. Evaluate the relevant OPA controls against the normalized state.
6. Exercise at least one intentional policy violation and record the resulting rejection or finding.
7. Destroy the deployed resources after the experiment.

Until that run is completed, the project distinguishes between locally validated Terraform and live Azure-verified behavior.
