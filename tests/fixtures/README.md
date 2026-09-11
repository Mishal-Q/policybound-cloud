# Test fixtures

The policy tests use canonical-schema fixtures directly inside the Rego test files. This keeps policy behavior isolated from Terraform-plan parsing and makes failures easier to diagnose.

Current coverage:

- AWS policy logic is covered by 34 OPA tests.
- Azure policy logic is covered by 14 OPA tests.
- The combined OPA baseline is 48 passing tests.
- Python tests cover the drift engine and Azure normalizer separately.

Raw Terraform plan fixtures are not yet included here. That means the project currently verifies the policy layer and normalizer logic independently, but does not yet include an end-to-end fixture proving that real `terraform show -json` output is transformed into the expected canonical resource shape.

A future fixture should be generated from a minimal Terraform plan in a controlled environment, stored under the relevant category in `tests/fixtures/`, and exercised through `desired_state.normalize()` in a dedicated normalizer test. Synthetic provider output is intentionally avoided because it would not prove compatibility with the real Terraform JSON structure.

## fail_public_db.tf

```hcl
resource "aws_db_instance" "app_db" {
  identifier          = "fixture-fail-public-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = true
  storage_encrypted   = true
  skip_final_snapshot = true
  username            = "fixture"
  password            = "fixture_only_not_real"
}
```

## pass_private_db.tf

Same as above with `publicly_accessible = false`.

Run:

```bash
terraform init
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > fail_public_db.tf.json
```
