# Architecture

## Two loops, not one

There's the actual infrastructure the workload runs on, and there's the
control plane that governs it. They're separate loops that happen to
share the same underlying AWS resources.

**Infrastructure data flow:**

```
internet -> ALB (public subnet, sg-alb) -> app tier (sg-app, ASG) -> RDS (sg-db, data subnet, no IGW route)
```

Nothing unusual here on purpose -- see docs/scope.md and ADR 0002/0003
for why the network layer stays this simple. The interesting part of
this project isn't the workload, it's what watches it.

**Control-plane flow:**

```
git push
  -> CI (terraform validate, checkov, opa test, cost delta check)
  -> merge
  -> terraform apply
  -> desired-state.json written to S3 (normalized canonical snapshot,
     see drift/detector/desired_state.py)
  -> AWS Config + CloudTrail start observing the real resources
  -> [fast path] CloudTrail API call matches an EventBridge rule
       (modules/logging/main.tf: aws_cloudwatch_event_rule.security_mutations)
       -> drift Lambda fires immediately
  -> [sweeper path] every 6 hours, drift Lambda fires on schedule
       regardless of whether anything happened
  -> drift Lambda: fetch AWS Config state -> normalize (aws_normalizer.py)
       -> diff against desired-state.json (diff.py)
       -> for each divergence: evaluate against OPA (same policies as CI)
       -> classify (triage_classifier.py)
  -> write every event to DynamoDB (drift-events table)
  -> route by classification:
       OUT_OF_SCOPE / BENIGN        -> log only
       AUTHORIZED_DRIFT             -> governance ticket
       POLICY_VIOLATING             -> remediation PR, human merges
       SECURITY_CRITICAL            -> remediation PR + alert, human merges
       UNDETERMINED                 -> alert, human investigates
```

The same OPA policy bundle runs in the CI step and inside the drift
Lambda. That's only possible because both paths normalize into the same
canonical schema first (see ADR 0007) -- a policy never has to know
whether it's looking at a Terraform plan or an AWS Config snapshot.

## Why the classifier has six states, not "compliant/non-compliant"

Early on the classifier only distinguished drift from no-drift. That's
not enough information to act on, because drift and policy violation
are different questions:

- A resource can drift (actual state != desired state) without
  violating any policy -- someone bumped an instance type from
  `t3.small` to `t3.medium` by hand, which is unauthorized *process*
  but not a security problem.
- A resource can violate policy without having drifted from Terraform at
  all, if the Terraform itself was written wrong and deployed that way.

So the pipeline is: detect divergence -> evaluate policy -> check for a
valid exception -> classify by risk. `UNDETERMINED` exists because a
classifier that's forced to pick BENIGN or POLICY_VIOLATING when its
evidence is incomplete (a stale desired-state snapshot, a normalizer
that couldn't populate a required field, an OPA evaluation that errored)
is a classifier that lies confidently under uncertainty. Failing closed
to UNDETERMINED and alerting a person is the honest answer.

## Where the Control abstraction lives

`policy-metadata/catalog.yaml` ties together, for each of the five
Controls: the policy ID and version, severity, which resource type it
scopes to, where its evidence comes from (Terraform plan vs. AWS
Config), which lifecycle phases it runs in, its remediation mode, and
whether it can be excepted at all (two of the five explicitly cannot --
see `remediation/exceptions.py`). This is what lets the audit trail in
DynamoDB, the CI output, and this document all refer to "NET-DB-001
version 1.0" as one identity instead of three different things that
happen to share a filename.
