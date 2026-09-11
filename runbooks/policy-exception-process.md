# Runbook: requesting a policy exception

Exceptions exist because sometimes there's a legitimate, temporary
reason to deviate from a Control -- a one-time data export that needs a
bigger instance for a few days, say. They are not a way to make an
inconvenient policy go away permanently. If you find yourself renewing
the same exception every month, the actual fix is probably to change the
Control or the infrastructure, not to keep renewing.

## How to request one

1. Add an entry to `remediation/exceptions.yaml` with every required
   field filled in: `id`, `resource_urn`, `policy_id`, `reason`,
   `expires_at`, `approved_pr_number`, `approver_team`. Missing any field
   fails CI (`remediation/exceptions.py:load_exceptions` raises
   `ExceptionValidationError`) -- there's no way to merge a
   partially-filled exception.
2. Open a PR with that change. CODEOWNERS should route it to whichever
   team is listed as the approver for that policy in
   `remediation/exceptions.py:POLICY_APPROVER_TEAMS` (currently:
   security for everything, finance additionally allowed for COST-001).
   If you're not on that team, you can't self-approve regardless of what
   `status: approved` says in the file -- `approver_authorized` is
   computed from your actual team, not taken on faith from the YAML.
3. Set `expires_at` to the shortest reasonable window. There's no
   enforced maximum in code right now, which is a gap worth knowing
   about (see docs/limitations.md) -- until an automated check exists,
   the approving team is the actual enforcement mechanism for keeping
   exception windows short.
4. Two policies can never be excepted, full stop, regardless of who
   approves it: `NET-DB-002` (database subnet reachable via an internet
   gateway) and `DATA-ENC-001` (unencrypted persistent storage). If your
   request is against one of these, the answer is to fix the
   infrastructure, not to request an exception -- see ADR entries and
   `remediation/exceptions.py` for why these two are treated
   differently from the others.

## What happens when it expires

Nothing automatic reverts the underlying resource. The exception simply
stops covering the drift on the next classification run, and whatever
the divergence actually is falls back to being classified as
`POLICY_VIOLATING` or `SECURITY_CRITICAL` on its own merits (see
`drift/classifier/triage_classifier.py:_classify_violation`). If the
need is still real, renew it deliberately through the same PR process --
don't let it silently lapse and then be surprised by a page.
