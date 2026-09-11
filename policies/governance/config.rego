package sentinel.governance.config

# --- policy metadata (informational) ---
# Central place for governance configuration values so they're not
# scattered as string literals inside individual policy files. Both
# GOV-REGION-001 and any future region-aware policy read from here
# instead of hardcoding "us-east-1" themselves.

approved_regions := {"us-east-1", "us-west-2"}
