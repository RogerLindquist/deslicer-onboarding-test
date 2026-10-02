# Enrollment Configuration Specification
# File permissions MUST be 0600 (owner read/write only)
#
# This file is used for zero-touch agent enrollment via Deployment Server.
# Place your enrollment token in local/enrollment.conf on the Deployment Server.
# See docs/SECURE_ENROLLMENT_PLAN.md for the full enrollment architecture.

[enrollment]
token = <string>
# Required. Enrollment token from the Deslicer AI portal.
# Format: dsle_enroll_<signed-JWT>
# Tokens are time-limited (default 30 days) and host-count limited.
# Revocable from the portal at any time.
# This token can ONLY enroll new hosts; it cannot access or ingest data.

observer_api_url = <string>
# Required for zero-touch enrollment. Deslicer Observer API URL.
# Default (EU Standard plan): https://dap-eu-s1t8vn.deslicer.ai
# Other plans and self-hosted tenants: use your tenant URL from
# deslicer.ai > Settings > Integrations > Deslicer Automation Platform (DAP),
# or override via the Configuration tab after install.
