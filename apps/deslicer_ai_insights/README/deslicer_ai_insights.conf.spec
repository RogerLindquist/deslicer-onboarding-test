# deslicer_ai_insights.conf.spec
#
# Configuration spec for Deslicer AI Insights.
# Secrets (API key, tenant ID) live in Splunk's encrypted credential store;
# this conf carries non-sensitive runtime and operator scope settings only.

[api]
observer_api_url = <string>
* HTTPS URL of the Deslicer Automation Platform (Observer API).
* Must use https:// — plain HTTP is rejected unless a dev-only bypass is enabled.
* Default (EU Standard plan): https://dap-eu-s1t8vn.deslicer.ai
* Other plans and self-hosted tenants: override via Settings >
* Integrations > Deslicer Automation Platform (DAP) Configuration tab, or
* set local/deslicer_ai_insights.conf on the host.
* Also set during zero-touch enrollment via local/enrollment.conf.

[identifiers]
tenant_id = <string>
* Tenant ID for multi-tenant Observer deployments.
* Set via the Configuration tab or written during enrollment.

[collection]
interval = <integer>
* Collection interval in seconds (default template in default/: 300).
* The persistent supervisor uses interval = -1 in default/inputs.conf so Splunk
* does not re-launch the helper on a timer; this [collection] interval is
* written to runtime-generated local/deslicer_ai_insights.conf only.

[observation_scope]

exclude_apps = <comma-separated app folder names>
* Comma-separated list of Splunk app folder names to exclude from
  observation (literal match against the folder name under
  $SPLUNK_HOME/etc/apps/, e.g. "secret_app", "my_internal_addon").
* Values are matched LITERALLY. Glob meta-characters (`*`, `?`, `[`, `]`,
  `{`, `}`) MUST NOT appear here -- the agent rejects (and the server
  audit flags) any entry containing them. Use exclude_path_glob for
  pattern-based exclusions.
* Reserved app names cannot be excluded: the running insights TA itself
  (`deslicer_ai_insights`) and any app under `system/` are always in
  scope. Attempts to exclude them are silently ignored by the agent and
  emit a warning in the server-side OBSERVATION_SCOPE_CHANGED audit
  event.
* Default: empty (no apps excluded -> agent observes every app folder it
  can read).
* Example:
*     exclude_apps = secret_app, customer_pii_addon, internal_only

exclude_path_glob = <comma-separated glob patterns>
* Comma-separated list of glob patterns evaluated against paths
  RELATIVE to $SPLUNK_HOME/etc. The agent walks
  $SPLUNK_HOME/etc/{apps,system,users,...} and skips any file whose
  relative path matches one of these patterns.
* Glob syntax follows POSIX glob (matches the same dialect as Splunk
  itself): `*` matches any segment, `**` matches across path
  separators, `?` matches one character, `[...]` matches a character
  class.
* Reserved paths are NEVER excludable, even if a pattern would match
  them: `system/**` (Splunk core) and `apps/deslicer_ai_insights/**`
  (the agent's own TA -- excluding it would orphan the heartbeat).
  Matching reserved paths is silently dropped with a server-side
  warning.
* Default: empty (no path globs -> all observable files are eligible).
* Examples:
*     exclude_path_glob = apps/*/local/passwd*, apps/*/local/server.conf
*     exclude_path_glob = apps/secret_app/**, users/**/savedsearches.conf

# SECURITY NOTE: Scope changes are an audit-significant event. The DAP
# backend tracks the last-known scope per host and emits a
# COVERAGE_DROP alert if the new scope reduces observable surface area
# below the tenant's configured floor. Operators should treat this conf
# stanza like any other security-sensitive Splunk configuration and
# version-control it alongside the rest of the deployment bundle.
