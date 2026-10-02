[deslicer_ai_insights://<name>]
account = Connection with enrollment token for this Insights Node. The node auto-enrolls and receives API keys automatically.
exclude_apps = Comma- or newline-separated list of Splunk app folder names to exclude from observation (literal match against the folder under $SPLUNK_HOME/etc/apps/). Equivalent conf path: [observation_scope] exclude_apps in local/deslicer_ai_insights.conf. The agent's own TA and apps under system/ cannot be excluded.
exclude_path_glob = Comma- or newline-separated POSIX glob patterns evaluated against paths RELATIVE to $SPLUNK_HOME/etc (e.g. apps/*/local/passwd*). Equivalent conf path: [observation_scope] exclude_path_glob. In clustered Splunk envs, configure via the deployer / cluster-manager bundle -- UI edits on member nodes are local-only and overwritten on the next bundle push.
index = (Default: main)
interval = Set to 0 for continuous watch mode (recommended). Non-zero values run the collector periodically. (Default: 0)
log_level = Log verbosity for the collector binary. (Default: info)

python.version = <string>
* Python version for this modular input. Set to python3.

python.required = <string>
* Required Python version. Set to 3.13 for Splunk 10.2+ (ignored safely on Splunk 9.x).
