The collector binaries are not stored in the repository.
They are injected at build/package time by tools/build-spl.sh.

Expected binary names after packaging:
  deslicer-insights-node-linux-amd64   (x86_64)
  deslicer-insights-node-linux-arm64   (aarch64, optional)

The wrapper script (deslicer_ai_insights_collector.sh) auto-detects the host
architecture via uname -m and launches the matching binary.
If no arch-specific binary is found, it falls back to the generic
name deslicer-insights-node.

The binary reads settings from the Splunk conf file written by the
add-on: local/deslicer_ai_insights.conf (created when you save
Configuration -> Accounts).
