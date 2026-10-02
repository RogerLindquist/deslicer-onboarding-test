Deslicer AI Insights Add-on
===========================

Overview
--------
Deslicer AI Insights Add-on collects Splunk configuration metadata from every host
in your deployment and sends it to the Deslicer AI platform. This enables
Deslicer to monitor configuration drift, detect anomalies, track deployment
state across your entire Splunk estate, and surface AI-driven automation
recommendations.

A single add-on package installs on all Splunk Enterprise host tiers — indexers,
search heads, heavy forwarders, and cluster managers. The add-on is hidden from
Splunk Web by default (is_visible = false) and is restricted to admin and
sc_admin roles. Making the app visible in Splunk Web is a conscious admin
decision — push local/app.conf with [ui] is_visible = true on tiers where the
dashboard is needed (e.g. SHC members via SH Deployer).

Requirements
------------
  - Splunk Enterprise 9.0 or later
  - Linux x86_64 or Linux arm64 (aarch64) — the collector binary runs on
    Linux only (Windows Splunk hosts are not currently supported)
  - Outbound HTTPS access from each Splunk host to the Deslicer platform
  - An enrollment token — obtained after signing up at https://deslicer.ai

Getting Your Enrollment Token
-----------------------------
After signing up at https://deslicer.ai:
  1. Create or select your workspace.
  2. Navigate to Settings > Integrations > Deslicer Automation Platform (DAP).
  3. Copy your enrollment token.

The Observer URL for standard plans is https://dap-eu-s1t8vn.deslicer.ai.
Each Splunk environment you want to monitor gets its own enrollment token.

Installation
------------

Splunkbase download filenames use hyphens in the app name and an underscore
before the dotless version suffix (e.g. v1.1.0 ->
deslicer-ai-insights-add-on_110.spl). GitHub release artifacts use a
different naming scheme (deslicer_ai_insights-<version>-linux-multiarch.spl).

--- Standalone (single-instance Splunk) ---

  Step 1. Install the app:
    $SPLUNK_HOME/bin/splunk install app deslicer-ai-insights-add-on_<dotless-version>.spl \
      -auth admin:password

    Example (v1.1.0): deslicer-ai-insights-add-on_110.spl

  Step 2. Restart Splunk:
    $SPLUNK_HOME/bin/splunk restart

  Step 3. Configure in Splunk Web:
    Apps > Deslicer AI Insights Add-on > Configuration > Add connection
    Enter https://dap-eu-s1t8vn.deslicer.ai as the Observer URL and your
    enrollment token from deslicer.ai.

  Step 4. Enable the data input:
    Apps > Deslicer AI Insights Add-on > Inputs > Create New Input
    Select your connection and save.

  Step 5 (optional). Show the app in Splunk Web navigation on tiers where the
    dashboard is needed (e.g. search heads):
    Create $SPLUNK_HOME/etc/apps/deslicer_ai_insights/local/app.conf:
      [ui]
      is_visible = true

--- Distributed Environment ---

Install Deslicer AI Insights Add-on (deslicer_ai_insights) on all Splunk Enterprise
hosts with meaningful configuration to observe. Universal Forwarders carry
minimal config and are not required.

  Host Tier               | Deploy with              | UI visible
  ------------------------|--------------------------|------------------------------------
  Heavy Forwarders        | Deployment Server        | No (default); set local/app.conf is_visible = true if needed
  Indexers (clustered)    | Cluster Manager          | No (default); set local/app.conf is_visible = true if needed
  Indexers (standalone)   | Deployment Server        | No (default); set local/app.conf is_visible = true if needed
  Search Heads / SHC      | SHC Deployer             | No (default); set is_visible = true where dashboard is needed
  Cluster Manager         | Manual / Deployment Svr  | No (default)
  License Manager         | Manual                   | No (default)
  Monitor Console         | Manual                   | No (default)

  Option A: Deployment Server (forwarders and standalone non-clustered hosts)

    a. Copy deslicer-ai-insights-add-on_<dotless-version>.spl to your Deployment Server.
    b. Expand into the deployment-apps directory:
         cd $SPLUNK_HOME/etc/deployment-apps
         tar xzf /path/to/deslicer-ai-insights-add-on_<dotless-version>.spl
    c. Create a server class targeting the hosts you want to collect from.
    d. Optionally provision the enrollment token before deploying
       (see "Provisioning Tokens at Scale" below).
    e. Reload the deployment server:
         $SPLUNK_HOME/bin/splunk reload deploy-server

  Option B: Cluster Manager (indexer cluster peers)

    a. Copy the app into the manager-apps directory on the Cluster Manager:
         cd $SPLUNK_HOME/etc/manager-apps
         tar xzf /path/to/deslicer-ai-insights-add-on_<dotless-version>.spl
    b. Apply the bundle to all peer nodes:
         $SPLUNK_HOME/bin/splunk apply cluster-bundle
    c. Verify all peers received the update:
         $SPLUNK_HOME/bin/splunk show cluster-bundle-status

  Option C: SHC Deployer (Search Head Cluster members)

    a. Copy the app into the deployer's shcluster/apps directory:
         $SPLUNK_HOME/etc/shcluster/apps/deslicer_ai_insights/
    b. The dashboard is hidden from Splunk Web by default. To show it on SHC members,
       add local/app.conf with is_visible = true under
       $SPLUNK_HOME/etc/shcluster/apps/deslicer_ai_insights/local/app.conf
    c. Push the bundle to all SHC members:
         $SPLUNK_HOME/bin/splunk apply shcluster-bundle \
           --answer-yes -target https://<SHC-captain>:8089

  Option D: Manual install (any individual host)

    $SPLUNK_HOME/bin/splunk install app deslicer-ai-insights-add-on_<dotless-version>.spl \
      -auth admin:password
    $SPLUNK_HOME/bin/splunk restart

Provisioning Tokens at Scale
-----------------------------
For large deployments, provision the enrollment token before deploying so each
host auto-enrolls on first startup — no per-host UI configuration needed.

  a. In your Deployment Server's copy of the app, create:
       $SPLUNK_HOME/etc/deployment-apps/deslicer_ai_insights/local/enrollment.conf

  b. Add the token and Observer URL:
       [enrollment]
       token = <your-enrollment-token>
       observer_api_url = https://dap-eu-s1t8vn.deslicer.ai

  c. Deploy as normal. Each host enrolls independently and receives its
     own API key stored in Splunk's encrypted credential store. The
     enrollment token is not stored long-term after successful enrollment.

Configuration
-------------
Credentials are stored in Splunk's encrypted storage/passwords endpoint.
No credentials are stored in plain text in any configuration file.

Access control: Configuration and Inputs tabs are restricted to admin and
sc_admin roles. The app is hidden from all other users in Splunk Web.

Configuration files used by this add-on:

  default/inputs.conf                  — Modular input definition (disabled by default)
  default/deslicer_ai_insights.conf    — Collector settings template
  local/enrollment.conf                — Optional: enrollment token for scale deployments
  local/app.conf                       — Optional: set is_visible = true to show the app UI

Binary Architecture
-------------------
The collector binary is a statically linked Linux executable:
  - x86_64 (amd64): deslicer-insights-node-linux-amd64
  - aarch64 (arm64): deslicer-insights-node-linux-arm64

The correct binary is selected automatically at runtime based on the host
architecture. The binary runs as the splunk OS user — no elevated privileges
are required.

Troubleshooting
---------------
Logs are written to:
  $SPLUNK_HOME/var/log/splunk/deslicer_ai_insights_<input_name>.log

Common issues:

  "Collector binary not found"
    Verify $SPLUNK_HOME/etc/apps/deslicer_ai_insights/bin/ contains
    deslicer-insights-node-linux-amd64 or deslicer-insights-node-linux-arm64.
    Contact support@deslicer.com to get the correct app binary package.

  "Cannot enroll: no credentials available"
    No enrollment token found. Either configure via:
    - Splunk Web: Apps > Deslicer AI Insights Add-on > Configuration > Add, or
    - local/enrollment.conf with token and observer_api_url.

  "Observer URL uses insecure HTTP"
    Update the connection to use https:// and restart the input.

  "API key revoked by admin"
    The API key was revoked in the Deslicer platform. Provide a new
    enrollment token and restart the input to re-enroll.

  Input running but no data appears in Deslicer
    1. Check the log for "Enrollment successful".
    2. Verify outbound HTTPS to your Observer URL on port 443.
    3. Confirm the modular input is enabled (not just saved).

Support
-------
Email:   support@deslicer.com
Sign up: https://deslicer.ai
