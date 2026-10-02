#!/bin/bash
# Deslicer AI Insights - execution wrapper for scripted input
# Runs the collector binary in watch mode with supervisor pattern:
# - Auto-selects correct binary for host architecture (amd64/arm64)
# - Reads settings from Splunk conf (local/deslicer_ai_insights.conf written by add-on)
# - Copies the binary to a runtime location (avoids "Text file busy")
# - Monitors for binary updates and self-restarts when detected
# - Restarts on crashes with backoff

set +e

CHILD_PID=""
cleanup() {
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=info msg=\"Received shutdown signal, stopping node\""
    if [ -n "$CHILD_PID" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
        kill -TERM "$CHILD_PID" 2>/dev/null
        wait "$CHILD_PID" 2>/dev/null
    fi
    [ -f "$RUNTIME_DIR/deslicer_ai_insights.conf" ] && rm "$RUNTIME_DIR/deslicer_ai_insights.conf" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

SPLUNK_HOME=${SPLUNK_HOME:-/opt/splunk}
APP_NAME="deslicer_ai_insights"
RUNTIME_DIR="${SPLUNK_HOME}/var/run/deslicer_ai_insights"
mkdir -p "$RUNTIME_DIR"

UPDATE_CHECK_INTERVAL=${UPDATE_CHECK_INTERVAL:-30}
MAX_RESTART_DELAY=300
restart_delay=5

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)   echo "linux-amd64" ;;
        aarch64|arm64)   echo "linux-arm64" ;;
        *)
            echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=error msg=\"Unsupported architecture: $machine. Supported: x86_64, aarch64.\""
            return 1
            ;;
    esac
}

get_checksum() {
    local file="$1"
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$file" 2>/dev/null | cut -d' ' -f1
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q "$file" 2>/dev/null
    else
        stat -c '%s-%Y' "$file" 2>/dev/null || stat -f '%z-%m' "$file" 2>/dev/null
    fi
}

find_source_binary() {
    local arch
    arch="$(detect_arch)" || exit 1

    local app_bin="$SPLUNK_HOME/etc/apps/${APP_NAME}/bin"
    local script_bin="$(dirname "$0")"

    for dir in "$app_bin" "$script_bin"; do
        if [ -x "$dir/deslicer-insights-node-${arch}" ]; then
            echo "$dir/deslicer-insights-node-${arch}"
            return 0
        fi
        if [ -x "$dir/deslicer-insights-node" ]; then
            echo "$dir/deslicer-insights-node"
            return 0
        fi
    done
    return 1
}

update_runtime_binary() {
    local src="$1"
    local dst="$RUNTIME_DIR/deslicer-insights-node"
    local src_checksum=$(get_checksum "$src")
    local dst_checksum=$(get_checksum "$dst" 2>/dev/null || echo "none")
    if [ "$src_checksum" != "$dst_checksum" ]; then
        echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=info msg=\"Binary updated, copying to runtime location\""
        cp -f "$src" "$dst"
        chmod +x "$dst"
        return 0
    fi
    return 1
}

find_config() {
    local script_path="$0"
    local app_dir
    if [[ "$script_path" == /* ]]; then
        app_dir="$(dirname "$(dirname "$script_path")")"
    else
        app_dir="$SPLUNK_HOME/etc/apps/${APP_NAME}"
    fi
    if [ -f "$app_dir/local/deslicer_ai_insights.conf" ]; then
        echo "$app_dir/local/deslicer_ai_insights.conf"
        return 0
    fi
    if [ -f "$SPLUNK_HOME/etc/apps/deslicer_ai_insights_config/local/deslicer_ai_insights.conf" ]; then
        echo "$SPLUNK_HOME/etc/apps/deslicer_ai_insights_config/local/deslicer_ai_insights.conf"
        return 0
    fi
    # Do not fall back to default/deslicer_ai_insights.conf: it is a template only.
    # Credentials are delivered via API_KEY env var (from storage/passwords), never written to conf.
    if [ -n "$OBSERVER_API_URL" ] && [ -n "$TENANT_ID" ]; then
        # Normalise: prefer API_KEY; fall back to legacy API_TOKEN name.
        API_KEY="${API_KEY:-$API_TOKEN}"
        if [ -z "$API_KEY" ]; then
            echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=error msg=\"env-var config path requires API_KEY or API_TOKEN to be set\""
            return 1
        fi
        export API_KEY
        local config_file="$RUNTIME_DIR/deslicer_ai_insights.conf"
        local old_umask
        old_umask=$(umask)
        umask 077
        # api_token is intentionally omitted from the file to avoid cleartext
        # credential persistence. The binary reads it from API_KEY env var instead.
        cat > "$config_file" << CONF
[api]
observer_api_url = ${OBSERVER_API_URL}

[identifiers]
tenant_id = ${TENANT_ID}
host_id = ${HOST_ID:-}

[collection]
interval = ${COLLECTION_INTERVAL:-300}
splunk_home = ${SPLUNK_HOME}
CONF
        chmod 600 "$config_file"
        umask "$old_umask"
        echo "$config_file"
        return 0
    fi
    return 1
}

main() {
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=info msg=\"Deslicer AI Insights supervisor starting\" update_check_interval=${UPDATE_CHECK_INTERVAL}s"

    NODE_SRC=$(find_source_binary)
    if [ -z "$NODE_SRC" ]; then
        echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=error msg=\"Collector binary not found\""
        exit 1
    fi

    CONFIG_FILE=$(find_config)
    if [ -z "$CONFIG_FILE" ]; then
        # Detect whether an account was saved via UI but not converted to binary config
        ACCOUNT_CONF="$SPLUNK_HOME/etc/apps/${APP_NAME}/local/deslicer_ai_insights_account.conf"
        if [ -f "$ACCOUNT_CONF" ]; then
            echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=error msg=\"Account credentials found in Configuration tab but enrollment is incomplete. If you saved an enrollment token, re-save it in Configuration > Accounts to trigger enrollment, or contact support.\""
        else
            echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=error msg=\"No configuration found. Add an account in the add-on Configuration tab (Settings > observer_api_url + Enrollment Token) and save to complete enrollment.\""
        fi
        exit 1
    fi

    BUFFER_DIR="${BUFFER_DIR:-/tmp/deslicer_ai_insights_buffer}"
    mkdir -p "$BUFFER_DIR"

    update_runtime_binary "$NODE_SRC"
    NODE_BIN="$RUNTIME_DIR/deslicer-insights-node"
    CURRENT_CHECKSUM=$(get_checksum "$NODE_SRC")

    while true; do
        echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=info msg=\"Starting Deslicer AI Insights node\" binary=\"$NODE_BIN\" config=\"$CONFIG_FILE\""

        MAX_PAYLOAD_SIZE_MB="${MAX_PAYLOAD_SIZE_MB:-2}" \
        "$NODE_BIN" \
            --config "$CONFIG_FILE" \
            --buffer-dir "$BUFFER_DIR" \
            --log-level "${LOG_LEVEL:-info}" \
            --watch &
        CHILD_PID=$!

        while kill -0 "$CHILD_PID" 2>/dev/null; do
            sleep "$UPDATE_CHECK_INTERVAL"
            NEW_CHECKSUM=$(get_checksum "$NODE_SRC")
            if [ "$NEW_CHECKSUM" != "$CURRENT_CHECKSUM" ]; then
                echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=info msg=\"Binary update detected, restarting node\""
                update_runtime_binary "$NODE_SRC"
                CURRENT_CHECKSUM="$NEW_CHECKSUM"
                kill -TERM "$CHILD_PID" 2>/dev/null
                wait "$CHILD_PID" 2>/dev/null
                restart_delay=5
                break
            fi
        done

        wait "$CHILD_PID" 2>/dev/null
        exit_code=$?
        CHILD_PID=""

        if [ $exit_code -eq 0 ]; then
            restart_delay=1
        elif [ $exit_code -eq 2 ]; then
            restart_delay=1
        else
            echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) level=warn msg=\"Node exited unexpectedly, restarting with backoff\" exit_code=$exit_code restart_delay=${restart_delay}s"
        fi

        sleep "$restart_delay"
        if [ $exit_code -ne 0 ] && [ $exit_code -ne 2 ]; then
            restart_delay=$((restart_delay * 2))
            if [ $restart_delay -gt $MAX_RESTART_DELAY ]; then
                restart_delay=$MAX_RESTART_DELAY
            fi
        fi

        update_runtime_binary "$NODE_SRC"
        CURRENT_CHECKSUM=$(get_checksum "$NODE_SRC")
    done
}

main
