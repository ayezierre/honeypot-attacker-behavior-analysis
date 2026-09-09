#!/bin/bash

########################################################################
# Honeypot Recycling Script
#
# Purpose:
# Automate the honeypot lifecycle by terminating active sessions,
# collecting logs, calculating metrics, restoring baseline snapshots,
# restarting logging, and reconnecting network rules.
#
# Logging:
# Uses Snoopy for command logging when available.
########################################################################

set -euo pipefail

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------

SCRIPT_DIR="/root/honeypots"
LOG_STORAGE_DIR="/root/honeypot_logs"
SNAPSHOT_DIR="/root/snapshots"

ACTIVE_PHASE_DURATION=$((6 * 3600))

# Honeypot containers and private IP addresses
declare -A CONTAINERS=(
    ["control"]="10.0.0.10"
    ["treatment1"]="10.0.0.11"
    ["treatment2"]="10.0.0.12"
    ["treatment3"]="10.0.0.13"
)

# ----------------------------------------------------------------------
# UTILITIES
# ----------------------------------------------------------------------

log_message() {
    mkdir -p "${LOG_STORAGE_DIR}"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" \
        | tee -a "${LOG_STORAGE_DIR}/recycling.log"
}

error_exit() {
    log_message "ERROR: $1"
    exit 1
}

# ----------------------------------------------------------------------
# PHASE 1: TERMINATE ACTIVE SESSIONS
# ----------------------------------------------------------------------

terminate_sessions() {
    local container=$1

    log_message "Terminating SSH processes and interactive shells in ${container}..."

    lxc-attach -n "${container}" -- pkill -9 sshd 2>/dev/null || true
    lxc-attach -n "${container}" -- pkill -9 -u root 2>/dev/null || true

    # Allow processes to terminate and logs to flush
    sleep 2
}

# ----------------------------------------------------------------------
# PHASE 2: COLLECT AND TIMESTAMP LOGS
# ----------------------------------------------------------------------

collect_logs() {
    local container=$1
    local timestamp
    local log_dir

    timestamp=$(date '+%Y%m%d_%H%M%S')
    log_dir="${LOG_STORAGE_DIR}/${container}/${timestamp}"

    log_message "Collecting logs for ${container} into ${log_dir}..."

    mkdir -p "${log_dir}"

    # SSH authentication logs
    lxc-attach -n "${container}" -- bash -lc \
        'if [ -f /var/log/auth.log ]; then
            cat /var/log/auth.log
         elif [ -f /var/log/secure ]; then
            cat /var/log/secure
         else
            echo "NO_AUTH_LOG"
         fi' \
        > "${log_dir}/auth.log" 2>/dev/null || true

    # Snoopy command logs
    lxc-attach -n "${container}" -- bash -lc \
        'if [ -f /var/log/snoopy.log ]; then
            cat /var/log/snoopy.log
         else
            echo "NO_SNOOPY_LOG"
         fi' \
        > "${log_dir}/snoopy.log" 2>/dev/null || true

    # Bash command histories
    lxc-attach -n "${container}" -- bash -lc \
        'find /home /root -maxdepth 3 -type f -name ".bash_history" \
        -exec sh -c "echo \"== {} ==\"; cat {}" \;' \
        > "${log_dir}/command_history.log" 2>/dev/null || true

    # Audit logs if ausearch is available
    lxc-attach -n "${container}" -- bash -lc \
        'command -v ausearch >/dev/null 2>&1 \
        && ausearch -m USER_CMD -ts today \
        || echo "NO_AUSEARCH"' \
        > "${log_dir}/audit_user_cmds.log" 2>/dev/null || true

    # File modification timestamps
    lxc-attach -n "${container}" -- bash -lc \
        'find /home /root -type f -printf "%T+ %p\n" 2>/dev/null || true' \
        > "${log_dir}/file_access_times.log" 2>/dev/null || true

    log_message "Collected logs for ${container}."
}

# ----------------------------------------------------------------------
# PHASE 3: CALCULATE METRICS
# ----------------------------------------------------------------------

calculate_metrics() {
    local container=$1
    local latest_dir
    local metrics_file

    latest_dir=$(
        ls -1dt "${LOG_STORAGE_DIR}/${container}/"* 2>/dev/null \
        | head -1 || true
    )

    if [ -z "${latest_dir}" ]; then
        log_message "No logs found for ${container}; skipping metrics."
        return
    fi

    metrics_file="${latest_dir}/metrics.txt"

    log_message "Calculating metrics for ${container} into ${metrics_file}..."

    {
        echo "=== HONEYPOT METRICS ==="
        echo "Container: ${container}"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Treatment: $(get_treatment_name "${container}")"
        echo ""

        echo "--- SSH ACTIVITY ---"

        if [ -s "${latest_dir}/auth.log" ]; then
            echo "First accepted login:"
            grep "Accepted" "${latest_dir}/auth.log" \
                | head -1 \
                || echo "None"

            echo "Last disconnect/session closed:"
            grep -E "session closed|Disconnected" "${latest_dir}/auth.log" \
                | tail -1 \
                || echo "None"

            echo "Total accepted count: $(
                grep -c "Accepted" "${latest_dir}/auth.log" 2>/dev/null \
                || echo 0
            )"
        else
            echo "No authentication logs present."
        fi

        echo ""
        echo "--- SNOOPY / COMMAND LOGS ---"

        if [ -s "${latest_dir}/snoopy.log" ]; then
            echo "Snoopy lines: $(
                wc -l < "${latest_dir}/snoopy.log" 2>/dev/null \
                || echo 0
            )"

            echo "Sample Snoopy entries:"
            head -10 "${latest_dir}/snoopy.log" 2>/dev/null || true

        elif [ -s "${latest_dir}/command_history.log" ]; then
            echo "Command history lines: $(
                wc -l < "${latest_dir}/command_history.log" 2>/dev/null \
                || echo 0
            )"

            echo "Top commands:"
            awk '{print $1}' "${latest_dir}/command_history.log" \
                | sort \
                | uniq -c \
                | sort -rn \
                | head -10 \
                || true
        else
            echo "No command logs present."
        fi

        echo ""
        echo "--- FILE ACCESS PATTERNS ---"

        if [ -s "${latest_dir}/file_access_times.log" ]; then
            echo "File access entries: $(
                wc -l < "${latest_dir}/file_access_times.log" 2>/dev/null \
                || echo 0
            )"

            echo "Most recently modified files:"
            sort -r "${latest_dir}/file_access_times.log" \
                | head -10 \
                || true
        fi

    } > "${metrics_file}"

    log_message "Metrics written to ${metrics_file}"
}

get_treatment_name() {
    case "$1" in
        "control")
            echo "Control (Zero files)"
            ;;
        "treatment1")
            echo "Treatment 1 (Insensitive Only)"
            ;;
        "treatment2")
            echo "Treatment 2 (Mixed - Insensitive + Sensitive)"
            ;;
        "treatment3")
            echo "Treatment 3 (Sensitive Only)"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# ----------------------------------------------------------------------
# PHASE 4: RESTORE FROM SNAPSHOT
# ----------------------------------------------------------------------

restore_snapshot() {
    local container=$1

    log_message "Restoring ${container} from snapshot..."

    lxc-stop -n "${container}" -t 30 2>/dev/null \
        || log_message "lxc-stop failed or container already stopped"

    if [ -d "${SNAPSHOT_DIR}/${container}_baseline" ]; then
        rsync -a --delete \
            "${SNAPSHOT_DIR}/${container}_baseline/" \
            "/var/lib/lxc/${container}/" \
            || error_exit "Snapshot restore failed."

        log_message "Snapshot restored for ${container}"
    else
        log_message "Snapshot not found for ${container}; skipping restore."
    fi

    lxc-start -n "${container}" 2>/dev/null \
        || error_exit "Failed to start ${container}"

    lxc-wait -n "${container}" -s RUNNING -t 30 || true

    log_message "${container} running after restore."
}

# ----------------------------------------------------------------------
# PHASE 5: RESTART LOGGING
# ----------------------------------------------------------------------

restart_logging() {
    local container=$1

    log_message "Restarting logging services inside ${container}..."

    # Enable timestamps for future interactive shell histories
    lxc-attach -n "${container}" -- bash -lc \
        "grep -q HISTTIMEFORMAT /etc/bash.bashrc \
        || echo 'export HISTTIMEFORMAT=\"%F %T \"' >> /etc/bash.bashrc" \
        || true

    # Clear old Snoopy log
    lxc-attach -n "${container}" -- bash -lc \
        'if [ -f /var/log/snoopy.log ]; then
            : > /var/log/snoopy.log
         fi' \
        2>/dev/null || true

    # Restart logging service
    lxc-attach -n "${container}" -- bash -lc \
        'if command -v systemctl >/dev/null 2>&1; then
            systemctl restart rsyslog.service \
            || systemctl restart rsyslog \
            || true
         else
            service rsyslog restart || true
         fi' \
        2>/dev/null || true

    log_message \
        "Logging services restarted for ${container}. Ensure Snoopy is installed and enabled."
}

# ----------------------------------------------------------------------
# PHASE 6: RECONNECT NETWORK
# ----------------------------------------------------------------------

reconnect_network() {
    local container=$1

    log_message "Re-applying network rules for ${container} if applicable..."

    if [ -f "${SCRIPT_DIR}/nat_rules.sh" ]; then
        bash "${SCRIPT_DIR}/nat_rules.sh" "${container}" \
            || log_message "nat_rules.sh returned a non-zero status"
    fi

    log_message "Network reconfiguration complete for ${container}."
}

# ----------------------------------------------------------------------
# MAIN WORKFLOW
# ----------------------------------------------------------------------

recycle_container() {
    local container=$1

    log_message "========================================="
    log_message "Starting recycling for ${container}"
    log_message "========================================="

    terminate_sessions "${container}"
    collect_logs "${container}"
    calculate_metrics "${container}"
    restore_snapshot "${container}"
    restart_logging "${container}"
    reconnect_network "${container}"

    log_message "Recycling complete for ${container}"
    echo ""
}

main() {
    log_message "Recycling script initiated"

    mkdir -p "${LOG_STORAGE_DIR}"
    mkdir -p "${SNAPSHOT_DIR}"

    if [ $# -eq 1 ]; then
        recycle_container "$1"
    else
        for container in "${!CONTAINERS[@]}"; do
            recycle_container "${container}"
        done
    fi

    log_message "All recycling operations completed"
}

main "$@"
