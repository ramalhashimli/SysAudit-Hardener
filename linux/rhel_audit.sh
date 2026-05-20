#!/usr/bin/env bash
# =============================================================================
# SysAudit-Hardener — RHEL System Audit & Hardening Script
# Compatible: RHEL 7 / 8 / 9, CentOS, Rocky Linux, AlmaLinux
# Run as:     root (or sudo)
# Log output: /var/log/sysaudit/rhel_audit_<timestamp>.log
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_DIR="/var/log/sysaudit"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="${LOG_DIR}/rhel_audit_${TIMESTAMP}.log"
readonly HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
readonly DISK_THRESHOLD=85  # percent — alert if any filesystem exceeds this

# Critical services that must be active. Add or remove entries as needed.
readonly CRITICAL_SERVICES=(
    "sshd"
    "chronyd"
    "firewalld"
)

# Files with their required permissions (octal) and owner:group
# Format: "path:permissions:owner:group"
readonly CRITICAL_FILES=(
    "/etc/passwd:644:root:root"
    "/etc/shadow:000:root:root"
    "/etc/gshadow:000:root:root"
    "/etc/group:644:root:root"
)

# ---------------------------------------------------------------------------
# COUNTERS
# ---------------------------------------------------------------------------
COUNT_TOTAL=0
COUNT_OK=0
COUNT_WARN=0
COUNT_FIX=0
COUNT_FAIL=0

# ---------------------------------------------------------------------------
# COLOR CODES (terminal only — stripped in log file)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    CLR_RESET="\033[0m"
    CLR_OK="\033[0;32m"      # green
    CLR_WARN="\033[0;33m"    # yellow
    CLR_FAIL="\033[0;31m"    # red
    CLR_INFO="\033[0;36m"    # cyan
    CLR_FIX="\033[0;35m"     # magenta
else
    CLR_RESET=""
    CLR_OK=""
    CLR_WARN=""
    CLR_FAIL=""
    CLR_INFO=""
    CLR_FIX=""
fi

# ---------------------------------------------------------------------------
# LOGGING HELPERS
# ---------------------------------------------------------------------------

# Write a line to both the terminal (with color) and the log file (plain text)
_log_raw() {
    local color="$1"
    local tag="$2"
    local message="$3"
    local line="[${tag}]  ${message}"
    printf "${color}%s${CLR_RESET}\n" "${line}" >&1
    printf "%s\n" "${line}" >> "${LOG_FILE}"
}

log_info()  { _log_raw "${CLR_INFO}"  "INFO"  "$*"; }
log_ok()    { _log_raw "${CLR_OK}"    "OK"    "$*"; COUNT_OK=$(( COUNT_OK + 1 )); COUNT_TOTAL=$(( COUNT_TOTAL + 1 )); }
log_warn()  { _log_raw "${CLR_WARN}"  "WARN"  "$*"; COUNT_WARN=$(( COUNT_WARN + 1 )); COUNT_TOTAL=$(( COUNT_TOTAL + 1 )); }
log_fail()  { _log_raw "${CLR_FAIL}"  "FAIL"  "$*"; COUNT_FAIL=$(( COUNT_FAIL + 1 )); COUNT_TOTAL=$(( COUNT_TOTAL + 1 )); }
log_fix()   { _log_raw "${CLR_FIX}"   "FIX"   "$*"; COUNT_FIX=$(( COUNT_FIX + 1 )); COUNT_TOTAL=$(( COUNT_TOTAL + 1 )); }

log_divider() {
    local line="$(printf '%.0s-' {1..80})"
    printf "${CLR_INFO}%s${CLR_RESET}\n" "${line}" >&1
    printf "%s\n" "${line}" >> "${LOG_FILE}"
}

log_section() {
    local title="$1"
    log_divider
    log_info "=== ${title} ==="
    log_divider
}

log_plain() {
    # Write a line without tag prefix — used for header/footer blocks
    printf "%s\n" "$*" | tee -a "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ---------------------------------------------------------------------------

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        printf "[FAIL]  This script must be run as root. Aborting.\n" >&2
        exit 1
    fi
}

init_log_dir() {
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}"
        chmod 700 "${LOG_DIR}"
    fi
    # Create the log file and restrict access — it may contain sensitive info
    touch "${LOG_FILE}"
    chmod 600 "${LOG_FILE}"
}

print_header() {
    local bar
    bar="$(printf '=%.0s' {1..80})"
    log_plain "${bar}"
    log_plain "  SysAudit-Hardener v${SCRIPT_VERSION} | RHEL System Audit Report"
    log_plain "  Host     : ${HOSTNAME_FQDN}"
    log_plain "  Date     : $(date '+%Y-%m-%d %H:%M:%S')"
    log_plain "  Run by   : $(id -un) (UID $(id -u))"
    log_plain "  Log      : ${LOG_FILE}"
    log_plain "${bar}"
    log_plain ""
}

print_footer() {
    local bar
    bar="$(printf '=%.0s' {1..80})"
    log_plain ""
    log_plain "${bar}"
    log_plain "  Audit complete."
    log_plain "  Total checks : ${COUNT_TOTAL}"
    log_plain "  OK           : ${COUNT_OK}"
    log_plain "  WARN         : ${COUNT_WARN}"
    log_plain "  FIXED        : ${COUNT_FIX}"
    log_plain "  FAIL         : ${COUNT_FAIL}"
    log_plain "${bar}"
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 1: DISK USAGE
# ---------------------------------------------------------------------------

audit_disk_usage() {
    log_section "DISK & FILESYSTEM USAGE (threshold: ${DISK_THRESHOLD}%)"

    # Parse df output — skip the header line and tmpfs/devtmpfs pseudo-filesystems
    while IFS= read -r line; do
        # Extract usage percentage (e.g., "42%") and mount point
        local usage_pct fs_name mount_point
        usage_pct="$(echo "${line}" | awk '{print $5}' | tr -d '%')"
        fs_name="$(echo "${line}"   | awk '{print $1}')"
        mount_point="$(echo "${line}" | awk '{print $6}')"

        # Skip non-numeric percentages (header artifacts)
        if ! [[ "${usage_pct}" =~ ^[0-9]+$ ]]; then
            continue
        fi

        local label="${fs_name} (${mount_point})"

        if (( usage_pct >= DISK_THRESHOLD )); then
            log_warn "${label} : ${usage_pct}% used — EXCEEDS ${DISK_THRESHOLD}% THRESHOLD"
        else
            log_ok   "${label} : ${usage_pct}% used"
        fi
    done < <(df -hTP | grep -vE '^(Filesystem|tmpfs|devtmpfs|udev|overlay|shm)')
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 2: USER ACCOUNTS
# ---------------------------------------------------------------------------

audit_user_accounts() {
    log_section "USER ACCOUNT SECURITY"

    log_info "Checking for accounts with empty passwords in /etc/shadow..."

    local empty_pw_found=0
    while IFS=: read -r username pw_hash _rest; do
        # An empty password field means no password set — critical security risk
        if [[ -z "${pw_hash}" ]]; then
            log_fail  "Account '${username}' has NO PASSWORD set in /etc/shadow"
            empty_pw_found=$(( empty_pw_found + 1 ))
        fi
    done < /etc/shadow

    if (( empty_pw_found == 0 )); then
        log_ok "No accounts with empty passwords found"
    fi

    log_info "Checking for accounts with UID 0 (root-equivalent)..."

    local uid0_count=0
    while IFS=: read -r username _pw uid _rest; do
        if [[ "${uid}" -eq 0 ]] && [[ "${username}" != "root" ]]; then
            log_warn "Non-root account '${username}' has UID 0 — root-equivalent privilege"
            uid0_count=$(( uid0_count + 1 ))
        fi
    done < /etc/passwd

    if (( uid0_count == 0 )); then
        log_ok "No unexpected UID-0 accounts found"
    fi

    log_info "Checking for system accounts that have a valid login shell..."

    # System accounts (UID < 1000) should typically use /sbin/nologin or /bin/false
    local suspicious_shell_count=0
    while IFS=: read -r username _pw uid _gid _gecos _home shell; do
        if (( uid > 0 && uid < 1000 )) && \
           [[ "${shell}" != "/sbin/nologin" ]] && \
           [[ "${shell}" != "/bin/false"   ]] && \
           [[ "${shell}" != "/usr/sbin/nologin" ]]; then
            log_warn "System account '${username}' (UID ${uid}) has login shell: ${shell}"
            suspicious_shell_count=$(( suspicious_shell_count + 1 ))
        fi
    done < /etc/passwd

    if (( suspicious_shell_count == 0 )); then
        log_ok "All system accounts use non-login shells"
    fi

    log_info "Listing human users (UID >= 1000) with their last login timestamps..."

    local human_users
    human_users="$(awk -F: '($3 >= 1000 && $1 != "nobody") {print $1}' /etc/passwd)"

    if [[ -z "${human_users}" ]]; then
        log_info "No human user accounts found (UID >= 1000)"
    else
        while IFS= read -r uname; do
            local last_login
            last_login="$(lastlog -u "${uname}" 2>/dev/null | tail -n1 | awk '{$1=""; print $0}' | xargs)"
            log_info "User '${uname}' — last login: ${last_login:-unknown}"
        done <<< "${human_users}"
    fi
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 3: CRITICAL SERVICES
# ---------------------------------------------------------------------------

audit_critical_services() {
    log_section "CRITICAL SYSTEMD SERVICES"

    for service in "${CRITICAL_SERVICES[@]}"; do
        local state
        state="$(systemctl is-active "${service}" 2>/dev/null || true)"

        if [[ "${state}" == "active" ]]; then
            log_ok "${service}.service : active (running)"
        else
            log_warn "${service}.service : ${state} — attempting to start..."

            if systemctl start "${service}" 2>/dev/null; then
                # Verify it actually came up after start attempt
                local new_state
                new_state="$(systemctl is-active "${service}" 2>/dev/null || true)"
                if [[ "${new_state}" == "active" ]]; then
                    log_fix "${service}.service : started successfully (now active)"
                else
                    log_fail "${service}.service : start attempted but still not active (state: ${new_state})"
                fi
            else
                log_fail "${service}.service : failed to start — check 'journalctl -u ${service}'"
            fi
        fi
    done

    # Also report the enabled/disabled state (separate from running state)
    log_info "Enabled/disabled states of critical services:"
    for service in "${CRITICAL_SERVICES[@]}"; do
        local enabled_state
        enabled_state="$(systemctl is-enabled "${service}" 2>/dev/null || echo 'unknown')"
        log_info "  ${service}.service — enabled: ${enabled_state}"
    done
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 4: FIREWALL
# ---------------------------------------------------------------------------

audit_firewall() {
    log_section "FIREWALL STATUS"

    # Check whether firewalld is running
    if ! systemctl is-active firewalld &>/dev/null; then
        log_fail "firewalld is NOT running — system may be unprotected"
        return
    fi

    log_ok "firewalld is active"

    # List active zones and their associated interfaces
    log_info "Active firewall zones:"
    local zone_output
    if zone_output="$(firewall-cmd --get-active-zones 2>/dev/null)"; then
        while IFS= read -r zone_line; do
            log_info "  ${zone_line}"
        done <<< "${zone_output}"
    else
        log_warn "Could not retrieve active zones from firewall-cmd"
    fi

    # List the default zone
    local default_zone
    default_zone="$(firewall-cmd --get-default-zone 2>/dev/null || echo 'unknown')"
    log_info "Default zone: ${default_zone}"

    # List services allowed in the default zone
    log_info "Services allowed in default zone '${default_zone}':"
    local services_in_zone
    if services_in_zone="$(firewall-cmd --zone="${default_zone}" --list-services 2>/dev/null)"; then
        log_info "  ${services_in_zone}"
    else
        log_warn "  Could not list services for zone '${default_zone}'"
    fi
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 5: CRITICAL FILE PERMISSIONS
# ---------------------------------------------------------------------------

audit_file_permissions() {
    log_section "CRITICAL FILE PERMISSIONS"

    for entry in "${CRITICAL_FILES[@]}"; do
        # Split entry on ':' — format is path:permissions:owner:group
        IFS=':' read -r filepath required_perm required_owner required_group <<< "${entry}"

        if [[ ! -e "${filepath}" ]]; then
            log_fail "${filepath} : FILE NOT FOUND"
            continue
        fi

        # Get current octal permissions using stat (portable format)
        local current_perm current_owner current_group
        current_perm="$(  stat -c '%a' "${filepath}" 2>/dev/null)"
        current_owner="$( stat -c '%U' "${filepath}" 2>/dev/null)"
        current_group="$( stat -c '%G' "${filepath}" 2>/dev/null)"

        local perm_ok=true
        local owner_ok=true

        # Check permissions
        if [[ "${current_perm}" != "${required_perm}" ]]; then
            perm_ok=false
            log_warn "${filepath} : permissions are ${current_perm}, expected ${required_perm} — fixing..."
            if chmod "${required_perm}" "${filepath}" 2>/dev/null; then
                log_fix "${filepath} : permissions corrected to ${required_perm}"
            else
                log_fail "${filepath} : failed to correct permissions"
            fi
        fi

        # Check owner and group
        if [[ "${current_owner}" != "${required_owner}" ]] || \
           [[ "${current_group}" != "${required_group}" ]]; then
            owner_ok=false
            log_warn "${filepath} : owner is ${current_owner}:${current_group}, expected ${required_owner}:${required_group} — fixing..."
            if chown "${required_owner}:${required_group}" "${filepath}" 2>/dev/null; then
                log_fix "${filepath} : ownership corrected to ${required_owner}:${required_group}"
            else
                log_fail "${filepath} : failed to correct ownership"
            fi
        fi

        if [[ "${perm_ok}" == true ]] && [[ "${owner_ok}" == true ]]; then
            log_ok "${filepath} : permissions ${current_perm}, owner ${current_owner}:${current_group} — compliant"
        fi
    done
}

# ---------------------------------------------------------------------------
# AUDIT MODULE 6: SSH CONFIGURATION
# ---------------------------------------------------------------------------

audit_ssh_config() {
    log_section "SSH SERVER CONFIGURATION"

    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "${sshd_config}" ]]; then
        log_warn "sshd_config not found at ${sshd_config} — skipping SSH audit"
        return
    fi

    # Check PermitRootLogin — should be 'no' or 'prohibit-password'
    local permit_root
    permit_root="$(grep -i '^\s*PermitRootLogin' "${sshd_config}" | awk '{print $2}' | tail -1)"
    permit_root="${permit_root:-not set (default: prohibit-password on RHEL8+)}"

    case "${permit_root,,}" in
        "no"|"prohibit-password"|"forced-commands-only")
            log_ok  "PermitRootLogin : ${permit_root}"
            ;;
        "yes")
            log_warn "PermitRootLogin : ${permit_root} — direct root SSH login is enabled"
            ;;
        *)
            log_info "PermitRootLogin : ${permit_root}"
            ;;
    esac

    # Check PasswordAuthentication — key-based auth is preferred
    local passwd_auth
    passwd_auth="$(grep -i '^\s*PasswordAuthentication' "${sshd_config}" | awk '{print $2}' | tail -1)"
    passwd_auth="${passwd_auth:-not set (default: yes)}"

    if [[ "${passwd_auth,,}" == "no" ]]; then
        log_ok   "PasswordAuthentication : no (key-based auth enforced)"
    else
        log_warn "PasswordAuthentication : ${passwd_auth} — password login permitted"
    fi

    # Check Protocol version (relevant on older RHEL 7 configs)
    local proto
    proto="$(grep -i '^\s*Protocol' "${sshd_config}" | awk '{print $2}' | tail -1)"
    if [[ -n "${proto}" ]] && [[ "${proto}" != "2" ]]; then
        log_fail "Protocol : ${proto} — SSHv1 or mixed mode detected; must be Protocol 2"
    elif [[ -z "${proto}" ]]; then
        log_ok   "Protocol : not explicitly set (SSHv2 default on RHEL 8/9)"
    else
        log_ok   "Protocol : ${proto}"
    fi
}

# ---------------------------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------------------------

main() {
    check_root
    init_log_dir
    print_header

    audit_disk_usage
    audit_user_accounts
    audit_critical_services
    audit_firewall
    audit_file_permissions
    audit_ssh_config

    print_footer
}

main "$@"
