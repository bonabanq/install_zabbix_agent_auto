#!/usr/bin/env bash
# Purpose: Non-interactive Zabbix agent install & configure for RHEL/CentOS 7/8/9
# Behavior: Fails fast, shows where it failed, idempotent edits for conf
# Notes  : Comments are English-only to avoid encoding issues

set -Eeuo pipefail

############################
# Error & cleanup handling #
############################
trap 'echo "[ERROR] Line ${LINENO}: command \"${BASH_COMMAND}\" failed."; exit 1' ERR

#####################
# Pre-flight checks #
#####################
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Run as root."
  exit 1
fi

if ! command -v rpm >/dev/null 2>&1; then
  echo "[ERROR] rpm is required."
  exit 1
fi

PKG_MGR="yum"
if command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
fi

SYSTEMCTL="systemctl"
if ! command -v systemctl >/dev/null 2>&1; then
  echo "[ERROR] systemctl not found."
  exit 1
fi

#####################
# Configurable vars #
#####################
# Set your Zabbix servers here (comma-separated, no spaces)
SERVER_LIST="10.99.3.36,10.99.3.37"

# Hostname to register (defaults to kernel hostname)
HOST_NAME="$(uname -n)"

CONF="/etc/zabbix/zabbix_agentd.conf"
CONF_BAK="/etc/zabbix/zabbix_agentd.conf.$(date +%Y%m%d%H%M%S).bak"
MARKER_BEGIN="# >>> custom userparameters (managed block) >>>"
MARKER_END="# <<< custom userparameters (managed block) <<<"

#############################
# Remove prior installations#
#############################
echo "[INFO] Removing any existing zabbix-agent packages (if present)..."
$PKG_MGR -y remove zabbix-agent zabbix-agent2 || true

#########################################
# Add Zabbix 7.0 release repo (idempot.)#
#########################################
RHEL_VER="$(rpm -E %{rhel})"
REPO_RPM="https://repo.zabbix.com/zabbix/7.0/rhel/${RHEL_VER}/x86_64/zabbix-release-latest-7.0.el${RHEL_VER}.noarch.rpm"

echo "[INFO] Installing Zabbix release repo: $REPO_RPM"
rpm -Uvh --force "$REPO_RPM"

#############################
# Install Zabbix agent pkg  #
#############################
echo "[INFO] Installing zabbix-agent..."
$PKG_MGR -y clean all
$PKG_MGR -y install zabbix-agent

if [[ ! -f "$CONF" ]]; then
  echo "[ERROR] Missing $CONF after install."
  exit 1
fi

########################
# Backup current conf  #
########################
cp -a "$CONF" "$CONF_BAK"
echo "[INFO] Backed up conf to $CONF_BAK"

##########################################
# Helper: enforce single KEY=VALUE line  #
##########################################
set_or_replace_kv () {
  local key="$1"
  local value="$2"
  local file="$3"

  # Remove ALL existing occurrences (active or commented), then append exactly one
  sed -i -E "/^[#[:space:]]*${key}=.*/d" "$file"
  echo "${key}=${value}" >> "$file"
}

#################################
# Configure Server & Hostname   #
#################################
echo "[INFO] Configuring Server= and Hostname= ..."
set_or_replace_kv "Server" "$SERVER_LIST" "$CONF"
set_or_replace_kv "Hostname" "$HOST_NAME" "$CONF"

#################################
# Inject UserParameter (guarded)#
#################################
echo "[INFO] Injecting UserParameter block (no duplicates)..."
# Remove old managed block if exists
if grep -qF "$MARKER_BEGIN" "$CONF"; then
  # delete from marker begin to marker end
  sed -i "/${MARKER_BEGIN}/,/${MARKER_END}/d" "$CONF"
fi

cat >> "$CONF" <<'EOF'
# >>> custom userparameters (managed block) >>>
# Top 10 CPU consumers (PID, command, CPU%)
UserParameter=custom.top10cpu,ps -eo pid,comm,%cpu --sort=-%cpu | head -n 11
# Top 10 Memory consumers (PID, command, MEM%)
UserParameter=custom.top10mem,ps -eo pid,comm,%mem --sort=-%mem | head -n 11
# Pretty OS version (human-readable)
UserParameter=system.osver,grep "^PRETTY_NAME=" /etc/os-release | cut -d= -f2- | tr -d '"'
# Machine serial number (fallback to empty if unreadable)
UserParameter=system.serial,sh -c 'cat /sys/class/dmi/id/product_serial 2>/dev/null || true'
# Motherboard model (fallback safe)
UserParameter=system.mb_model,sh -c '\''[ -r /sys/class/dmi/id/board_name ] && cat /sys/class/dmi/id/board_name || true'\'''
# System vendor (fallback to empty if unreadable)
UserParameter=system.vendor,sh -c 'cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true'
# <<< custom userparameters (managed block) <<<
EOF

#################################
# Enable & start the service    #
#################################
echo "[INFO] Enabling and starting zabbix-agent service..."
$SYSTEMCTL daemon-reload || true
$SYSTEMCTL enable zabbix-agent
$SYSTEMCTL restart zabbix-agent
$SYSTEMCTL is-active --quiet zabbix-agent && echo "[INFO] zabbix-agent is active." || (echo "[ERROR] zabbix-agent failed to start." && exit 1)

#################################
# Print verification snippet    #
#################################
echo "----------------------------------------"
echo "[VERIFY] Server= and Hostname= in conf:"
grep -E '^(Server|Hostname)=' "$CONF" || true
echo "----------------------------------------"
echo "[VERIFY] UserParameter lines in conf:"
grep -E '^UserParameter=' "$CONF" || true
echo "----------------------------------------"
echo "[DONE] Installation and configuration completed."
