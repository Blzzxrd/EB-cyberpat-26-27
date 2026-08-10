#!/usr/bin/env bash
#
# ============================================================================
#  CyberPatriot Linux Security Audit Script
# ============================================================================
#  Purpose : Read-only recon/audit tool for CyberPatriot-style Linux images
#            (Ubuntu/Debian and Fedora/RHEL family). It inspects the system
#            and prints warnings + concrete fix commands. IT DOES NOT CHANGE
#            ANYTHING ITSELF.
#
#  Usage   : sudo ./audit.sh [--full]
#              --full   also run the slower prohibited-media file search
#
#  Why read-only: blindly auto-fixing on a scored image is how you lose
#  points -- disabling a service the README says is required hurts just as
#  much as leaving a real vuln in place. Fix things one at a time by hand,
#  checking the scoring report after each change.
# ============================================================================

# We deliberately do NOT use 'set -e'. Most checks here are grep/find
# commands that return non-zero when a condition simply isn't present --
# that's a normal "clean" result, not a script failure.

FULL_SCAN=0
[[ "${1:-}" == "--full" ]] && FULL_SCAN=1

# ---- colors / helpers -------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ACTION_ITEMS=()
OK_COUNT=0

ok()      { echo -e "  ${GREEN}[OK]${NC}   $1"; ((OK_COUNT++)); }
warn()    { echo -e "  ${YELLOW}[WARN]${NC} $1"; ACTION_ITEMS+=("$1"); }
crit()    { echo -e "  ${RED}[CRIT]${NC} $1"; ACTION_ITEMS+=("$1"); }
info()    { echo -e "  ${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${BOLD}==>  $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
  echo "Run this as root (sudo) -- most of these checks read protected files like /etc/shadow."
  exit 1
fi

# ---- distro detection ---------------------------------------------------
# Command names, admin group, and PAM file paths all differ between the
# Debian family (Ubuntu) and RHEL family (Fedora), so we branch once here
# instead of re-detecting in every section.
DISTRO_ID="unknown"
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRO_ID="$ID"
fi

case "$DISTRO_ID" in
  ubuntu|debian) FAMILY="debian" ;;
  fedora|rhel|centos|rocky|almalinux) FAMILY="rhel" ;;
  *) FAMILY="unknown" ;;
esac

if [[ "$FAMILY" == "debian" ]]; then
  ADMIN_GROUP="sudo"
  PAM_PW_FILE="/etc/pam.d/common-password"
elif [[ "$FAMILY" == "rhel" ]]; then
  ADMIN_GROUP="wheel"
  PAM_PW_FILE="/etc/pam.d/system-auth"
else
  ADMIN_GROUP="sudo"
  PAM_PW_FILE="/etc/pam.d/common-password"
fi

echo -e "${BOLD}CyberPatriot Linux Audit${NC}"
echo "Detected distro: $DISTRO_ID (family: $FAMILY)"
echo "Run at: $(date)"
echo "This script only reports. Cross-check every finding against your README before acting."

# ============================================================================
section "1. User Accounts"
# ============================================================================

info "Full account list -- compare every line against the README's authorized user list:"
awk -F: '{print "    " $1 " (UID " $3 ")"}' /etc/passwd

echo
info "Accounts with UID 0 (root)"
UID0_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
UID0_COUNT=$(echo "$UID0_USERS" | grep -c .)
if [[ "$UID0_COUNT" -gt 1 ]]; then
  crit "Multiple UID 0 accounts found: $(echo $UID0_USERS | tr '\n' ' ') -- remove any that aren't 'root': userdel -r <name>"
else
  ok "Only one UID 0 account (root)."
fi

echo
info "Members of the admin group '$ADMIN_GROUP' (sudo users):"
MEMBERS=$(getent group "$ADMIN_GROUP" 2>/dev/null | awk -F: '{print $4}')
echo "    ${MEMBERS:-'(none)'}"
if [[ -n "$MEMBERS" ]]; then
  warn "Verify every member of '$ADMIN_GROUP' above is authorized in README. Remove unauthorized: gpasswd -d <user> $ADMIN_GROUP"
fi

echo
info "Accounts with an EMPTY password field in /etc/shadow:"
EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
if [[ -n "$EMPTY_PW" ]]; then
  crit "No password set for: $EMPTY_PW -- lock now: passwd -l <user>   (then set a real password if the account is legitimate)"
else
  ok "No accounts with empty passwords."
fi

echo
info "Regular user accounts (UID 1000-65533) and their login shells:"
awk -F: '($3 >= 1000 && $3 < 65534) {print "    " $1 " -> " $7}' /etc/passwd
warn "Confirm every username above is on the authorized list. Remove unknowns: userdel -r <user>"

echo
info "System/service accounts (UID < 1000) that still have an interactive shell:"
SYS_SHELLS=$(awk -F: '($3 < 1000 && $7 !~ /(nologin|false)$/ && $1 != "root") {print $1 " -> " $7}' /etc/passwd)
if [[ -n "$SYS_SHELLS" ]]; then
  warn "Service accounts with a real shell (should usually be nologin/false):"
  echo "$SYS_SHELLS" | sed 's/^/    /'
else
  ok "All non-root system accounts have nologin/false shells."
fi

# ============================================================================
section "2. Password Policy"
# ============================================================================

info "/etc/login.defs aging/length settings:"
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs | sed 's/^/    /'

MAXDAYS=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs)
if [[ -z "$MAXDAYS" ]]; then
  warn "PASS_MAX_DAYS not set in /etc/login.defs -- set it, e.g. 'PASS_MAX_DAYS 90'."
elif [[ "$MAXDAYS" -gt 90 ]]; then
  warn "PASS_MAX_DAYS is $MAXDAYS (recommend <= 90). Edit /etc/login.defs."
else
  ok "PASS_MAX_DAYS is $MAXDAYS."
fi

echo
if [[ -f "$PAM_PW_FILE" ]]; then
  info "Checking $PAM_PW_FILE for password-complexity enforcement:"
  if grep -Eq 'pam_(pwquality|cracklib)\.so' "$PAM_PW_FILE"; then
    ok "Complexity module present:"
    grep -E 'pam_(pwquality|cracklib)\.so' "$PAM_PW_FILE" | sed 's/^/    /'
  else
    warn "No pam_pwquality/pam_cracklib line in $PAM_PW_FILE. Add e.g.: 'password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1'"
  fi
else
  warn "$PAM_PW_FILE not found -- confirm the correct PAM password file for this distro and check it by hand."
fi

echo
info "Per-user password aging (chage -l) for real accounts:"
for u in $(awk -F: '($3 >= 1000 && $3 < 65534){print $1}' /etc/passwd); do
  echo "    -- $u --"
  chage -l "$u" | sed 's/^/       /'
done

# ============================================================================
section "3. SSH Configuration"
# ============================================================================

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]]; then
  check_sshd() {
    local key="$1" expected="$2" desc="$3" val
    val=$(grep -Ei "^\s*${key}\s+" "$SSHD_CONFIG" | tail -n1 | awk '{print $2}')
    if [[ -z "$val" ]]; then
      warn "$desc: '$key' not explicitly set (default may be insecure). Set '$key $expected' in $SSHD_CONFIG."
    elif [[ "${val,,}" != "${expected,,}" ]]; then
      warn "$desc: '$key' is currently '$val', recommended '$expected'."
    else
      ok "$desc: $key $val"
    fi
  }
  check_sshd "PermitRootLogin" "no" "Root login over SSH"
  check_sshd "PasswordAuthentication" "no" "Password authentication (only set 'no' if the README allows key-only auth)"
  check_sshd "PermitEmptyPasswords" "no" "Empty password logins"
  check_sshd "X11Forwarding" "no" "X11 forwarding"

  PORT_LINE=$(grep -Ei '^\s*Port\s+' "$SSHD_CONFIG")
  info "SSH Port directive: ${PORT_LINE:-'(not set -- default 22)'}"
else
  info "sshd_config not found -- SSH server isn't installed. Only an issue if the README requires SSH."
fi

if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
  ok "SSH service is running."
  warn "Confirm SSH is SUPPOSED to run per the README. If not authorized: systemctl disable --now sshd"
else
  info "SSH service is not active."
fi

# ============================================================================
section "4. Firewall"
# ============================================================================

if command -v firewall-cmd &>/dev/null; then
  STATE=$(firewall-cmd --state 2>/dev/null)
  if [[ "$STATE" == "running" ]]; then
    ok "firewalld is running."
    info "Active zones/rules:"
    firewall-cmd --list-all 2>/dev/null | sed 's/^/    /'
  else
    crit "firewalld is installed but NOT running. Enable: systemctl enable --now firewalld"
  fi
elif command -v ufw &>/dev/null; then
  UFW_STATE=$(ufw status | head -n1)
  if [[ "$UFW_STATE" == *"active"* ]]; then
    ok "ufw is active."
    info "Rules:"
    ufw status verbose | sed 's/^/    /'
  else
    crit "ufw is installed but INACTIVE. Enable: ufw enable"
  fi
else
  warn "No firewalld/ufw found. Checking raw iptables rules instead:"
  iptables -L -n -v 2>/dev/null | sed 's/^/    /'
fi

# ============================================================================
section "5. Listening Services / Open Ports"
# ============================================================================

info "Currently listening TCP/UDP sockets and the process behind each:"
if command -v ss &>/dev/null; then
  ss -tulpn 2>/dev/null | sed 's/^/    /'
else
  netstat -tulpn 2>/dev/null | sed 's/^/    /'
fi
warn "Match the list above against the README's authorized-services list. Stop/disable anything unauthorized: systemctl stop <service> && systemctl disable <service>"

# ============================================================================
section "6. Commonly Prohibited / High-Risk Services"
# ============================================================================
# These daemons show up repeatedly in CyberPatriot scenarios as things that
# should be removed unless the README explicitly says otherwise.

PROHIBITED_SERVICES=(telnet telnetd rsh rlogin rexec vsftpd proftpd pure-ftpd tftp tftpd nfs-server rpcbind ypserv snmpd xinetd)
FOUND_PROHIBITED=0
for svc in "${PROHIBITED_SERVICES[@]}"; do
  if systemctl list-unit-files 2>/dev/null | grep -qi "^${svc}\.service"; then
    FOUND_PROHIBITED=1
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      crit "'$svc' is INSTALLED and RUNNING. If unauthorized: systemctl stop $svc && systemctl disable $svc  (then consider uninstalling it)."
    else
      warn "'$svc' is installed but not running. Uninstall if unauthorized (apt remove / dnf remove $svc)."
    fi
  fi
done
[[ "$FOUND_PROHIBITED" -eq 0 ]] && ok "None of the commonly-prohibited services are installed."

# ============================================================================
section "7. System Updates"
# ============================================================================

info "Checking for available package updates (may take a moment)..."
if [[ "$FAMILY" == "debian" ]]; then
  apt update -qq &>/dev/null
  UPDATES=$(apt list --upgradable 2>/dev/null | tail -n +2)
elif [[ "$FAMILY" == "rhel" ]]; then
  UPDATES=$(dnf check-update 2>/dev/null | grep -Ev '^$|^Last metadata')
else
  UPDATES=""
fi

if [[ -n "$UPDATES" ]]; then
  COUNT=$(echo "$UPDATES" | grep -c .)
  warn "$COUNT package(s) have updates available. Run: $( [[ "$FAMILY" == debian ]] && echo 'apt upgrade -y' || echo 'dnf upgrade -y' )"
  echo "$UPDATES" | head -n 15 | sed 's/^/    /'
  [[ "$COUNT" -gt 15 ]] && info "(...and $((COUNT-15)) more)"
else
  ok "System appears up to date (or the update check isn't available in this environment)."
fi

echo
if [[ "$FAMILY" == "debian" ]] && dpkg -l unattended-upgrades &>/dev/null 2>&1; then
  ok "unattended-upgrades is installed for automatic patching."
elif [[ "$FAMILY" == "rhel" ]] && rpm -q dnf-automatic &>/dev/null 2>&1; then
  ok "dnf-automatic is installed for automatic patching."
else
  info "No automatic-update package detected. Install/enable one if the README requires it."
fi

# ============================================================================
section "8. File Permissions"
# ============================================================================

info "World-writable files (excluding /proc, /sys) -- may take a minute:"
WW_FILES=$(find / -xdev -path /proc -prune -o -path /sys -prune -o -type f -perm -0002 -print 2>/dev/null | head -n 30)
if [[ -n "$WW_FILES" ]]; then
  warn "World-writable files found (showing up to 30). Tighten with chmod o-w <file>:"
  echo "$WW_FILES" | sed 's/^/    /'
else
  ok "No world-writable files found on the root filesystem."
fi

echo
info "SUID/SGID binaries -- compare this list against what's normal for a stock install of this distro:"
SUID_FILES=$(find / -xdev -path /proc -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
echo "$SUID_FILES" | sed 's/^/    /'
warn "Anything unfamiliar here (especially in /tmp, /home, or unexpected copies of bash/nc/find) is a red flag. Strip the bit: chmod u-s,g-s <file>  or delete the file entirely."

# ============================================================================
section "9. Critical File Permissions & Ownership"
# ============================================================================

check_perm() {
  local file="$1" expected_perm="$2" expected_owner="$3"
  [[ -f "$file" ]] || { info "$file not found."; return; }
  local actual_perm actual_owner
  actual_perm=$(stat -c '%a' "$file")
  actual_owner=$(stat -c '%U:%G' "$file")
  if [[ "$actual_perm" != "$expected_perm" ]]; then
    warn "$file has mode $actual_perm (expected $expected_perm). Fix: chmod $expected_perm $file"
  else
    ok "$file mode ($actual_perm) OK."
  fi
  if [[ "$actual_owner" != "$expected_owner" ]]; then
    warn "$file is owned by $actual_owner (expected $expected_owner). Fix: chown $expected_owner $file"
  else
    ok "$file ownership ($actual_owner) OK."
  fi
}

check_perm /etc/passwd 644 root:root
check_perm /etc/group  644 root:root
check_perm /etc/sudoers 440 root:root

echo
info "/etc/shadow (mode/owner conventions vary by distro; the key requirement is NOT world-readable):"
SHADOW_PERM=$(stat -c '%a' /etc/shadow)
SHADOW_OWNER=$(stat -c '%U:%G' /etc/shadow)
echo "    Current: $SHADOW_PERM owned by $SHADOW_OWNER"
if [[ "${SHADOW_PERM: -1}" != "0" ]]; then
  crit "/etc/shadow looks world-accessible (mode $SHADOW_PERM). Fix: chmod 600 /etc/shadow (or 640 root:shadow to match your distro's convention)."
else
  ok "/etc/shadow is not world-accessible."
fi

# ============================================================================
section "10. Scheduled Tasks (cron/at) -- common persistence mechanism"
# ============================================================================

info "System-wide /etc/crontab:"
[[ -f /etc/crontab ]] && { grep -Ev '^\s*#|^\s*$' /etc/crontab | sed 's/^/    /'; } || info "    (file not found)"

echo
info "/etc/cron.d/ contents:"
ls -la /etc/cron.d/ 2>/dev/null | sed 's/^/    /'

echo
info "Per-user crontabs:"
FOUND_CRON=0
for u in $(awk -F: '{print $1}' /etc/passwd); do
  CRON=$(crontab -u "$u" -l 2>/dev/null)
  if [[ -n "$CRON" ]]; then
    FOUND_CRON=1
    echo "    -- $u --"
    echo "$CRON" | sed 's/^/       /'
  fi
done
if [[ "$FOUND_CRON" -eq 1 ]]; then
  warn "Review every cron entry above. Remove anything unfamiliar, especially entries that download/execute scripts or run as root: crontab -u <user> -e"
else
  ok "No per-user crontabs found."
fi

echo
info "Pending 'at' jobs:"
atq 2>/dev/null | sed 's/^/    /'

# ============================================================================
section "11. Backdoor / Malware Indicators"
# ============================================================================

info "Top processes by CPU (skim for anything unfamiliar: netcat, reverse shells, miners, odd binaries running from /tmp):"
ps aux --sort=-%cpu | head -n 20 | sed 's/^/    /'

echo
info "SSH authorized_keys for every home directory (an attacker-added key is a silent, passwordless backdoor):"
FOUND_KEYS=0
for home in /root /home/*; do
  AK="$home/.ssh/authorized_keys"
  if [[ -f "$AK" ]]; then
    FOUND_KEYS=1
    warn "$AK exists -- verify every key below was actually added by you/your team:"
    sed 's/^/    /' "$AK"
  fi
done
[[ "$FOUND_KEYS" -eq 0 ]] && ok "No authorized_keys files found."

echo
info "Scanning shell startup files for suspicious patterns (reverse shells, piped curl/wget, base64 payloads)..."
SUSPICIOUS='nc \-e|/dev/tcp/|curl .*\| ?sh|wget .*\| ?sh|base64 -d'
FOUND_SUSPICIOUS=0
for f in /root/.bashrc /root/.profile /etc/bash.bashrc /etc/profile /home/*/.bashrc /home/*/.profile; do
  [[ -f "$f" ]] || continue
  HIT=$(grep -En "$SUSPICIOUS" "$f")
  if [[ -n "$HIT" ]]; then
    FOUND_SUSPICIOUS=1
    crit "Suspicious content in $f:"
    echo "$HIT" | sed 's/^/    /'
  fi
done
[[ "$FOUND_SUSPICIOUS" -eq 0 ]] && ok "No obviously suspicious patterns in shell startup files."

echo
info "/etc/hosts (look for unexpected domain redirects):"
grep -Ev '^\s*#|^\s*$' /etc/hosts | sed 's/^/    /'

# ============================================================================
section "12. Prohibited Media / Files"
# ============================================================================

if [[ "$FULL_SCAN" -eq 1 ]]; then
  info "Searching /home and /root for common prohibited media types (slow)..."
  MEDIA=$(find /home /root -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.torrent' -o -iname '*.iso' \) 2>/dev/null)
  if [[ -n "$MEDIA" ]]; then
    warn "Potentially prohibited files found -- remove if the README disallows them:"
    echo "$MEDIA" | sed 's/^/    /'
  else
    ok "No obviously prohibited media files found in home directories."
  fi
else
  info "Skipped -- rerun with --full to include this (slower) search."
fi

# ============================================================================
section "13. Installed Network Applications"
# ============================================================================
# These only fire if the relevant package is actually present -- they exist
# to remind you to do a manual pass, not to replace one.

if command -v apache2 &>/dev/null || command -v httpd &>/dev/null || systemctl list-unit-files 2>/dev/null | grep -qiE '^(apache2|httpd)\.service'; then
  info "Apache/httpd detected."
  warn "Manually check: 'Options -Indexes' (no directory listing), 'ServerTokens Prod' + 'ServerSignature Off', default/test pages removed, and that it should be running at all."
  warn "Run apps/apache.py"
fi

if command -v mysql &>/dev/null || command -v mariadb &>/dev/null || systemctl list-unit-files 2>/dev/null | grep -qiE '^(mysql|mariadb)\.service'; then
  info "MySQL/MariaDB detected."
  warn "Manually check: strong root DB password, no anonymous users, remote root login disabled, test DB removed. Consider running mysql_secure_installation."
fi

if command -v smbd &>/dev/null || systemctl list-unit-files 2>/dev/null | grep -qi '^smb\.service'; then
  info "Samba detected."
  warn "Review /etc/samba/smb.conf for open/guest shares, and confirm Samba is supposed to be running per the README."
fi



# ===========================================================================
section "14. auditd"
# ===========================================================================

echo "auditd: " $(systemctl is-enabled auditd 2>/dev/null || echo "not installed")
echo "auditd: " $(systemctl is-active auditd 2>/dev/null || echo "not running")
echo "auditd output:"
echo "$(auditctl -s 2>/dev/null | head -n1 || echo "auditctl not available")"

echo "If auditd is not enabled, check in the README and enable it if necessary."

# ============================================================================
section "SUMMARY"
# ============================================================================

echo -e "Checks passed cleanly : ${GREEN}${OK_COUNT}${NC}"
echo -e "Action items flagged  : ${YELLOW}${#ACTION_ITEMS[@]}${NC}"
echo
if [[ "${#ACTION_ITEMS[@]}" -gt 0 ]]; then
  echo -e "${BOLD}Action items (fuller context is inline above):${NC}"
  i=1
  for item in "${ACTION_ITEMS[@]}"; do
    echo "  $i. $item"
    ((i++))
  done
else
  echo "Nothing flagged -- still cross-check manually against the README, since this script can't see the hidden scoring checklist."
fi

echo
echo "fix issues ONE AT A TIME and re-check  score/points after each change."
echo "undo point changing moves so that yk whats going wrong