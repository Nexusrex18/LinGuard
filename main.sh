#!/bin/bash
# =============================================================================
# Wazuh + Falco + chkrootkit — Interactive Security Operations CLI v2.0
# Usage: sudo bash wazuh-falco-cli.sh
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

log_ok() { echo -e "  ${GREEN}✔${NC}  $1"; }
log_err() { echo -e "  ${RED}✘${NC}  $1"; }
log_warn() { echo -e "  ${YELLOW}!${NC}  $1"; }
log_info() { echo -e "  ${CYAN}→${NC}  $1"; }
log_run() { echo -e "  ${DIM}$ $1${NC}"; }
log_alert() { echo -e "  ${YELLOW}⚡${NC}  $1"; }
log_crit() { echo -e "  ${RED}☠${NC}  ${RED}$1${NC}"; }
separator() { echo -e "  ${DIM}────────────────────────────────────────────────${NC}"; }

header() {
  clear
  echo ""
  echo -e "  ${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "  ${CYAN}${BOLD}║   🛡  LINGUARD SECURITY OPS CLI  v1.0             ║${NC}"
  echo -e "  ${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
}

pause() {
  echo ""
  echo -e "  ${DIM}Press Enter to continue...${NC}"
  read -r
}
confirm() {
  echo -ne "  ${YELLOW}$1 [y/N]:${NC} "
  read -r -n1 ans
  echo ""
  [[ "$ans" =~ ^[Yy]$ ]]
}

run_cmd() {
  echo -e "  ${BLUE}▶${NC} ${WHITE}$1${NC}"
  log_run "$2"
  sleep 0.3
  eval "$2" >>/tmp/wazuh_cli.log 2>&1 && log_ok "$1" || log_warn "$1 — check /tmp/wazuh_cli.log"
}

get_manager_container() { docker ps --format "{{.Names}}" 2>/dev/null | grep -i "wazuh" | grep -i "manager" | head -1; }
get_public_ip() { curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'; }

attack_card() {
  local num="$1" name="$2" what="$3" why="$4" falco="$5" wazuh="$6" mitre="$7"
  echo ""
  echo -e "  ${RED}${BOLD}╔─ ATTACK $num — $name${NC}"
  echo -e "  ${WHITE}│ What happens:${NC}  $what"
  echo -e "  ${YELLOW}│ Why it matters:${NC} $why"
  echo -e "  ${CYAN}│ Falco detects:${NC} $falco"
  echo -e "  ${GREEN}│ Wazuh alerts:${NC}  $wazuh"
  echo -e "  ${DIM}│ MITRE ATT&CK:  $mitre${NC}"
  echo -e "  ${RED}╚────────────────────────────────────────────────${NC}"
  echo ""
}

show_status_bar() {
  local dc fa ag
  dc=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -ic "wazuh" || echo 0)
  fa=$(systemctl is-active falco-modern-bpf 2>/dev/null || echo "inactive")
  ag=$(systemctl is-active wazuh-agent 2>/dev/null || echo "inactive")
  echo -e "  ${DIM}Status:${NC}"
  echo -n "  "
  [ "$dc" -ge 3 ] 2>/dev/null && echo -ne "  ${GREEN}● Docker[3/3]${NC}" ||
    { [ "$dc" -gt 0 ] 2>/dev/null && echo -ne "  ${YELLOW}● Docker[${dc}/3]${NC}" || echo -ne "  ${RED}● Docker[0/3]${NC}"; }
  [ "$ag" = "active" ] && echo -ne "  ${GREEN}● Wazuh-Agent${NC}" || echo -ne "  ${RED}● Wazuh-Agent${NC}"
  [ "$fa" = "active" ] && echo -ne "  ${GREEN}● Falco-eBPF${NC}" || echo -ne "  ${RED}● Falco-eBPF${NC}"
  command -v chkrootkit &>/dev/null && echo -ne "  ${GREEN}● chkrootkit${NC}" || echo -ne "  ${DIM}● chkrootkit${NC}"
  [ -f /var/log/falco.log ] && echo -ne "  ${CYAN}● falco.log[$(wc -l </var/log/falco.log)L]${NC}"
  echo ""
  echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
main_menu() {
  while true; do
    header
    show_status_bar
    echo -e "  ${WHITE}${BOLD}MAIN MENU${NC}"
    separator
    echo -e "  ${CYAN}[1]${NC}  ⚙   Setup Infrastructure"
    echo -e "  ${GREEN}[2]${NC}  ◉   System Status"
    echo -e "  ${RED}[3]${NC}  ⚡   Simulate Attacks"
    echo -e "  ${YELLOW}[4]${NC}  ◈   Live Logs"
    echo -e "  ${MAGENTA}[5]${NC}  ◆   Falco Rules Manager"
    echo -e "  ${CYAN}[6]${NC}  ✎   Wazuh Rules Manager"
    echo -e "  ${BLUE}[7]${NC}  ✦   Dashboard Info"
    echo -e "  ${GREEN}[8]${NC}  🔍  chkrootkit"
    echo -e "  ${RED}[9]${NC}  ⏻   Shutdown / Cleanup"
    echo -e "  ${DIM}[0]  ✕   Exit${NC}"
    separator
    echo -ne "\n  ${WHITE}Choose option: ${NC}"
    read -r choice
    case "$choice" in
    1) menu_setup ;; 2) menu_status ;; 3) menu_attacks ;;
    4) menu_logs ;; 5) menu_falco_rules ;; 6) menu_wazuh_rules ;;
    7) menu_dashboard ;; 8) menu_chkrootkit ;; 9) menu_shutdown ;;
    0)
      clear
      echo -e "\n  ${DIM}Goodbye.${NC}\n"
      exit 0
      ;;
    *)
      echo -e "\n  ${RED}Invalid${NC}"
      sleep 1
      ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SETUP
# ══════════════════════════════════════════════════════════════════════════════
menu_setup() {
  header
  echo -e "  ${CYAN}${BOLD}⚙  SETUP INFRASTRUCTURE${NC}"
  separator
  echo ""
  echo -e "  Installs and configures the full stack:"
  echo -e "  ${DIM}  Phase 1 — Docker + compose"
  echo -e "  Phase 2 — Wazuh Stack (Manager + Indexer + Dashboard)"
  echo -e "  Phase 3 — Wazuh Agent"
  echo -e "  Phase 4 — Falco (eBPF) + FilelessShield rules"
  echo -e "  Phase 5 — Wazuh decoder + Falco rules"
  echo -e "  Phase 6 — chkrootkit + daily cron + Wazuh rules${NC}"
  echo ""
  if ! confirm "Proceed with full setup?"; then return; fi

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 1 — Prerequisites${NC}"
  separator
  run_cmd "Updating packages" "apt-get update -qq"
  run_cmd "Installing dependencies" "apt-get install -y git curl ca-certificates gnupg python3 -qq"
  if ! command -v docker &>/dev/null; then
    run_cmd "Installing Docker" "curl -fsSL https://get.docker.com | bash"
    run_cmd "Enabling Docker" "systemctl enable docker && systemctl start docker"
  else
    log_ok "Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"
  fi
  if ! command -v docker-compose &>/dev/null; then
    run_cmd "Installing docker-compose" \
      "curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose"
  else log_ok "docker-compose already installed"; fi

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 2 — Wazuh Docker Stack${NC}"
  separator
  WAZUH_DIR="$HOME/wazuh-docker/single-node"
  [ ! -d "$WAZUH_DIR" ] && run_cmd "Cloning Wazuh repo v4.7.0" \
    "git clone https://github.com/wazuh/wazuh-docker.git $HOME/wazuh-docker --branch v4.7.0 -q" ||
    log_ok "Repo already cloned"
  cd "$WAZUH_DIR" || return
  [ ! -f "config/wazuh_indexer_ssl_certs/wazuh.indexer.pem" ] &&
    run_cmd "Generating SSL certs" "docker-compose -f generate-indexer-certs.yml run --rm generator" ||
    log_ok "SSL certs exist"
  run_cmd "Starting Wazuh stack" "docker-compose up -d"
  echo -ne "  ${CYAN}→${NC}  Waiting for containers"
  for i in {1..20}; do
    echo -n "."
    sleep 3
    [ "$(docker ps --filter 'name=wazuh' --filter 'status=running' 2>/dev/null | grep -c 'Up')" -ge 3 ] && break
  done
  echo ""
  log_ok "Stack running ($(docker ps --filter 'name=wazuh' --filter 'status=running' 2>/dev/null | grep -c 'Up') containers)"

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 3 — Wazuh Agent${NC}"
  separator
  if ! dpkg -l 2>/dev/null | grep -q "^ii  wazuh-agent"; then
    run_cmd "Adding Wazuh GPG key" \
      "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
    run_cmd "Adding Wazuh repo" \
      "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list"
    run_cmd "apt-get update" "apt-get update -qq"
    AVER=$(apt-cache madison wazuh-agent 2>/dev/null | grep "4.7" | head -1 | awk '{print $3}')
    [ -n "$AVER" ] &&
      run_cmd "Installing wazuh-agent=$AVER" "WAZUH_MANAGER='127.0.0.1' apt-get install -y wazuh-agent=$AVER" ||
      run_cmd "Installing wazuh-agent" "WAZUH_MANAGER='127.0.0.1' apt-get install -y wazuh-agent"
  else log_ok "Wazuh agent already installed"; fi

  grep -q "MANAGER_IP" /var/ossec/etc/ossec.conf 2>/dev/null &&
    run_cmd "Fixing manager IP" "sed -i 's/MANAGER_IP/127.0.0.1/g' /var/ossec/etc/ossec.conf"

  if ! grep -q "falco.log" /var/ossec/etc/ossec.conf 2>/dev/null; then
    run_cmd "Adding Falco log to ossec.conf" \
      "python3 -c \"
path='/var/ossec/etc/ossec.conf'
b='\n  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/falco.log</location>\n  </localfile>\n'
with open(path) as f: c=f.read()
i=c.rfind('</ossec_config>')
with open(path,'w') as f: f.write(c[:i]+b+c[i:])
\""
  else log_ok "Falco log in ossec.conf"; fi

  if ! grep -q "/var/log/syslog" /var/ossec/etc/ossec.conf 2>/dev/null; then
    run_cmd "Adding syslog to ossec.conf" \
      "python3 -c \"
path='/var/ossec/etc/ossec.conf'
b='\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n'
with open(path) as f: c=f.read()
i=c.rfind('</ossec_config>')
with open(path,'w') as f: f.write(c[:i]+b+c[i:])
\""
  else log_ok "syslog in ossec.conf"; fi

  run_cmd "Starting Wazuh agent" \
    "systemctl daemon-reload && systemctl enable wazuh-agent && systemctl restart wazuh-agent"

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 4 — Falco${NC}"
  separator
  if ! dpkg -l 2>/dev/null | grep -q "^ii  falco"; then
    run_cmd "Adding Falco GPG key" \
      "curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg"
    run_cmd "Adding Falco repo" \
      "echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' | tee /etc/apt/sources.list.d/falcosecurity.list"
    run_cmd "apt-get update" "apt-get update -qq"
    run_cmd "Installing Falco" "FALCO_FRONTEND=noninteractive apt-get install -y falco"
  else log_ok "Falco $(dpkg -l falco 2>/dev/null | awk '/^ii/{print $3}')"; fi

  run_cmd "JSON output ON" "sed -i 's/^json_output: false/json_output: true/' /etc/falco/falco.yaml"
  run_cmd "File output ON" "sed -i '/^file_output:/,/enabled:/{s/enabled: false/enabled: true/}' /etc/falco/falco.yaml"
  run_cmd "Set log path" "sed -i 's|filename:.*|filename: /var/log/falco.log|' /etc/falco/falco.yaml"
  run_cmd "Set permissions" "touch /var/log/falco.log && chmod 644 /var/log/falco.log && echo 'f /var/log/falco.log 0644 root root -' > /etc/tmpfiles.d/falco.conf"
  deploy_falco_rules_silent
  log_ok "FilelessShield rules written (17 rules)"
  run_cmd "Starting Falco eBPF" "systemctl enable falco-modern-bpf && systemctl restart falco-modern-bpf"

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 5 — Wazuh Manager Integration${NC}"
  separator
  MANAGER=$(get_manager_container)
  if [ -z "$MANAGER" ]; then
    log_warn "Manager container not found — skipping"
  else
    deploy_wazuh_decoder_silent "$MANAGER"
    log_ok "Falco decoder deployed"
    deploy_wazuh_rules_silent "$MANAGER"
    log_ok "Falco rules 100200–100203 deployed"
    run_cmd "Validating syntax" "docker exec $MANAGER /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -v 'ERROR\|CRITICAL' || true"
    run_cmd "Restarting manager" "docker restart $MANAGER"
    echo -ne "  ${CYAN}→${NC}  Waiting for analysisd"
    for i in {1..12}; do
      echo -n "."
      sleep 5
      docker exec "$MANAGER" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running" && break
    done
    echo ""
    log_ok "Manager up — Falco rules active"
  fi

  echo ""
  separator
  echo -e "  ${CYAN}PHASE 6 — chkrootkit${NC}"
  separator
  run_cmd "Installing chkrootkit" "apt-get install -y chkrootkit"
  log_info "Running initial scan..."
  chkrootkit 2>&1 | tee /var/log/chkrootkit_first_scan.txt >>/tmp/wazuh_cli.log
  HITS=$(grep -ciE "infected|suspect|WARNING" /var/log/chkrootkit_first_scan.txt 2>/dev/null || echo 0)
  log_ok "Initial scan done — $HITS warning(s)"
  cat >/etc/cron.d/chkrootkit <<'CRON_EOF'
0 4 * * * root /usr/sbin/chkrootkit 2>&1 | grep -iE "infected|suspect|WARNING" | grep -v "not infected" | logger -p security.warning -t chkrootkit
CRON_EOF
  log_ok "Daily cron: 04:00 → syslog → Wazuh"
  chkrootkit 2>&1 | grep -iE "infected|suspect|WARNING" | grep -v "not infected" | logger -p security.warning -t chkrootkit 2>/dev/null
  sleep 2
  log_ok "syslog pipeline: $(grep -c 'chkrootkit' /var/log/syslog 2>/dev/null || echo 0) entries"

  MANAGER=$(get_manager_container)
  if [ -n "$MANAGER" ]; then
    deploy_chkrootkit_rules_silent "$MANAGER"
    run_cmd "Reloading manager rules" "docker exec $MANAGER /var/ossec/bin/ossec-control reload"
    log_ok "chkrootkit rules 100300–100302 active"
    logger -p security.warning -t chkrootkit "WARNING: test INFECTED binary /usr/bin/test"
    sleep 5
    ALERT=$(docker exec "$MANAGER" grep "chkrootkit" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -1 | python3 -c "
import sys,json
try:
  e=json.loads(sys.stdin.read()); print('[level',str(e['rule']['level'])+']',e['rule']['description'])
except: print('no alert yet')
" 2>/dev/null)
    log_info "Pipeline test: $ALERT"
  fi

  echo ""
  separator
  PUBLIC_IP=$(get_public_ip)
  echo -e "  ${GREEN}${BOLD}✔  SETUP COMPLETE${NC}"
  separator
  echo -e "  ${DIM}Wazuh Stack     ${NC}Manager + Indexer + Dashboard (Docker)"
  echo -e "  ${DIM}Wazuh Agent     ${NC}→ 127.0.0.1:1514"
  echo -e "  ${DIM}Falco eBPF      ${NC}/var/log/falco.log (17 rules)"
  echo -e "  ${DIM}Falco→Wazuh     ${NC}Rules 100200–100203"
  echo -e "  ${DIM}chkrootkit      ${NC}Daily 04:00 → syslog → Rules 100300–100302"
  separator
  echo -e "  ${WHITE}Dashboard:${NC}  ${CYAN}https://${PUBLIC_IP}${NC}  ${DIM}(admin / SecretPassword)${NC}"
  separator
  pause
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. STATUS
# ══════════════════════════════════════════════════════════════════════════════
menu_status() {
  while true; do
    header
    echo -e "  ${GREEN}${BOLD}◉  SYSTEM STATUS${NC}"
    separator
    echo ""
    echo -e "  ${WHITE}Docker Containers${NC}"
    echo ""
    FOUND=0
    while IFS=$'\t' read -r name status; do
      FOUND=1
      echo "$status" | grep -q "Up" &&
        echo -e "  ${GREEN}●${NC} ${WHITE}$name${NC}  ${DIM}$status${NC}" ||
        echo -e "  ${RED}●${NC} ${WHITE}$name${NC}  ${DIM}$status${NC}"
    done < <(docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null | grep -i "wazuh")
    [ "$FOUND" -eq 0 ] && log_warn "No Wazuh containers found"

    echo ""
    separator
    echo -e "  ${WHITE}Host Services${NC}"
    echo ""
    for svc in wazuh-agent falco-modern-bpf; do
      st=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
      [ "$st" = "active" ] &&
        echo -e "  ${GREEN}●${NC} ${WHITE}$svc${NC}  ${DIM}(running)${NC}" ||
        echo -e "  ${RED}●${NC} ${WHITE}$svc${NC}  ${DIM}($st)${NC}"
    done

    echo ""
    separator
    echo -e "  ${WHITE}Falco Log${NC}"
    echo ""
    if [ -f /var/log/falco.log ]; then
      lines=$(wc -l </var/log/falco.log)
      size=$(du -sh /var/log/falco.log | cut -f1)
      last=$(tail -1 /var/log/falco.log 2>/dev/null | python3 -c \
        "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('rule','?'))" 2>/dev/null || echo "N/A")
      log_ok "/var/log/falco.log — ${lines} lines, ${size}  |  Last: ${last}"
    else log_warn "/var/log/falco.log not found"; fi

    echo ""
    separator
    echo -e "  ${WHITE}Wazuh Manager Processes${NC}"
    echo ""
    MANAGER=$(get_manager_container)
    if [ -n "$MANAGER" ]; then
      docker exec "$MANAGER" /var/ossec/bin/wazuh-control status 2>/dev/null |
        grep -v "not used\|removing" |
        while read -r l; do
          echo "$l" | grep -q "is running" &&
            echo -e "  ${GREEN}●${NC} ${DIM}$l${NC}" || echo -e "  ${RED}●${NC} ${DIM}$l${NC}"
        done
    else log_warn "Manager container not found"; fi

    echo ""
    separator
    echo -e "  ${WHITE}Indexer Health${NC}"
    echo ""
    result=$(curl -s -k -u admin:SecretPassword "https://localhost:9200/_cluster/health" \
      --connect-timeout 3 2>/dev/null | python3 -c \
      "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'),'— nodes:',d.get('number_of_nodes','?'))" 2>/dev/null)
    [ -n "$result" ] && log_ok "Indexer: $result" || log_warn "Indexer not reachable"

    echo ""
    separator
    echo -e "  ${WHITE}chkrootkit${NC}"
    echo ""
    if command -v chkrootkit &>/dev/null; then
      log_ok "$(chkrootkit -V 2>&1 | head -1)"
      if [ -f /var/log/chkrootkit_last_scan.txt ]; then
        HITS=$(grep -ciE "infected|suspect|WARNING" /var/log/chkrootkit_last_scan.txt 2>/dev/null || echo 0)
        [ "$HITS" -gt 0 ] && log_warn "Last scan: $HITS warning(s)" || log_ok "Last scan: clean"
      else log_info "No scan run yet"; fi
    else log_warn "chkrootkit not installed"; fi

    echo ""
    separator
    echo -e "  ${DIM}[R] Refresh   [0] Back${NC}"
    echo -ne "\n  ${WHITE}Choice: ${NC}"
    read -r -n1 ch
    echo ""
    case "$ch" in r | R) continue ;; *) return ;; esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. ATTACKS
# ══════════════════════════════════════════════════════════════════════════════
menu_attacks() {
  while true; do
    header
    echo -e "  ${RED}${BOLD}⚡  SIMULATE ATTACKS${NC}"
    separator
    echo ""
    echo -e "  Each entry shows what the attack does, why it's dangerous,"
    echo -e "  which Falco rule fires, and what appears in Wazuh dashboard."
    echo -e "  ${DIM}After running: Dashboard → Security Events → rule.groups: falco${NC}"
    echo ""
    separator
    echo ""
    echo -e "  ${CYAN}[1]${NC}  ${WHITE}Read /etc/shadow${NC}  ${DIM}— credential harvesting${NC}"
    echo -e "      ${DIM}Reads hashed passwords. First step after gaining access.${NC}"
    echo ""
    echo -e "  ${CYAN}[2]${NC}  ${WHITE}Python Reverse Shell${NC}  ${DIM}— command & control${NC}"
    echo -e "      ${DIM}Opens a raw socket to external IP. Simulates C2 beaconing.${NC}"
    echo ""
    echo -e "  ${CYAN}[3]${NC}  ${WHITE}LD_PRELOAD Injection${NC}  ${DIM}— rootkit installation${NC}"
    echo -e "      ${DIM}Writes /etc/ld.so.preload. Forces .so into EVERY process.${NC}"
    echo ""
    echo -e "  ${CYAN}[4]${NC}  ${WHITE}curl|bash Delivery${NC}  ${DIM}— fileless dropper${NC}"
    echo -e "      ${DIM}Downloads and runs payload in one line. Nothing saved to disk.${NC}"
    echo ""
    echo -e "  ${CYAN}[5]${NC}  ${WHITE}Cron Persistence${NC}  ${DIM}— survives reboots${NC}"
    echo -e "      ${DIM}Writes a root cron job. Executes automatically every minute.${NC}"
    echo ""
    echo -e "  ${CYAN}[6]${NC}  ${WHITE}Base64 Obfuscation${NC}  ${DIM}— evades string detection${NC}"
    echo -e "      ${DIM}Hides command inside base64 blob. Bypasses simple IDS rules.${NC}"
    echo ""
    echo -e "  ${RED}[A]${NC}  ${RED}${BOLD}Run ALL 6 attacks in sequence${NC}"
    separator
    echo -e "  ${DIM}[0] Back${NC}"
    echo -ne "\n  ${WHITE}Choose: ${NC}"
    read -r choice
    echo ""

    case "$choice" in
    1) attack_shadow ;; 2) attack_python ;; 3) attack_ldpreload ;;
    4) attack_curlbash ;; 5) attack_cron ;; 6) attack_base64 ;;
    a | A)
      echo -e "  ${RED}${BOLD}Running all 6 attacks...${NC}"
      separator
      attack_shadow
      attack_python
      attack_ldpreload
      attack_curlbash
      attack_cron
      attack_base64
      echo ""
      separator
      log_ok "All 6 attacks done"
      log_info "Dashboard → Security Events → ${WHITE}rule.groups: falco${NC}"
      separator
      pause
      ;;
    0) return ;;
    *)
      echo -e "  ${RED}Invalid${NC}"
      sleep 1
      ;;
    esac
  done
}

attack_shadow() {
  attack_card "1" "Read /etc/shadow" \
    "Reads /etc/shadow — the file containing every user's hashed password" \
    "Hashed passwords can be cracked offline. Reading this file is a sign of credential theft." \
    "Read sensitive file untrusted | Priority: Warning" \
    "Rule 100202 fired | Level 10" \
    "T1003.008 — Credential Dumping via /etc/shadow"
  log_run "cat /etc/shadow > /dev/null"
  cat /etc/shadow >/dev/null 2>&1
  sleep 1
  log_alert "Falco fired: Read sensitive file untrusted [Warning]"
  log_alert "Wazuh: Rule 100202 → Level 10"
  echo ""
  log_info "Dashboard description: Falco Warning: Read sensitive file untrusted (proc=cat file=/etc/shadow)"
  pause
}

attack_python() {
  attack_card "2" "Python Reverse Shell" \
    "python3 opens a raw TCP socket to 8.8.8.8:9999 — simulating a C2 callback" \
    "Scripting runtimes making raw outbound connections = reverse shell or data exfiltration." \
    "Scripting Runtime Opens Outbound Connection | Priority: Error" \
    "Rule 100203 fired | Level 13" \
    "T1059.006 — Command & Scripting Interpreter: Python"
  log_run "python3 -c 'socket.connect((8.8.8.8, 9999))'"
  python3 -c "
import socket; s=socket.socket()
try: s.settimeout(1); s.connect(('8.8.8.8',9999))
except: pass
s.close()" 2>/dev/null
  sleep 1
  log_crit "Falco fired: RUNTIME OUTBOUND CONNECTION [Error]"
  log_crit "Wazuh: Rule 100203 → Level 13"
  echo ""
  log_info "Dashboard description: Falco Critical: RUNTIME OUTBOUND CONNECTION (proc=python3 dest=8.8.8.8)"
  pause
}

attack_ldpreload() {
  attack_card "3" "LD_PRELOAD Injection" \
    "Writes /tmp/evil.so path into /etc/ld.so.preload then removes it" \
    "This forces the attacker's .so file into every single process on the system — instant rootkit." \
    "Global LD_PRELOAD Config Modified | Priority: CRITICAL" \
    "Rule 100203 fired | Level 13" \
    "T1574.006 — Hijack Execution Flow: LD_PRELOAD"
  log_run "echo /tmp/evil.so | tee /etc/ld.so.preload"
  echo "/tmp/evil.so" | tee /etc/ld.so.preload >/dev/null 2>&1
  sleep 0.5
  rm -f /etc/ld.so.preload
  sleep 1
  log_crit "Falco fired: /etc/ld.so.preload MODIFIED [CRITICAL]"
  log_crit "Wazuh: Rule 100203 → Level 13"
  echo ""
  log_info "Dashboard description: Falco Critical: /etc/ld.so.preload MODIFIED (writer=tee pid=XXXX user=root)"
  pause
}

attack_curlbash() {
  attack_card "4" "curl|bash Delivery" \
    "Spins up a local HTTP server, downloads payload.sh, pipes it into bash in one command" \
    "The script never saves to disk in a visible way. Most common payload delivery technique." \
    "Shell Spawned from Unusual Parent | Priority: Error" \
    "Rule 100203 fired | Level 13" \
    "T1059.004 — Unix Shell via pipe"
  log_run "curl http://127.0.0.1:8889/payload.sh | bash"
  echo 'echo "payload executed"' >/tmp/payload.sh
  python3 -m http.server 8889 -d /tmp &>/dev/null &
  SERVER_PID=$!
  sleep 1
  curl -s http://127.0.0.1:8889/payload.sh 2>/dev/null | bash 2>/dev/null
  kill "$SERVER_PID" 2>/dev/null
  rm -f /tmp/payload.sh
  sleep 1
  log_crit "Falco fired: SHELL FROM UNUSUAL PARENT [Error]"
  log_crit "Wazuh: Rule 100203 → Level 13"
  echo ""
  log_info "Dashboard description: Falco Critical: SHELL FROM UNUSUAL PARENT (shell=bash parent=curl user=root)"
  pause
}

attack_cron() {
  attack_card "5" "Cron Persistence" \
    "Writes '* * * * * root id' into /etc/cron.d/backdoor then removes it" \
    "Cron jobs survive reboots and run automatically as root — classic post-exploitation persistence." \
    "Cron Persistence Write | Priority: Warning" \
    "Rule 100202 fired | Level 10" \
    "T1053.003 — Scheduled Task: Cron"
  log_run "echo '* * * * * root id' > /etc/cron.d/backdoor"
  echo "* * * * * root id" >/etc/cron.d/backdoor 2>/dev/null
  sleep 0.5
  rm -f /etc/cron.d/backdoor
  sleep 1
  log_alert "Falco fired: CRON PERSISTENCE WRITE [Warning]"
  log_alert "Wazuh: Rule 100202 → Level 10"
  echo ""
  log_info "Dashboard description: Falco Warning: CRON PERSISTENCE WRITE (writer=bash file=/etc/cron.d/backdoor)"
  pause
}

attack_base64() {
  attack_card "6" "Base64 Obfuscation" \
    "Encodes 'id' as base64 (aWQ=), decodes at runtime, pipes into bash" \
    "Hides the real command from static scanners. The payload is invisible until execution." \
    "Base64 Encoded Command Execution | Priority: Warning" \
    "Rule 100202 fired | Level 10" \
    "T1027 — Obfuscated Files or Information"
  log_run "echo 'aWQ=' | base64 -d | bash   # 'aWQ=' decodes to: id"
  echo 'aWQ=' | base64 -d | bash >/dev/null 2>&1
  sleep 1
  log_alert "Falco fired: BASE64-ENCODED EXECUTION [Warning]"
  log_alert "Wazuh: Rule 100202 → Level 10"
  echo ""
  log_info "Dashboard description: Falco Warning: BASE64-ENCODED EXECUTION (proc=bash cmdline=...base64 -d...)"
  pause
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. LIVE LOGS
# ══════════════════════════════════════════════════════════════════════════════
menu_logs() {
  while true; do
    header
    echo -e "  ${YELLOW}${BOLD}◈  LIVE LOGS${NC}"
    separator
    echo ""
    echo -e "  ${CYAN}[1]${NC}  Falco raw stream           ${DIM}/var/log/falco.log${NC}"
    echo -e "  ${CYAN}[2]${NC}  Falco pretty print         ${DIM}rule + priority + timestamp${NC}"
    echo -e "  ${CYAN}[3]${NC}  Wazuh alerts stream        ${DIM}alerts.json in container${NC}"
    echo -e "  ${CYAN}[4]${NC}  Wazuh agent log            ${DIM}/var/ossec/logs/ossec.log${NC}"
    echo -e "  ${CYAN}[5]${NC}  Last 20 Falco alerts       ${DIM}snapshot${NC}"
    echo -e "  ${CYAN}[6]${NC}  Last 20 Wazuh alerts       ${DIM}snapshot${NC}"
    echo -e "  ${CYAN}[7]${NC}  chkrootkit syslog          ${DIM}snapshot${NC}"
    separator
    echo -e "  ${DIM}[0] Back${NC}"
    echo -ne "\n  ${WHITE}Choose: ${NC}"
    read -r choice
    echo ""

    case "$choice" in
    1)
      echo -e "  ${DIM}Ctrl+C to stop${NC}"
      echo ""
      tail -f /var/log/falco.log 2>/dev/null || log_warn "falco.log not found"
      ;;
    2)
      echo -e "  ${DIM}Pretty Falco stream — Ctrl+C to stop${NC}"
      echo ""
      tail -f /var/log/falco.log 2>/dev/null | while read -r line; do
        rule=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('rule','?'))" 2>/dev/null)
        prio=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('priority','?'))" 2>/dev/null)
        ts=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('time','?')[:19])" 2>/dev/null)
        case "$prio" in
        CRITICAL | Alert | Emergency) echo -e "  ${RED}[$ts] [$prio]${NC} $rule" ;;
        ERROR | Error) echo -e "  ${YELLOW}[$ts] [$prio]${NC} $rule" ;;
        WARNING | Warning) echo -e "  ${CYAN}[$ts] [$prio]${NC} $rule" ;;
        *) echo -e "  ${DIM}[$ts] [$prio] $rule${NC}" ;;
        esac
      done
      ;;
    3)
      MANAGER=$(get_manager_container)
      [ -z "$MANAGER" ] && log_warn "Manager not found" && pause && continue
      echo -e "  ${DIM}Wazuh alerts — Ctrl+C to stop${NC}"
      echo ""
      docker exec -it "$MANAGER" tail -f /var/ossec/logs/alerts/alerts.json 2>/dev/null
      ;;
    4)
      echo -e "  ${DIM}Agent log — Ctrl+C to stop${NC}"
      echo ""
      tail -f /var/ossec/logs/ossec.log 2>/dev/null || log_warn "Agent log not found"
      ;;
    5)
      echo -e "  ${WHITE}Last 20 Falco alerts:${NC}"
      echo ""
      tail -20 /var/log/falco.log 2>/dev/null | while read -r line; do
        rule=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('rule','?'))" 2>/dev/null)
        prio=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('priority','?'))" 2>/dev/null)
        ts=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('time','?')[:19])" 2>/dev/null)
        case "$prio" in
        CRITICAL | Alert | Emergency) echo -e "  ${RED}$ts  [$prio]${NC}  $rule" ;;
        ERROR | Error) echo -e "  ${YELLOW}$ts  [$prio]${NC}  $rule" ;;
        *) echo -e "  ${DIM}$ts${NC}  ${CYAN}[$prio]${NC}  $rule" ;;
        esac
      done || log_warn "falco.log not found"
      pause
      ;;
    6)
      MANAGER=$(get_manager_container)
      [ -z "$MANAGER" ] && log_warn "Manager not found" && pause && continue
      echo -e "  ${WHITE}Last 20 Wazuh alerts:${NC}"
      echo ""
      docker exec "$MANAGER" tail -20 /var/ossec/logs/alerts/alerts.json 2>/dev/null |
        python3 -c "
import sys,json
for line in sys.stdin:
  try:
    d=json.loads(line); r=d.get('rule',{})
    ts=d.get('timestamp','')[:19]; lvl=r.get('level','?'); desc=r.get('description','?')
    print(f'  [{ts}]  Lvl:{lvl:>2}  {desc}')
  except: pass
" 2>/dev/null || log_warn "No alerts"
      pause
      ;;
    7)
      echo -e "  ${WHITE}chkrootkit syslog entries:${NC}"
      echo ""
      grep "chkrootkit" /var/log/syslog 2>/dev/null | tail -20 |
        while read -r l; do echo -e "  ${DIM}$l${NC}"; done ||
        log_warn "No chkrootkit entries in syslog"
      pause
      ;;
    0) return ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. FALCO RULES MANAGER
# ══════════════════════════════════════════════════════════════════════════════
deploy_falco_rules_silent() {
  cat >/etc/falco/falco_rules.local.yaml <<'FALCO_EOF'
- list: shell_binaries
  items: [sh, bash, dash, zsh, ksh, fish, tcsh, csh, rbash]
- list: scripting_runtimes
  items: [python3, python, python2, perl, ruby, php, node, nodejs,
          lua, tclsh, wish, awk, gawk, nawk, mawk, groovy]
- list: sensitive_services
  items: [nginx, apache2, httpd, lighttpd, mysqld, postgres, mongod,
          redis-server, sshd, docker, tomcat, java, php-fpm, uwsgi, gunicorn]
- list: known_package_managers
  items: [apt, apt-get, dpkg, yum, dnf, rpm, pip, pip3, gem, npm]
- list: known_safe_shell_parents
  items: [sshd, sudo, su, tmux, screen, login, bash, zsh, sh,
          systemd, init, cron, crond, fish, ksh]
- macro: spawned_process
  condition: evt.type = execve
- macro: file_opened_for_write
  condition: >
    (evt.type in (open, openat, openat2))
    and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)
- macro: network_connection
  condition: >
    evt.type in (connect, accept) and (fd.type = ipv4 or fd.type = ipv6)
- macro: is_shell
  condition: proc.name in (shell_binaries)
- macro: is_scripting_runtime
  condition: proc.name in (scripting_runtimes)
- macro: executing_from_suspicious_dir
  condition: >
    spawned_process
    and (proc.exe startswith /tmp/ or proc.exe startswith /dev/shm/ or proc.exe startswith /var/tmp/)
- macro: parent_is_service
  condition: proc.pname in (sensitive_services)
- macro: known_false_positive_procs
  condition: proc.name in (known_package_managers) or proc.pname in (known_package_managers)

- rule: Anonymous Memory File Execution
  desc: memfd_create called — fileless payload in RAM
  condition: evt.type = memfd_create and not known_false_positive_procs
  output: FILELESS EXEC via memfd_create (proc=%proc.name pid=%proc.pid user=%user.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [T1106, fileless]
- rule: Process Memory Injection Detected
  desc: ptrace or process_vm_writev — process injection
  condition: >
    evt.type in (ptrace, process_vm_writev, process_vm_readv)
    and evt.arg.request != PTRACE_TRACEME
    and not proc.name in (gdb, strace, ltrace, perf, valgrind)
    and not known_false_positive_procs
  output: PROCESS INJECTION (injector=%proc.name pid=%proc.pid syscall=%evt.type user=%user.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [T1055, injection]
- rule: Sensitive Service Spawns Shell or Runtime
  desc: Web/db service spawned shell — webshell or RCE
  condition: spawned_process and parent_is_service and (is_shell or is_scripting_runtime)
  output: SERVICE SPAWNED SHELL (service=%proc.pname shell=%proc.name pid=%proc.pid user=%user.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [T1059, webshell]
- rule: Execution from Temporary Directory
  desc: Binary executed from /tmp or /dev/shm — staged payload
  condition: executing_from_suspicious_dir
  output: EXEC FROM TEMP DIR (proc=%proc.name pid=%proc.pid exe=%proc.exe user=%user.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [T1059, staged_payload]
- rule: Global LD_PRELOAD Config Modified
  desc: /etc/ld.so.preload written — system-wide library injection
  condition: file_opened_for_write and fd.name = /etc/ld.so.preload
  output: /etc/ld.so.preload MODIFIED (writer=%proc.name pid=%proc.pid user=%user.name)
  priority: CRITICAL
  tags: [T1574.006, rootkit]
- rule: Scripting Runtime Opens Outbound Connection
  desc: Python/perl/ruby outbound socket — possible reverse shell
  condition: >
    network_connection and evt.type = connect and is_scripting_runtime
    and fd.sip != "127.0.0.1" and fd.sip != "::1"
  output: RUNTIME OUTBOUND CONNECTION (proc=%proc.name pid=%proc.pid dest=%fd.sip user=%user.name cmdline=%proc.cmdline)
  priority: ERROR
  tags: [T1059, reverse_shell]
- rule: Shell Spawned from Unusual Parent
  desc: Shell from non-standard parent — post-exploitation
  condition: >
    spawned_process and is_shell
    and not proc.pname in (known_safe_shell_parents) and not known_false_positive_procs
  output: SHELL FROM UNUSUAL PARENT (shell=%proc.name pid=%proc.pid parent=%proc.pname user=%user.name cmdline=%proc.cmdline)
  priority: ERROR
  tags: [T1059, post_exploitation]
- rule: Bash Built-in Reverse Shell via dev tcp
  desc: /dev/tcp used — bash reverse shell without binary
  condition: evt.type in (open, openat) and fd.name startswith /dev/tcp/
  output: DEV TCP REVERSE SHELL (proc=%proc.name pid=%proc.pid dest=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: ERROR
  tags: [T1059.004, reverse_shell]
- rule: Network Tunnel Tool Spawned
  desc: nc/socat spawned — bind/reverse shell or tunnel
  condition: >
    spawned_process and proc.name in (nc, ncat, netcat, socat)
    and not proc.pname in (known_safe_shell_parents)
  output: NETWORK TUNNEL TOOL (proc=%proc.name pid=%proc.pid parent=%proc.pname user=%user.name cmdline=%proc.cmdline)
  priority: ERROR
  tags: [T1059, T1071]
- rule: Executable Written to Temp Directory
  desc: Executable written to /tmp — dropper stage
  condition: >
    file_opened_for_write
    and (fd.name startswith /tmp/ or fd.name startswith /dev/shm/ or fd.name startswith /var/tmp/)
    and (fd.name endswith .sh or fd.name endswith .py or fd.name endswith .pl or fd.name endswith .elf)
    and not known_false_positive_procs
  output: EXECUTABLE WRITTEN TO TEMP DIR (writer=%proc.name pid=%proc.pid file=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: ERROR
  tags: [T1059, dropper]
- rule: Cron Persistence Write
  desc: Crontab or cron.d modified — scheduled persistence
  condition: >
    file_opened_for_write
    and (fd.name startswith /etc/cron or fd.name startswith /var/spool/cron or fd.name = /etc/rc.local)
    and not proc.name in (crontab, anacron, run-parts) and not known_false_positive_procs
  output: CRON PERSISTENCE WRITE (writer=%proc.name pid=%proc.pid file=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1053.003, persistence]
- rule: Systemd Unit Created or Modified
  desc: New systemd unit written — reboot-persistent execution
  condition: >
    file_opened_for_write
    and (fd.name startswith /etc/systemd/system/ or fd.name startswith /lib/systemd/system/)
    and not known_false_positive_procs
  output: SYSTEMD UNIT WRITTEN (writer=%proc.name pid=%proc.pid unit=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1543.002, persistence]
- rule: SSH Authorized Keys Modified
  desc: authorized_keys written — SSH backdoor key
  condition: >
    file_opened_for_write and fd.name endswith /.ssh/authorized_keys
    and not proc.name in (sshd, ssh-keygen, ansible)
  output: SSH AUTHORIZED_KEYS MODIFIED (writer=%proc.name pid=%proc.pid file=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1098.004, persistence]
- rule: Base64 Encoded Command Execution
  desc: base64 decode piped to execution — obfuscation
  condition: >
    spawned_process
    and (proc.cmdline contains "base64 -d" or proc.cmdline contains "base64 --decode"
         or proc.cmdline contains "|base64")
  output: BASE64-ENCODED EXECUTION (proc=%proc.name pid=%proc.pid user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1027, obfuscation]
- rule: New System User Created
  desc: useradd or adduser — possible backdoor account
  condition: spawned_process and proc.name in (useradd, adduser, usermod) and not known_false_positive_procs
  output: NEW USER CREATED (proc=%proc.name pid=%proc.pid user=%user.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1136, persistence]
- rule: Shell Startup File Modified
  desc: bashrc or profile.d modified — login persistence
  condition: >
    file_opened_for_write
    and (fd.name startswith /etc/profile.d/
         or fd.name in (/etc/bash.bashrc, /etc/profile, /root/.bashrc, /root/.bash_profile))
    and not known_false_positive_procs
  output: SHELL STARTUP FILE MODIFIED (writer=%proc.name pid=%proc.pid file=%fd.name user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [T1546.004, persistence]
FALCO_EOF
}

menu_falco_rules() {
  while true; do
    header
    echo -e "  ${MAGENTA}${BOLD}◆  FALCO RULES MANAGER${NC}"
    separator
    echo ""
    echo -e "  ${CYAN}[1]${NC}  List active rules"
    echo -e "  ${CYAN}[2]${NC}  Validate syntax"
    echo -e "  ${CYAN}[3]${NC}  Deploy FilelessShield rules (overwrite)"
    echo -e "  ${CYAN}[4]${NC}  Reload Falco"
    echo -e "  ${CYAN}[5]${NC}  View rule file"
    separator
    echo -e "  ${DIM}[0] Back${NC}"
    echo -ne "\n  ${WHITE}Choose: ${NC}"
    read -r choice
    echo ""

    case "$choice" in
    1)
      echo -e "  ${WHITE}Active rules:${NC}"
      echo ""
      awk '/^- rule:/{r=substr($0,9)} /priority:/{p=$2; if(p=="CRITICAL") c="\033[0;31m"; else if(p=="ERROR") c="\033[1;33m"; else c="\033[0;36m"; printf "  "c"["p"]""\033[0m"" "r"\n"}' \
        /etc/falco/falco_rules.local.yaml 2>/dev/null || log_warn "No local rules"
      echo ""
      log_info "Total: $(grep -c '^- rule:' /etc/falco/falco_rules.local.yaml 2>/dev/null || echo 0) rules"
      pause
      ;;
    2)
      echo -e "  ${WHITE}Validating...${NC}"
      echo ""
      result=$(falco --dry-run 2>&1)
      echo "$result" | grep -q "^Error:" &&
        {
          log_err "Errors:"
          echo "$result" | grep "LOAD_ERR" | while read -r l; do echo -e "  ${RED}  $l${NC}"; done
        } ||
        log_ok "All rules valid"
      pause
      ;;
    3)
      if confirm "Overwrite with FilelessShield v1.1.0?"; then
        cp /etc/falco/falco_rules.local.yaml "/etc/falco/falco_rules.local.yaml.bak.$(date +%s)" 2>/dev/null
        deploy_falco_rules_silent
        log_ok "Deployed: $(grep -c '^- rule:' /etc/falco/falco_rules.local.yaml) rules"
      fi
      pause
      ;;
    4)
      result=$(falco --dry-run 2>&1)
      echo "$result" | grep -q "^Error:" &&
        {
          log_err "Syntax errors — fix first"
          echo "$result" | grep "LOAD_ERR" | head -3 | while read -r l; do echo -e "  ${RED}  $l${NC}"; done
        } ||
        {
          run_cmd "Restarting falco-modern-bpf" "systemctl restart falco-modern-bpf"
          sleep 3
          st=$(systemctl is-active falco-modern-bpf)
          [ "$st" = "active" ] && log_ok "Falco running" || log_err "Failed — journalctl -u falco-modern-bpf"
        }
      pause
      ;;
    5)
      head -80 /etc/falco/falco_rules.local.yaml 2>/dev/null | while read -r line; do
        echo "$line" | grep -q "^- rule:" && echo -e "  ${MAGENTA}$line${NC}" ||
          { echo "$line" | grep -q "priority:" && echo -e "  ${YELLOW}  $line${NC}" ||
            echo -e "  ${DIM}$line${NC}"; }
      done
      log_info "Full file: /etc/falco/falco_rules.local.yaml"
      pause
      ;;
    0) return ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. WAZUH RULES MANAGER
# ══════════════════════════════════════════════════════════════════════════════
deploy_wazuh_decoder_silent() {
  local mgr="$1"
  docker exec "$mgr" bash -c 'cat > /var/ossec/etc/decoders/falco_decoders.xml << EOF
<decoder name="falco">
  <prematch>{"hostname":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
EOF
chown wazuh:wazuh /var/ossec/etc/decoders/falco_decoders.xml
chmod 660 /var/ossec/etc/decoders/falco_decoders.xml' 2>/dev/null
}

deploy_wazuh_rules_silent() {
  local mgr="$1"
  docker exec "$mgr" bash -c 'cat > /var/ossec/etc/rules/falco_rules.xml << EOF
<group name="falco,">
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">^syscall\$</field>
    <field name="rule">\.+</field>
    <description>Falco alert</description>
  </rule>
  <rule id="100201" level="5">
    <if_sid>100200</if_sid>
    <field name="priority">^Notice\$</field>
    <description>Falco Notice: \$(output)</description>
  </rule>
  <rule id="100202" level="10">
    <if_sid>100200</if_sid>
    <field name="priority">^Warning\$</field>
    <description>Falco Warning: \$(output)</description>
  </rule>
  <rule id="100203" level="13">
    <if_sid>100200</if_sid>
    <field name="priority">^Error\$|^Critical\$|^Alert\$|^Emergency\$</field>
    <description>Falco Critical: \$(output)</description>
  </rule>
</group>
EOF
chown wazuh:wazuh /var/ossec/etc/rules/falco_rules.xml
chmod 660 /var/ossec/etc/rules/falco_rules.xml' 2>/dev/null
}

deploy_chkrootkit_rules_silent() {
  local mgr="$1"
  docker exec "$mgr" bash -c "
grep -q 'chkrootkit' /var/ossec/etc/rules/local_rules.xml 2>/dev/null && exit 0
cat >> /var/ossec/etc/rules/local_rules.xml << 'WAZUH_EOF'

<!-- chkrootkit rules -->
<group name=\"chkrootkit,rootkit,\">
  <rule id=\"100300\" level=\"12\">
    <program_name>chkrootkit</program_name>
    <match>INFECTED</match>
    <description>chkrootkit: ROOTKIT binary detected</description>
    <mitre><id>T1014</id></mitre>
  </rule>
  <rule id=\"100301\" level=\"10\">
    <program_name>chkrootkit</program_name>
    <match>suspect</match>
    <description>chkrootkit: Suspicious file or activity detected</description>
    <mitre><id>T1014</id></mitre>
  </rule>
  <rule id=\"100302\" level=\"8\">
    <program_name>chkrootkit</program_name>
    <match>WARNING</match>
    <description>chkrootkit: Warning — possible rootkit indicator</description>
    <mitre><id>T1014</id></mitre>
  </rule>
</group>
WAZUH_EOF
" 2>/dev/null
}

menu_wazuh_rules() {
  while true; do
    header
    echo -e "  ${CYAN}${BOLD}✎  WAZUH RULES MANAGER${NC}"
    separator
    echo ""
    echo -e "  ${CYAN}[1]${NC}  Show Falco decoder"
    echo -e "  ${CYAN}[2]${NC}  Show Falco rules (100200–100203)"
    echo -e "  ${CYAN}[3]${NC}  Show chkrootkit rules (100300–100302)"
    echo -e "  ${CYAN}[4]${NC}  Redeploy Falco decoder + rules"
    echo -e "  ${CYAN}[5]${NC}  Test with wazuh-logtest"
    echo -e "  ${CYAN}[6]${NC}  Validate config syntax"
    echo -e "  ${CYAN}[7]${NC}  Restart Wazuh manager"
    separator
    echo -e "  ${DIM}[0] Back${NC}"
    echo -ne "\n  ${WHITE}Choose: ${NC}"
    read -r choice
    echo ""

    MANAGER=$(get_manager_container)
    [ -z "$MANAGER" ] && log_warn "Manager container not found" && pause && continue

    case "$choice" in
    1)
      echo -e "  ${WHITE}falco_decoders.xml:${NC}"
      echo ""
      docker exec "$MANAGER" cat /var/ossec/etc/decoders/falco_decoders.xml 2>/dev/null |
        while read -r l; do echo -e "  ${DIM}$l${NC}"; done || log_warn "Not found"
      pause
      ;;
    2)
      echo -e "  ${WHITE}falco_rules.xml:${NC}"
      echo ""
      docker exec "$MANAGER" cat /var/ossec/etc/rules/falco_rules.xml 2>/dev/null |
        while read -r l; do
          echo "$l" | grep -q "description" && echo -e "  ${CYAN}$l${NC}" || echo -e "  ${DIM}$l${NC}"
        done || log_warn "Not found"
      pause
      ;;
    3)
      echo -e "  ${WHITE}local_rules.xml (chkrootkit):${NC}"
      echo ""
      docker exec "$MANAGER" grep -A20 "chkrootkit" /var/ossec/etc/rules/local_rules.xml 2>/dev/null |
        while read -r l; do echo -e "  ${DIM}$l${NC}"; done || log_warn "Not found"
      pause
      ;;
    4)
      if confirm "Redeploy to $MANAGER?"; then
        deploy_wazuh_decoder_silent "$MANAGER" && log_ok "Decoder deployed"
        deploy_wazuh_rules_silent "$MANAGER" && log_ok "Rules deployed"
        log_info "Restart manager [7] to apply"
      fi
      pause
      ;;
    5)
      echo -e "  ${WHITE}wazuh-logtest — paste Falco JSON, Ctrl+C to exit${NC}"
      echo -e "  ${DIM}Sample:${NC}"
      echo -e '  {"hostname":"host","output":"test","priority":"Critical","rule":"Global LD_PRELOAD Config Modified","source":"syscall","time":"2026-03-08T00:00:00Z"}'
      echo ""
      docker exec -it "$MANAGER" /var/ossec/bin/wazuh-logtest
      ;;
    6)
      result=$(docker exec "$MANAGER" /var/ossec/bin/wazuh-analysisd -t 2>&1)
      echo "$result" | grep -q "ERROR\|CRITICAL" &&
        {
          log_err "Errors:"
          echo "$result" | grep "ERROR\|CRITICAL" | while read -r l; do echo -e "  ${RED}  $l${NC}"; done
        } ||
        log_ok "Syntax OK"
      pause
      ;;
    7)
      if confirm "Restart $MANAGER?"; then
        run_cmd "Restarting" "docker restart $MANAGER"
        echo -ne "  ${CYAN}→${NC}  Waiting"
        for i in {1..12}; do
          echo -n "."
          sleep 5
          docker exec "$MANAGER" /var/ossec/bin/wazuh-control status 2>/dev/null |
            grep -q "wazuh-analysisd is running" && break
        done
        echo ""
        log_ok "Manager restarted"
      fi
      pause
      ;;
    0) return ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 7. DASHBOARD INFO
# ══════════════════════════════════════════════════════════════════════════════
menu_dashboard() {
  header
  echo -e "  ${BLUE}${BOLD}✦  DASHBOARD INFO${NC}"
  separator
  echo ""
  PUBLIC_IP=$(get_public_ip)
  echo -e "  ${WHITE}Access${NC}"
  echo -e "  ${CYAN}  https://${PUBLIC_IP}${NC}  ${DIM}(admin / SecretPassword)${NC}"
  echo ""
  separator
  echo -e "  ${WHITE}API Endpoints${NC}"
  echo -e "  ${DIM}  Wazuh API:   ${NC}https://${PUBLIC_IP}:55000"
  echo -e "  ${DIM}  Indexer:     ${NC}https://${PUBLIC_IP}:9200"
  echo ""
  separator
  echo -e "  ${WHITE}Useful Dashboard Filters${NC}"
  echo -e "  ${DIM}  All Falco:       ${CYAN}rule.groups: falco${NC}"
  echo -e "  ${DIM}  All chkrootkit:  ${CYAN}rule.groups: chkrootkit${NC}"
  echo -e "  ${DIM}  Critical:        ${CYAN}rule.level: 13${NC}"
  echo -e "  ${DIM}  High:            ${CYAN}rule.level: [10 TO 12]${NC}"
  echo -e "  ${DIM}  This agent:      ${CYAN}agent.name: $(hostname)${NC}"
  echo ""
  separator
  echo -e "  ${WHITE}Rule Reference${NC}"
  echo ""
  echo -e "  ${DIM}Falco (syscall detection)${NC}"
  echo -e "  ${DIM}  100200${NC}  Base match          ${DIM}Level  0${NC}"
  echo -e "  ${DIM}  100201${NC}  Notice              ${CYAN}Level  5${NC}"
  echo -e "  ${DIM}  100202${NC}  Warning             ${YELLOW}Level 10${NC}"
  echo -e "  ${DIM}  100203${NC}  Error / Critical    ${RED}Level 13${NC}"
  echo ""
  echo -e "  ${DIM}chkrootkit (rootkit scanner)${NC}"
  echo -e "  ${DIM}  100300${NC}  INFECTED binary     ${RED}Level 12${NC}"
  echo -e "  ${DIM}  100301${NC}  Suspect file        ${YELLOW}Level 10${NC}"
  echo -e "  ${DIM}  100302${NC}  WARNING indicator   ${CYAN}Level  8${NC}"
  echo ""
  separator
  pause
}

# ══════════════════════════════════════════════════════════════════════════════
# 8. CHKROOTKIT
# ══════════════════════════════════════════════════════════════════════════════
menu_chkrootkit() {
  while true; do
    header
    echo -e "  ${GREEN}${BOLD}🔍  CHKROOTKIT${NC}"
    separator
    echo ""
    echo -e "  ${DIM}Scans binaries against known rootkit signatures."
    echo -e "  Findings: syslog → Wazuh agent → Wazuh manager → Dashboard.${NC}"
    echo ""
    separator
    echo -e "  ${CYAN}[1]${NC}  Install chkrootkit"
    echo -e "  ${CYAN}[2]${NC}  Run full scan now"
    echo -e "  ${CYAN}[3]${NC}  Show last scan — warnings only"
    echo -e "  ${CYAN}[4]${NC}  Show last scan — full output"
    echo -e "  ${CYAN}[5]${NC}  Setup daily cron + syslog pipeline"
    echo -e "  ${CYAN}[6]${NC}  Deploy Wazuh rules (100300–100302)"
    echo -e "  ${CYAN}[7]${NC}  Test full pipeline end-to-end"
    echo -e "  ${CYAN}[8]${NC}  View last Wazuh chkrootkit alerts"
    separator
    echo -e "  ${DIM}[0] Back${NC}"
    echo -ne "\n  ${WHITE}Choose: ${NC}"
    read -r choice
    echo ""

    case "$choice" in
    1)
      run_cmd "Installing chkrootkit" "apt-get install -y chkrootkit"
      log_ok "$(chkrootkit -V 2>&1 | head -1)"
      pause
      ;;
    2)
      echo -e "  ${WHITE}Running full scan (~30 seconds)...${NC}"
      echo ""
      log_run "chkrootkit 2>&1 | tee /var/log/chkrootkit_last_scan.txt"
      chkrootkit 2>&1 | tee /var/log/chkrootkit_last_scan.txt | while read -r line; do
        echo "$line" | grep -iqE "INFECTED" && echo -e "  ${RED}☠  $line${NC}" ||
          { echo "$line" | grep -iqE "suspect|WARNING" && echo -e "  ${YELLOW}!  $line${NC}" ||
            echo -e "  ${DIM}   $line${NC}"; }
      done
      echo ""
      HITS=$(grep -ciE "infected|suspect|WARNING" /var/log/chkrootkit_last_scan.txt 2>/dev/null || echo 0)
      CLEAN=$(grep -c "not infected" /var/log/chkrootkit_last_scan.txt 2>/dev/null || echo 0)
      separator
      [ "$HITS" -gt 0 ] && log_warn "$HITS warning(s) — see option [3]" || log_ok "System clean"
      log_info "$CLEAN checks passed"
      pause
      ;;
    3)
      echo -e "  ${WHITE}Warnings only:${NC}"
      echo ""
      if [ -f /var/log/chkrootkit_last_scan.txt ]; then
        RES=$(grep -iE "infected|suspect|WARNING" /var/log/chkrootkit_last_scan.txt | grep -v "not infected")
        [ -z "$RES" ] && log_ok "No warnings — system clean" ||
          echo "$RES" | while read -r line; do
            echo "$line" | grep -iqE "INFECTED" && echo -e "  ${RED}☠  $line${NC}" || echo -e "  ${YELLOW}!  $line${NC}"
          done
      else log_warn "No scan yet — run [2]"; fi
      pause
      ;;
    4)
      echo -e "  ${WHITE}Full last scan:${NC}"
      echo ""
      if [ -f /var/log/chkrootkit_last_scan.txt ]; then
        cat /var/log/chkrootkit_last_scan.txt | while read -r line; do
          echo "$line" | grep -iqE "INFECTED" && echo -e "  ${RED}$line${NC}" ||
            { echo "$line" | grep -iqE "suspect|WARNING" && echo -e "  ${YELLOW}$line${NC}" ||
              echo -e "  ${DIM}$line${NC}"; }
        done
      else log_warn "No scan yet — run [2]"; fi
      pause
      ;;
    5)
      echo -e "  ${WHITE}Setting up daily cron + syslog pipeline...${NC}"
      echo ""
      cat >/etc/cron.d/chkrootkit <<'CRON_EOF'
0 4 * * * root /usr/sbin/chkrootkit 2>&1 | grep -iE "infected|suspect|WARNING" | grep -v "not infected" | logger -p security.warning -t chkrootkit
CRON_EOF
      log_ok "Cron: /etc/cron.d/chkrootkit (daily 04:00 → syslog)"
      if ! grep -q "/var/log/syslog" /var/ossec/etc/ossec.conf 2>/dev/null; then
        python3 -c "
path='/var/ossec/etc/ossec.conf'
b='\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n'
with open(path) as f: c=f.read()
i=c.rfind('</ossec_config>')
with open(path,'w') as f: f.write(c[:i]+b+c[i:])
" 2>/dev/null && log_ok "syslog added to ossec.conf" || log_warn "Add manually"
        systemctl restart wazuh-agent 2>/dev/null
      else log_ok "syslog already in ossec.conf"; fi
      log_info "Testing pipeline now..."
      chkrootkit 2>&1 | grep -iE "infected|suspect|WARNING" | grep -v "not infected" |
        logger -p security.warning -t chkrootkit 2>/dev/null
      sleep 2
      log_ok "syslog: $(grep -c 'chkrootkit' /var/log/syslog 2>/dev/null || echo 0) entries"
      pause
      ;;
    6)
      MANAGER=$(get_manager_container)
      [ -z "$MANAGER" ] && log_warn "Manager not found" && pause && continue
      deploy_chkrootkit_rules_silent "$MANAGER"
      run_cmd "Reloading rules" "docker exec $MANAGER /var/ossec/bin/ossec-control reload"
      log_ok "Rules 100300–100302 active"
      echo ""
      echo -e "  ${DIM}  100300  Level 12  INFECTED — rootkit binary found${NC}"
      echo -e "  ${DIM}  100301  Level 10  suspect  — unusual activity${NC}"
      echo -e "  ${DIM}  100302  Level  8  WARNING  — possible rootkit indicator${NC}"
      pause
      ;;
    7)
      echo -e "  ${WHITE}Testing full pipeline...${NC}"
      echo ""
      log_run "logger -p security.warning -t chkrootkit 'WARNING: test INFECTED binary /usr/bin/test'"
      logger -p security.warning -t chkrootkit "WARNING: test INFECTED binary /usr/bin/test"
      log_info "Test event injected into syslog"
      echo -ne "  ${CYAN}→${NC}  Waiting for Wazuh"
      for i in {1..6}; do
        echo -n "."
        sleep 2
      done
      echo ""
      MANAGER=$(get_manager_container)
      if [ -n "$MANAGER" ]; then
        ALERT=$(docker exec "$MANAGER" grep "chkrootkit" /var/ossec/logs/alerts/alerts.json 2>/dev/null |
          tail -1 | python3 -c "
import sys,json
try:
  e=json.loads(sys.stdin.read())
  print('Level', e['rule']['level'], '—', e['rule']['description'])
  print('  log:', e.get('full_log','')[:100])
except: print('no alert found yet')
" 2>/dev/null)
        echo ""
        echo "$ALERT" | grep -q "Level" &&
          {
            log_ok "Pipeline working!"
            echo -e "  ${GREEN}  $ALERT${NC}"
          } ||
          {
            log_warn "$ALERT"
            log_info "Deploy rules [6] then retry"
          }
      else log_warn "Manager not found"; fi
      pause
      ;;
    8)
      MANAGER=$(get_manager_container)
      [ -z "$MANAGER" ] && log_warn "Manager not found" && pause && continue
      echo -e "  ${WHITE}Last 20 chkrootkit alerts:${NC}"
      echo ""
      docker exec "$MANAGER" grep "chkrootkit" /var/ossec/logs/alerts/alerts.json 2>/dev/null |
        tail -20 | python3 -c "
import sys,json
for line in sys.stdin:
  try:
    e=json.loads(line.strip())
    ts=e.get('timestamp','')[:19]; lvl=e['rule']['level']; desc=e['rule']['description']
    log=e.get('full_log','')[-80:]
    print(f'  [{ts}] Lvl:{lvl:>2}  {desc}')
    print(f'    {log}')
  except: pass
" 2>/dev/null || log_warn "No chkrootkit alerts found"
      pause
      ;;
    0) return ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 9. SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════
menu_shutdown() {
  header
  echo -e "  ${RED}${BOLD}⏻  SHUTDOWN / CLEANUP${NC}"
  separator
  echo ""
  echo -e "  ${CYAN}[1]${NC}  Stop Wazuh agent"
  echo -e "  ${CYAN}[2]${NC}  Stop Falco"
  echo -e "  ${CYAN}[3]${NC}  Stop Wazuh Docker stack"
  echo -e "  ${CYAN}[4]${NC}  Stop everything (agent + Falco + Docker)"
  echo -e "  ${RED}[5]${NC}  ${RED}Full teardown — containers + volumes + data${NC}"
  separator
  echo -e "  ${DIM}[0] Back${NC}"
  echo -ne "\n  ${WHITE}Choose: ${NC}"
  read -r choice
  echo ""

  case "$choice" in
  1)
    confirm "Stop wazuh-agent?" && run_cmd "Stopping agent" "systemctl stop wazuh-agent"
    pause
    ;;
  2)
    confirm "Stop Falco?" && run_cmd "Stopping Falco" "systemctl stop falco-modern-bpf"
    pause
    ;;
  3)
    confirm "Stop Wazuh stack?" &&
      run_cmd "Stopping stack" "cd $HOME/wazuh-docker/single-node && docker-compose down"
    pause
    ;;
  4)
    if confirm "Stop ALL?"; then
      run_cmd "Stopping agent" "systemctl stop wazuh-agent"
      run_cmd "Stopping Falco" "systemctl stop falco-modern-bpf"
      run_cmd "Stopping stack" "cd $HOME/wazuh-docker/single-node && docker-compose down"
      log_ok "All services stopped"
    fi
    pause
    ;;
  5)
    echo -e "  ${RED}${BOLD}WARNING: Removes ALL containers, volumes and data${NC}"
    echo ""
    if confirm "DESTROY everything?"; then
      run_cmd "Stop + disable agent" "systemctl stop wazuh-agent && systemctl disable wazuh-agent"
      run_cmd "Stop Falco" "systemctl stop falco-modern-bpf"
      run_cmd "Remove stack+volumes" "cd $HOME/wazuh-docker/single-node && docker-compose down -v"
      run_cmd "Prune Docker" "docker system prune -f"
      log_ok "Full teardown complete"
    fi
    pause
    ;;
  0) return ;;
  esac
}

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
[ "$EUID" -ne 0 ] && echo -e "\n  ${RED}Run as root: sudo bash $0${NC}\n" && exit 1
>/tmp/wazuh_cli.log
main_menu
