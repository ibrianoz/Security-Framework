#!/bin/bash

# ==============================================================================
# ZX301 SECURITY FRAMEWORK - v5.0 (PARALLEL EDITION)
# ==============================================================================

# --- GLOBAL TIMERS ---
SCRIPT_START_SEC=$(date +%s)
SCRIPT_START_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# --- STYLING & COLORS ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[1;30m'
NC='\033[0m'
BOLD='\033[1m'

# Backgrounds
BG_BLUE='\033[44m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'

# CONFIGURATION
BASE_OUTPUT_DIR=""
TARGET_NETWORK=""
MY_IP=""
SCAN_MODE="" 
PASS_LIST_PATH=$(mktemp /tmp/zx301_pass.XXXXXX)
USER_LIST_PATH=$(mktemp /tmp/zx301_user.XXXXXX)
DEFAULTS_USER_PATH=$(mktemp /tmp/zx301_def_user.XXXXXX)
DEFAULTS_PASS_PATH=$(mktemp /tmp/zx301_def_pass.XXXXXX)

# LOG FILES
AUDIT_FILE=""
DEBUG_LOG=""

# SCAN SETTINGS
NMAP_RATE="1000"
MASS_RATE="5000"
T_LEVEL="T4"

# ==============================================================================
# SAFE EXIT & CLEANUP
# ==============================================================================

cleanup() {
    tput cnorm 2>/dev/null 
    stty echo 2>/dev/null  
    
    if [[ -n "$(jobs -p)" ]]; then
        kill $(jobs -p) > /dev/null 2>&1
    fi

    rm -f "$PASS_LIST_PATH" "$USER_LIST_PATH" \
          "$DEFAULTS_USER_PATH" "$DEFAULTS_PASS_PATH" \
          /tmp/tcp_*.gnmap /tmp/udp_*.tmp
    
    # Force ownership change on exit if directory exists
    if [[ -n "$BASE_OUTPUT_DIR" && -d "$BASE_OUTPUT_DIR" && -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$BASE_OUTPUT_DIR" 2>/dev/null
    fi

    if [[ -n "$AUDIT_FILE" && -f "$AUDIT_FILE" ]]; then
        echo "[$(date "+%H:%M:%S")] Script execution ended." >> "$AUDIT_FILE"
    fi
}

safe_exit() {
    echo -e "\n\n${RED}[!] CAUGHT INTERRUPT (Ctrl+C)${NC}"
    echo -e "${YELLOW}[*] Cleaning up temporary files...${NC}"
    
    if [[ -n "$(jobs -p)" ]]; then
        kill $(jobs -p) > /dev/null 2>&1
    fi

    rm -f "$PASS_LIST_PATH" "$USER_LIST_PATH" \
          "$DEFAULTS_USER_PATH" "$DEFAULTS_PASS_PATH" \
          /tmp/tcp_*.gnmap /tmp/udp_*.tmp

    if [[ -n "$BASE_OUTPUT_DIR" && -d "$BASE_OUTPUT_DIR" ]]; then
        if [[ -z "$(ls -A "$BASE_OUTPUT_DIR")" ]]; then
             rm -rf "$BASE_OUTPUT_DIR"
        else
             if [[ -n "$SUDO_USER" ]]; then
                 chown -R "$SUDO_USER":"$SUDO_USER" "$BASE_OUTPUT_DIR" 2>/dev/null
                 echo -e "${GREEN}[✓] Saved partial data to: $BASE_OUTPUT_DIR${NC}"
             fi
        fi
    fi

    tput cnorm 2>/dev/null 
    stty echo 2>/dev/null  
    echo -e "${GREEN}[✓] Safe exit complete.${NC}"
    exit 1
}
trap safe_exit SIGINT

# ==============================================================================
# UI HELPER FUNCTIONS
# ==============================================================================

draw_line() {
    local WIDTH=$(tput cols 2>/dev/null || echo 80)
    if ! [[ "$WIDTH" =~ ^[0-9]+$ ]]; then WIDTH=80; fi
    printf "${GRAY}%*s${NC}\n" "$WIDTH" '' | tr ' ' '-'
}

print_stage() {
    local TITLE=" $1 "
    local COLOR="${2:-$BG_BLUE}"
    local WIDTH=$(tput cols 2>/dev/null || echo 80)
    if ! [[ "$WIDTH" =~ ^[0-9]+$ ]]; then WIDTH=80; fi
    local PAD_LEN=$(( (WIDTH - ${#TITLE}) / 2 ))
    if [[ $PAD_LEN -lt 0 ]]; then PAD_LEN=0; fi
    
    echo ""
    printf "${COLOR}${WHITE}${BOLD}%*s%s%*s${NC}\n" $PAD_LEN "" "$TITLE" $PAD_LEN ""
    echo ""
}

print_sub() {
    echo -e "${YELLOW}:: $1 ::${NC}"
}

# ==============================================================================
# CORE HELPER FUNCTIONS
# ==============================================================================

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Error: This script requires root privileges.${NC}"
        exit 1
    fi
}

fix_ownership() {
    local TARGET_PATH="$1"
    if [[ -n "$SUDO_USER" && -e "$TARGET_PATH" ]]; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$TARGET_PATH"
        log_audit "Action: Ownership transferred to $SUDO_USER"
    fi
}

log_audit() {
    local MSG="$1"
    local TIMESTAMP=$(date "+%H:%M:%S")
    if [[ -n "$AUDIT_FILE" && -d "$BASE_OUTPUT_DIR" ]]; then
        echo "[$TIMESTAMP] $MSG" >> "$AUDIT_FILE"
    fi
}

log_cmd_exec() {
    local CMD_STR="$1"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    if [[ -n "$DEBUG_LOG" ]]; then
        echo "" >> "$DEBUG_LOG"
        echo "------------------------------------------------------------" >> "$DEBUG_LOG"
        echo "[$TIMESTAMP] CMD: $CMD_STR" >> "$DEBUG_LOG"
        echo "------------------------------------------------------------" >> "$DEBUG_LOG"
    fi
}

calc_duration() {
    local START=$1
    local END=$2
    local DIFF=$((END - START))
    echo "$(date -u -d @${DIFF} +%T)"
}

# NOTE: Original run_tool is kept for sequential parts, 
# but parallel worker uses direct execution to avoid UI glitches.
run_tool() {
    local DESC="$1"
    local CMD="$2"
    
    local T_START=$(date +%s)
    log_audit "STARTED: $DESC"
    log_cmd_exec "$CMD"
    
    eval "$CMD" >> "$DEBUG_LOG" 2>&1 &
    local PID=$!
    
    track_process $PID "$DESC"
    
    local T_END=$(date +%s)
    local DURATION=$(calc_duration $T_START $T_END)
    log_audit "COMPLETED: $DESC (Time: $DURATION)"
}

show_banner() {
    clear
    echo -e "${RED}"
    echo "  ███████╗██╗  ██╗██████╗  ██████╗  ██╗"
    echo "  ╚══███╔╝╚██╗██╔╝╚════██╗██╔═████╗███║"
    echo "    ███╔╝  ╚███╔╝  █████╔╝██║██╔██║╚██║"
    echo "   ███╔╝   ██╔██╗  ╚═══██╗████╔╝██║ ██║"
    echo "  ███████╗██╔╝ ██╗██████╔╝╚██████╔╝ ██║"
    echo "  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═╝"
    echo -e "${NC}"
    echo -e "  ${WHITE}ZX301 SECURITY FRAMEWORK ${GRAY}| v5.0 Parallel Edition${NC}"
    echo -e "  ${WHITE}Created by ${GRAY}| Oz Itzkowitz${NC}"
    echo -e "  ${GRAY}#: S10${NC}"
    echo -e "  ${GRAY}Class: 77367${NC}"
    echo -e "  ${GRAY}Teacher: Erel Regev${NC}"
    echo ""
}

check_dependencies() {
    echo -e "${CYAN}[*] Verifying Environment...${NC}"
    local REQUIRED_TOOLS=("nmap" "masscan" "searchsploit" "zip" "curl")
    local UPDATE_RUN=0
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "    ${RED}[MISSING]${NC} $tool. Installing..."
            if [ $UPDATE_RUN -eq 0 ]; then
                apt-get update -y > /dev/null 2>&1
                UPDATE_RUN=1
            fi
            if [ "$tool" == "searchsploit" ]; then
                apt-get install -y exploitdb > /dev/null 2>&1
            else
                apt-get install -y "$tool" > /dev/null 2>&1
            fi
            
            if command -v "$tool" &> /dev/null; then
                echo -e "    ${GREEN}[INSTALLED]${NC} $tool ready."
            else
                echo -e "${RED}[!] Critical Failure: Could not install $tool.${NC}"
                exit 1
            fi
        else
            echo -e "    ${GREEN}[OK]${NC} $tool"
        fi
    done
    sleep 0.5
}

track_process() {
    local pid=$1
    local text=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    
    tput civis 2>/dev/null 
    stty -echo 2>/dev/null 
    
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spin#?}
        local spin=$temp${spin%"$temp"}
        printf "\r${CYAN} %c ${NC} %-50s" "$spin" "$text..."
        read -t 0.1 -n 10000 discard 2>/dev/null
    done
    
    stty echo 2>/dev/null 
    tput cnorm 2>/dev/null 
    printf "\r${GREEN} ✔ ${NC} %-50s\n" "$text"
}

# ==============================================================================
# STEP 1: CONFIGURATION
# ==============================================================================

get_user_input() {
    print_stage "PHASE 1: CONFIGURATION" "$BG_BLUE"

    echo -e "${CYAN}[?] Select Network Source:${NC}"
    echo -e "  ${WHITE}1)${NC} Manual Entry (IP, CIDR, or Interface Name)"
    echo -e "  ${WHITE}2)${NC} Auto-Detect"
    read -e -p "  > Selection: " NET_OPT

    if [[ "$NET_OPT" == "2" ]]; then
        echo -e "\n${CYAN}[*] Auto-Detecting Interfaces...${NC}"
        mapfile -t IFACE_LIST < <(ip -o -4 addr show | awk '$2 != "lo" {print $2, $4}')
        
        local COUNT=${#IFACE_LIST[@]}
        if [[ $COUNT -eq 0 ]]; then
            echo -e "${RED}[!] No external interfaces found.${NC}"
            NET_OPT="1"
        elif [[ $COUNT -eq 1 ]]; then
            read IFACE CIDR <<< "${IFACE_LIST[0]}"
            TARGET_NETWORK=$CIDR
            MY_IP=${CIDR%/*}
            echo -e "    ${GREEN}[OK]${NC} Detected: $TARGET_NETWORK ($IFACE)"
        else
            echo -e "    ${YELLOW}[!] Multiple interfaces found:${NC}"
            for i in "${!IFACE_LIST[@]}"; do
                read IFACE CIDR <<< "${IFACE_LIST[$i]}"
                echo -e "    ${WHITE}$((i+1)))${NC} $IFACE  ${BLUE}($CIDR)${NC}"
            done
            while true; do
                read -e -p "    > Select Interface: " IFACE_SEL
                if [[ "$IFACE_SEL" =~ ^[0-9]+$ ]] && (( IFACE_SEL >= 1 && IFACE_SEL <= COUNT )); then
                    SELECTED="${IFACE_LIST[$((IFACE_SEL-1))]}"
                    read IFACE CIDR <<< "$SELECTED"
                    TARGET_NETWORK=$CIDR
                    MY_IP=${CIDR%/*}
                    echo -e "    ${GREEN}[OK]${NC} Selected: $TARGET_NETWORK"
                    break
                else
                    echo -e "${RED}[!] Invalid selection.${NC}"
                fi
            done
        fi
    fi

    if [[ "$NET_OPT" != "2" ]]; then
        echo -e "\n${GRAY}--- Reference: Available Interfaces ---${NC}"
        ip -o -4 addr show | awk '$2 != "lo" {print "    " $2 ": " $4}'
        echo -e "${GRAY}---------------------------------------${NC}"

        local DEF_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
        local DEF_NET=""
        if [[ -n "$DEF_IFACE" ]]; then
            DEF_NET=$(ip -o -4 addr show "$DEF_IFACE" | awk '{print $4}' | head -n1)
        fi

        while true; do
            echo -e "${CYAN}[?] Target Network/IP:${NC}"
            if [[ -n "$DEF_NET" ]]; then
                echo -e "    ${GRAY}Hit [ENTER] for default: ${BLUE}$DEF_NET${NC}"
            fi
            read -e -p "    > Input (IP, CIDR, or Interface): " USER_INPUT

            if [[ -z "$USER_INPUT" && -n "$DEF_NET" ]]; then
                TARGET_NETWORK="$DEF_NET"
                echo -e "    ${GREEN}[OK]${NC} Using default network."
            elif ip -o -4 addr show "$USER_INPUT" &>/dev/null; then
                TARGET_NETWORK=$(ip -o -4 addr show "$USER_INPUT" | awk '{print $4}' | head -n1)
                if [[ -z "$TARGET_NETWORK" ]]; then
                    echo -e "${RED}[!] Interface '$USER_INPUT' has no IPv4 address.${NC}"
                    continue
                fi
                echo -e "    ${GREEN}[OK]${NC} Resolved '$USER_INPUT' to: $TARGET_NETWORK"
            else
                TARGET_NETWORK="$USER_INPUT"
            fi

            if [[ "$TARGET_NETWORK" =~ ^127\. ]] || [[ "$TARGET_NETWORK" == "lo" ]]; then
                echo -e "${RED}[!] LOOPBACK RESTRICTED:${NC} Self-scanning (127.x.x.x) is disabled."
                continue
            fi

            if [[ "$TARGET_NETWORK" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
                 local TEST_IP=${TARGET_NETWORK%/*}
                 MY_IP=$(ip route get "$TEST_IP" 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print $2}')
                 break
            else
                echo -e "${RED}[!] Invalid format.${NC} Try: IP, CIDR, or Interface Name (e.g., eth0)." 
            fi
        done
    fi
    
    local DEF_DIR="Scan_$(date +%Y%m%d_%H%M)"
    echo -e "\n${CYAN}[?] Project Name / Output Dir:${NC}"
    read -e -p "    > Name [Default: $DEF_DIR]: " INPUT_DIR
    DIR_NAME=${INPUT_DIR:-$DEF_DIR}
    
    BASE_OUTPUT_DIR="$(pwd)/$DIR_NAME"
    mkdir -p "$BASE_OUTPUT_DIR"
    
    AUDIT_FILE="$BASE_OUTPUT_DIR/audit_trace.txt"
    DEBUG_LOG="$BASE_OUTPUT_DIR/execution_log.txt"
    touch "$AUDIT_FILE" "$DEBUG_LOG"
    
    log_audit "=== AUDIT SESSION STARTED ==="
    log_audit "Target: $TARGET_NETWORK | Dir: $BASE_OUTPUT_DIR"

    echo -e "\n${CYAN}[?] Scan Profile:${NC}"
    echo -e "  ${WHITE}1)${NC} Stealth (Slow)"
    echo -e "  ${WHITE}2)${NC} Normal (Default)"
    echo -e "  ${WHITE}3)${NC} Aggressive (Noisy)"
    read -e -p "    > Selection [2]: " SPEED_OPT
    SPEED_OPT=${SPEED_OPT:-2}

    case $SPEED_OPT in
        1) NMAP_RATE="300"; MASS_RATE="500"; T_LEVEL="T3"; log_audit "Config: Slow" ;;
        3) NMAP_RATE="5000"; MASS_RATE="10000"; T_LEVEL="T5"; log_audit "Config: Aggressive" ;;
        *) NMAP_RATE="1000"; MASS_RATE="5000"; T_LEVEL="T4"; log_audit "Config: Normal" ;;
    esac

    echo -e "\n${CYAN}[?] Analysis Depth:${NC}"
    echo -e "  ${WHITE}1)${NC} Basic (Ports + Weak Passwords)"
    echo -e "  ${WHITE}2)${NC} Full  (Basic + Vuln Scripts + Searchsploit)"
    read -e -p "    > Selection [1]: " MODE_OPT
    MODE_OPT=${MODE_OPT:-1}
    
    case $MODE_OPT in
        2) SCAN_MODE="FULL" ;;
        *) SCAN_MODE="BASIC" ;;
    esac
    log_audit "Config: Mode $SCAN_MODE"
}

configure_passwords() {
    print_stage "PHASE 2: ACCESS SETUP" "$BG_BLUE"
    
    cat <<EOF > "$DEFAULTS_USER_PATH"
root
admin
administrator
guest
user
kali
EOF
    cat <<EOF > "$DEFAULTS_PASS_PATH"

admin
password
12345
toor
kali
EOF
    cat <<EOF > "$USER_LIST_PATH"
root
admin
administrator
user
test
guest
oracle
postgres
mysql
webadmin
kali
EOF

    echo -e "${CYAN}[?] Dictionary Attack Config:${NC}"
    echo -e "  ${WHITE}1)${NC} Use Built-in 'Top 20' List"
    echo -e "  ${WHITE}2)${NC} Load Custom Wordlist"
    read -e -p "    > Selection: " PASS_OPT

    if [[ "$PASS_OPT" == "2" ]]; then
        while true; do
            read -e -p "    > File Path: " CUSTOM_PATH
            if [[ -z "$CUSTOM_PATH" ]]; then
                echo -e "${YELLOW}    [!] Reverting to built-in list.${NC}"
                PASS_OPT="1"
                break
            fi
            if [[ -f "$CUSTOM_PATH" ]]; then
                cp "$CUSTOM_PATH" "$PASS_LIST_PATH"
                log_audit "Config: Custom wordlist: $CUSTOM_PATH"
                echo -e "${GREEN}    [OK] Loaded.${NC}"
                break
            else
                echo -e "${RED}    [!] File not found.${NC}"
            fi
        done
    fi

    if [[ "$PASS_OPT" != "2" ]]; then
        cat <<EOF > "$PASS_LIST_PATH"
123456
password
12345678
12345
qwerty
welcome
letmein
admin
1234
kali
EOF
    fi
}
# ==============================================================================
# WORKER FUNCTION (FIXED)
# ==============================================================================

scan_target_node() {
    local TARGET_IP=$1
    
    # Define vars inside worker
    local HOST_CLEAN=${TARGET_IP//./_}
    
    # [NEW] Create Host-Specific Directory
    local HOST_DIR="$BASE_OUTPUT_DIR/$HOST_CLEAN"
    mkdir -p "$HOST_DIR"

    # [NEW] Update file paths to live inside the host directory
    local HOST_XML="$HOST_DIR/scan_${HOST_CLEAN}.xml"
    local HOST_TXT="$HOST_DIR/scan_${HOST_CLEAN}.txt"

    # [LOG] Start
    echo -e "${BLUE}[*] Thread Started: $TARGET_IP${NC}"
    log_audit "[$TARGET_IP] THREAD STARTED"

    # --- STAGE A: TCP ---
    local TCP_OUT=$(mktemp /tmp/tcp.XXXXXX)
    log_audit "[$TARGET_IP] Starting Fast TCP Scan..."
    nmap -sS -p- --min-rate $NMAP_RATE -n -$T_LEVEL $TARGET_IP -oG $TCP_OUT > /dev/null 2>&1
    
    local DISCOVERED_TCP=$(awk '/Ports: / {for(i=1;i<=NF;i++) {if($i ~ /^[0-9]+\/open\//) {split($i, a, "/"); printf "%s,", a[1]}}}' "$TCP_OUT" | tr -d '[:space:]' | sed 's/,$//')
    rm -f "$TCP_OUT"

    # --- STAGE B: UDP ---
    local UDP_OUT=$(mktemp /tmp/udp.XXXXXX)
    local IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$IFACE" ]]; then
        log_audit "[$TARGET_IP] Starting Masscan UDP..."
        masscan -pU:1-65535 $TARGET_IP -e $IFACE --rate=$MASS_RATE > $UDP_OUT 2>/dev/null
    fi
    
    local DISCOVERED_UDP=""
    if [[ -f "$UDP_OUT" ]]; then
        DISCOVERED_UDP=$(grep "open udp" "$UDP_OUT" | awk '{print $4}' | cut -d'/' -f1 | sort -u | tr '\n' ',' | tr -d '[:space:]' | sed 's/,$//')
        rm -f "$UDP_OUT"
    fi

    # --- STAGE C: DEEP ANALYSIS ---
    local SCAN_FLAGS="-sS -sV -Pn -$T_LEVEL"
    local PORTS_ARG=""

    if [[ -n "$DISCOVERED_TCP" && -n "$DISCOVERED_UDP" ]]; then
        SCAN_FLAGS="$SCAN_FLAGS -sU"
        PORTS_ARG="-p T:${DISCOVERED_TCP},U:${DISCOVERED_UDP}"
    elif [[ -n "$DISCOVERED_TCP" ]]; then
        PORTS_ARG="-p ${DISCOVERED_TCP}"
    elif [[ -n "$DISCOVERED_UDP" ]]; then
        SCAN_FLAGS="-sU -sV -Pn -$T_LEVEL"
        PORTS_ARG="-p ${DISCOVERED_UDP}"
    else
        echo -e "${YELLOW}[-] $TARGET_IP: No open ports found.${NC}"
        log_audit "[$TARGET_IP] SKIP: No open ports found."
        return
    fi

    if [[ "$SCAN_MODE" == "FULL" ]]; then 
        SCAN_FLAGS="$SCAN_FLAGS --script vuln"
    fi

    # Run the deep scan
    log_audit "[$TARGET_IP] Starting Deep Analysis (Nmap Service Scan)..."
    nmap $SCAN_FLAGS $PORTS_ARG $TARGET_IP -oN $HOST_TXT -oX $HOST_XML > /dev/null 2>&1

    # --- STAGE D: ATTACK VECTORS (Full Mode) ---
    if [[ "$SCAN_MODE" == "FULL" ]]; then
        local COMBINED_PORTS="$DISCOVERED_TCP,$DISCOVERED_UDP"
        
        # Web
        if [[ "$COMBINED_PORTS" == *"80"* ]] || [[ "$COMBINED_PORTS" == *"443"* ]]; then
             log_audit "[$TARGET_IP] Web Recon Started"
             local WEB_FILE="$HOST_DIR/web_${HOST_CLEAN}.txt"
             echo "--- WEB RECON ---" > "$WEB_FILE"
             curl -I -s -L --connect-timeout 3 http://$TARGET_IP >> "$WEB_FILE" 2>/dev/null
             nmap -p 80,443 --script http-default-accounts,http-config-backup $TARGET_IP -oN "${WEB_FILE}.vuln" > /dev/null 2>&1
        fi

        # SMB
        if [[ "$COMBINED_PORTS" == *"445"* ]]; then
              log_audit "[$TARGET_IP] SMB Enumeration Started"
              nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010 $TARGET_IP -oN "$HOST_DIR/smb_${HOST_CLEAN}.txt" > /dev/null 2>&1
        fi
    fi

    # --- STAGE E: CREDENTIAL CHECK ---
    if [[ -f "$HOST_TXT" ]]; then
        local BRUTE_PORTS=""
        local BRUTE_SCRIPTS=""

        local SSH_PORTS=$(grep -E -i "^[0-9]+/tcp.*open.*ssh" "$HOST_TXT" | cut -d'/' -f1 | tr '\n' ',' | tr -d '[:space:]')
        if [[ -n "$SSH_PORTS" ]]; then 
            BRUTE_PORTS="${BRUTE_PORTS}${SSH_PORTS}"
            BRUTE_SCRIPTS="${BRUTE_SCRIPTS}ssh-brute,"
        fi
        
        local FTP_PORTS=$(grep -E -i "^[0-9]+/tcp.*open.*ftp" "$HOST_TXT" | cut -d'/' -f1 | tr '\n' ',' | tr -d '[:space:]')
        if [[ -n "$FTP_PORTS" ]]; then 
            BRUTE_PORTS="${BRUTE_PORTS}${FTP_PORTS}"
            BRUTE_SCRIPTS="${BRUTE_SCRIPTS}ftp-brute,"
        fi

        local TELNET_PORTS=$(grep -E -i "^[0-9]+/tcp.*open.*telnet" "$HOST_TXT" | cut -d'/' -f1 | tr '\n' ',' | tr -d '[:space:]')
        if [[ -n "$TELNET_PORTS" ]]; then 
            BRUTE_PORTS="${BRUTE_PORTS}${TELNET_PORTS}"
            BRUTE_SCRIPTS="${BRUTE_SCRIPTS}telnet-brute,"
        fi

        local RDP_PORTS=$(grep -E -i "^[0-9]+/tcp.*open.*(ms-wbt-server|rdp)" "$HOST_TXT" | cut -d'/' -f1 | tr '\n' ',' | tr -d '[:space:]')
        if [[ -n "$RDP_PORTS" ]]; then 
            BRUTE_PORTS="${BRUTE_PORTS}${RDP_PORTS}"
            BRUTE_SCRIPTS="${BRUTE_SCRIPTS}rdp-brute,"
        fi

        if [[ -n "$BRUTE_PORTS" ]]; then
             BRUTE_PORTS=${BRUTE_PORTS%,}
             BRUTE_SCRIPTS=${BRUTE_SCRIPTS%,}
             
             if [[ "$BRUTE_PORTS" =~ ^[0-9,]+$ ]]; then
                 log_audit "[$TARGET_IP] Credential Brute-Force Started (Ports: $BRUTE_PORTS)"
                 local BRUTE_FILE="$HOST_DIR/creds_${HOST_CLEAN}.txt"
                 
                 nmap -p $BRUTE_PORTS --script $BRUTE_SCRIPTS --script-args userdb=$DEFAULTS_USER_PATH,passdb=$DEFAULTS_PASS_PATH $TARGET_IP -oN "${BRUTE_FILE}_defaults" > /dev/null 2>&1
                 
                 if [[ -f "${BRUTE_FILE}_defaults" ]] && grep -q "Valid credentials" "${BRUTE_FILE}_defaults"; then
                     cat "${BRUTE_FILE}_defaults" >> "$BRUTE_FILE"
                     log_audit "[$TARGET_IP] CRITICAL: Default Credentials Found!"
                 else
                     nmap -p $BRUTE_PORTS --script $BRUTE_SCRIPTS --script-args userdb=$USER_LIST_PATH,passdb=$PASS_LIST_PATH $TARGET_IP -oN "${BRUTE_FILE}_brute" > /dev/null 2>&1
                     if [[ -f "${BRUTE_FILE}_brute" ]] && grep -q "Valid credentials" "${BRUTE_FILE}_brute"; then
                         cat "${BRUTE_FILE}_brute" >> "$BRUTE_FILE"
                         log_audit "[$TARGET_IP] CRITICAL: Weak Credentials Found!"
                     fi
                 fi
             else
                 log_audit "[$TARGET_IP] ERR: Skipped Brute Force due to malformed port list: '$BRUTE_PORTS'"
             fi
        fi
    fi

    # --- STAGE F: VULN MAPPING ---
    if [[ "$SCAN_MODE" == "FULL" && -f "$HOST_XML" ]]; then
        log_audit "[$TARGET_IP] Running Searchsploit Correlation"
        searchsploit --nmap $HOST_XML | sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$HOST_DIR/vuln_${HOST_CLEAN}.txt" 2>/dev/null
    fi

    echo -e "${GREEN}[✓] Finished: $TARGET_IP${NC}"
    log_audit "[$TARGET_IP] THREAD COMPLETED"
}

# CRITICAL: Export the function so xargs subshells can see it
export -f scan_target_node


# ==============================================================================
# STEP 3: SCANNING LOGIC (PARALLEL WRAPPER)
# ==============================================================================

perform_scan() {
    print_stage "PHASE 3: NETWORK ENUMERATION" "$BG_BLUE"
    local LIVE_HOSTS_FILE="$BASE_OUTPUT_DIR/live_hosts.txt"
    local EXCLUDE_FLAG=""
    if [[ -n "$MY_IP" ]]; then EXCLUDE_FLAG="--exclude $MY_IP"; fi

    print_sub "Target Discovery"
    run_tool "Ping Sweep ($TARGET_NETWORK)" \
             "nmap -sn -n -PE $TARGET_NETWORK $EXCLUDE_FLAG -oG - | awk '/Up$/{print \$2}' > $LIVE_HOSTS_FILE"

    if [[ ! -s "$LIVE_HOSTS_FILE" ]]; then
        echo -e "${RED}[!] No live hosts found. Exiting.${NC}"
        log_audit "FAIL: No live hosts found."
        return
    fi

    mapfile -t HOSTS < "$LIVE_HOSTS_FILE"
    
    echo -e "\n${BG_GREEN}${WHITE}  ACTIVE HOSTS FOUND: ${#HOSTS[@]}  ${NC}"
    local i=1
    for host in "${HOSTS[@]}"; do
        echo -e "  ${CYAN}[$i]${NC} $host"
        ((i++))
    done
    echo ""
    echo -e "${YELLOW}[TIP] Press ENTER to scan ALL, or type IDs/Range (e.g. '1 3' or '2-5')${NC}"
    
    if read -e -t 10 -p "  > Targets: " INPUT_STR; then
        if [[ -n "$INPUT_STR" ]]; then
            read -ra TOKENS <<< "$INPUT_STR"
            SELECTED_INDICES=()

            for token in "${TOKENS[@]}"; do
                if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    START=${BASH_REMATCH[1]}
                    END=${BASH_REMATCH[2]}
                    if [ "$START" -gt "$END" ]; then
                        TEMP=$START; START=$END; END=$TEMP
                    fi
                    for ((j=START; j<=END; j++)); do
                        SELECTED_INDICES+=("$j")
                    done
                elif [[ "$token" =~ ^[0-9]+$ ]]; then
                    SELECTED_INDICES+=("$token")
                fi
            done

            IFS=$'\n' SORTED_UNIQUE=($(sort -nu <<<"${SELECTED_INDICES[*]}"))
            unset IFS

            NEW_HOSTS=()
            for idx in "${SORTED_UNIQUE[@]}"; do
                if [ "$idx" -ge 1 ] && [ "$idx" -le "${#HOSTS[@]}" ]; then
                    NEW_HOSTS+=("${HOSTS[$((idx-1))]}")
                fi
            done

            if [ ${#NEW_HOSTS[@]} -gt 0 ]; then
                HOSTS=("${NEW_HOSTS[@]}")
                echo -e "  ${GREEN}[OK] Focused scan on ${#HOSTS[@]} host(s).${NC}"
            else
                echo -e "  ${RED}[!] Invalid selection. Scanning ALL.${NC}"
            fi
        else
             echo -e "  ${GREEN}[OK] Scanning ALL hosts.${NC}"
        fi
    else
        echo -e "\n  ${YELLOW}[!] Timeout. Scanning ALL hosts.${NC}"
    fi

    # === PREPARE FOR PARALLEL EXECUTION ===
    echo -e "\n${CYAN}[*] Initializing Parallel Engine...${NC}"
    echo -e "${GRAY}    Target Count: ${#HOSTS[@]}${NC}"
    echo -e "${GRAY}    Max Threads:  5${NC}"
    
   # 1. Export Configuration Variables
    export BASE_OUTPUT_DIR NMAP_RATE MASS_RATE T_LEVEL SCAN_MODE AUDIT_FILE
    export BG_BLUE BG_RED BG_GREEN RED GREEN YELLOW BLUE CYAN WHITE GRAY NC
    export DEFAULTS_USER_PATH DEFAULTS_PASS_PATH USER_LIST_PATH PASS_LIST_PATH
    
    # Export the logging function so workers can use it
    export -f log_audit

    # 2. EXECUTE PARALLEL SCAN
    echo -e "\n${BG_RED}${WHITE}  LAUNCHING ATTACK THREADS  ${NC}"
    # Passes each host IP to the worker function in parallel
    printf "%s\n" "${HOSTS[@]}" | xargs -n 1 -P 5 -I {} bash -c 'scan_target_node "$@"' _ {}

    echo -e "\n${GREEN}[✓] Batch Scan Complete.${NC}"
}

# ==============================================================================
# STEP 4: REPORTING & FINALIZATION
# ==============================================================================

generate_report() {
    print_stage "PHASE 4: REPORT GENERATION" "$BG_BLUE"
    local REPORT_FILE="$BASE_OUTPUT_DIR/Final_Report.txt"
    local HTML_FILE="$BASE_OUTPUT_DIR/Final_Report.html"
    local XML_FILE="$BASE_OUTPUT_DIR/final_report.xml"
    
    local T_END=$(date +%s)
    local DURATION=$(calc_duration $SCRIPT_START_SEC $T_END)
    local END_DATE=$(date "+%Y-%m-%d %H:%M:%S")
    
    log_audit "Generating final reports. Total Duration: $DURATION"

    # CONSOLE PREVIEW SUMMARY
    echo -e "${CYAN}=== SCAN SUMMARY ===${NC}"
    echo -e "${WHITE}Duration:${NC} $DURATION"
    echo -e "${WHITE}Target:${NC}   $TARGET_NETWORK"

    # --- TEXT REPORT GENERATION ---
    {
        echo "============================================================"
        echo "ZX301 SECURITY AUDIT REPORT"
        echo "============================================================"
        echo "Start:    $SCRIPT_START_DATE"
        echo "End:      $END_DATE"
        echo "Duration: $DURATION"
        echo "Target:   $TARGET_NETWORK"
        echo "Mode:     $SCAN_MODE"
        echo "============================================================"
        
        # [NEW] Iterate through host subdirectories
        for txt_file in "$BASE_OUTPUT_DIR"/*/scan_*.txt; do
            [ -e "$txt_file" ] || continue
            
            local HOST_DIR=$(dirname "$txt_file")
            local BASE_NAME=$(basename "$txt_file" .txt | sed 's/scan_//')
            local IP_TAG=$(echo "$BASE_NAME" | sed 's/_/./g')
            
            # [NEW] Look for files in the host specific directory
            local CRED_FILE="$HOST_DIR/creds_${BASE_NAME}.txt"
            local VULN_FILE="$HOST_DIR/vuln_${BASE_NAME}.txt"
            local WEB_FILE="$HOST_DIR/web_${BASE_NAME}.txt"
            local SMB_FILE="$HOST_DIR/smb_${BASE_NAME}.txt"

            echo ""
            echo "------------------------------------------------------------"
            echo "HOST: $IP_TAG"
            echo "------------------------------------------------------------"
            
            # 1. CRITICAL: Credentials
            if [[ -s "$CRED_FILE" ]]; then 
                echo -e "\n[!!!] COMPROMISED CREDENTIALS [!!!]"
                cat "$CRED_FILE"
                echo -e "------------------------------------------------------------"
            fi

            # 2. Ports
            echo "OPEN PORTS:"
            grep "open" "$txt_file" | grep -v "SF:" | head -n 20

            # 3. Web Recon
            if [[ -s "$WEB_FILE" ]]; then
                echo -e "\n[+] WEB RECONNAISSANCE:"
                cat "$WEB_FILE" | head -n 20
            fi

            # 4. SMB/SMTP Recon
            if [[ -s "$SMB_FILE" ]]; then
                 echo -e "\n[+] SMB ENUMERATION:"
                 grep -E "OS:|Computer name:|Domain name:|FQDN:" "$SMB_FILE"
            fi

            # 5. Vulnerabilities (Searchsploit)
            if [[ -s "$VULN_FILE" ]]; then
                echo -e "\n[!] POTENTIAL VULNERABILITIES:"
                sed -r 's/\x1B\[[0-9;]*[mK]//g' "$VULN_FILE" | head -n 10
            fi
        done

        # FILE MANIFEST (Recursive)
        echo ""
        echo "============================================================"
        echo "GENERATED EVIDENCE FILES"
        echo "============================================================"
        find "$BASE_OUTPUT_DIR" -type f | sort | while read -r f; do
            local REL_PATH=${f#$BASE_OUTPUT_DIR/}
            local SIZE=$(du -h "$f" | cut -f1)
            echo " - $REL_PATH ($SIZE)"
        done

    } > "$REPORT_FILE"

    # --- HTML REPORT GENERATION ---
    {
        echo "<html><head><title>ZX301 Report</title>"
        echo "<style>"
        echo "body{font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding:20px; background:#f4f4f9; color:#333;}"
        echo ".header{background:#2c3e50; color:#fff; padding:20px; border-radius:8px 8px 0 0;}"
        echo ".card{background:#fff; padding:20px; margin-bottom:20px; border-radius:8px; box-shadow:0 4px 6px rgba(0,0,0,0.1); border-left: 5px solid #3498db;}"
        echo "h1{margin:0;} h2{color:#2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px;}"
        echo "h3{font-size: 1.1em; margin-top: 15px; color: #555; text-transform: uppercase; letter-spacing: 1px;}"
        echo "pre{background:#222; color:#0f0; padding:15px; overflow:auto; border-radius:4px; font-family: 'Courier New', monospace;}"
        echo "ul.file-list {list-style-type: none; padding: 0;}"
        echo "ul.file-list li {background: #eee; margin: 2px 0; padding: 5px 10px; border-radius: 4px; font-family: monospace; display: flex; justify-content: space-between;}"
        echo ".f-size {color: #777; font-weight: bold;}"
        echo ".critical{border-left: 8px solid #e74c3c; background: #fadbd8; padding: 10px; margin-top: 10px;}"
        echo ".critical h3{color: #c0392b; font-weight: bold;}"
        echo ".critical pre{background: #fff; color: #c0392b; border: 1px solid #c0392b;}"
        echo ".warning{border-left: 5px solid #f39c12; background: #fef9e7; padding: 10px;}"
        echo ".info{border-left: 5px solid #3498db; background: #ebf5fb; padding: 10px;}"
        echo "</style></head><body>"
        
        echo "<div class='header'>"
        echo "<h1>ZX301 Audit Report</h1>"
        echo "<p><strong>Target:</strong> $TARGET_NETWORK | <strong>Duration:</strong> $DURATION | <strong>Date:</strong> $END_DATE</p>"
        echo "</div><br>"
        
        # [NEW] Iterate subdirectories
        for txt_file in "$BASE_OUTPUT_DIR"/*/scan_*.txt; do
            [ -e "$txt_file" ] || continue
            
            local HOST_DIR=$(dirname "$txt_file")
            local BASE_NAME=$(basename "$txt_file" .txt | sed 's/scan_//')
            local IP_TAG=$(echo "$BASE_NAME" | sed 's/_/./g')
            
            local CRED_FILE="$HOST_DIR/creds_${BASE_NAME}.txt"
            local VULN_FILE="$HOST_DIR/vuln_${BASE_NAME}.txt"
            local WEB_FILE="$HOST_DIR/web_${BASE_NAME}.txt"
            local SMB_FILE="$HOST_DIR/smb_${BASE_NAME}.txt"

            echo "<div class='card'>"
            echo "<h2>Host: $IP_TAG</h2>"
            
            # 1. CREDENTIALS
            if [[ -s "$CRED_FILE" ]]; then
                echo "<div class='critical'>"
                echo "<h3>&#9888; COMPROMISED CREDENTIALS FOUND</h3>"
                echo "<pre>"
                cat "$CRED_FILE"
                echo "</pre></div>"
            fi

            # 2. PORTS & SERVICES
            echo "<h3>Open Ports & Services</h3>"
            echo "<pre>"
            grep "open" "$txt_file" | grep -v "SF:" | head -n 30
            echo "</pre>"

            # 3. WEB RECON
            if [[ -s "$WEB_FILE" ]]; then
                echo "<div class='info'><h3>Web Reconnaissance</h3>"
                echo "<pre>"
                cat "$WEB_FILE" | sed 's/</\&lt;/g' | head -n 20
                echo "</pre></div>"
            fi
            
            # 4. SMB RECON
            if [[ -s "$SMB_FILE" ]]; then
                 echo "<div class='warning'><h3>SMB Enumeration</h3><pre>"
                 cat "$SMB_FILE"
                 echo "</pre></div>"
            fi

            # 5. VULNERABILITIES
            if [[ -s "$VULN_FILE" ]]; then
                echo "<div class='warning'><h3>Potential Vulnerabilities (ExploitDB)</h3>"
                echo "<pre>"
                sed -r 's/\x1B\[[0-9;]*[mK]//g' "$VULN_FILE" | head -n 20
                echo "</pre></div>"
            fi
            
            echo "</div>" # End Card
        done

        # HTML FILE MANIFEST
        echo "<div class='card'>"
        echo "<h2>Generated Evidence Files</h2>"
        echo "<ul class='file-list'>"
        find "$BASE_OUTPUT_DIR" -type f | sort | while read -r f; do
             local REL_PATH=${f#$BASE_OUTPUT_DIR/}
             local SIZE=$(du -h "$f" | cut -f1)
             echo "<li><span>$REL_PATH</span> <span class='f-size'>$SIZE</span></li>"
        done
        echo "</ul>"
        echo "</div>"

        echo "</body></html>"
    } > "$HTML_FILE"
    
    # XML Generation
    {
        echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        echo "<ScanReport><Metadata><Target>$TARGET_NETWORK</Target><Duration>$DURATION</Duration></Metadata><Hosts>"
        for txt_file in "$BASE_OUTPUT_DIR"/*/scan_*.txt; do
             [ -e "$txt_file" ] || continue
             local IP_TAG=$(basename "$txt_file" .txt | sed 's/scan_//' | sed 's/_/./g')
             echo "<Host ip=\"$IP_TAG\">"
             grep "open" "$txt_file" | awk -F/ '{print "<Port>"$1"</Port><Service>"$3"</Service>"}'
             echo "</Host>"
        done
        echo "</Hosts></ScanReport>"
    } > "$XML_FILE"

    echo -e "\n  ${GREEN}[OK] Reports saved to: $BASE_OUTPUT_DIR${NC}"
    echo -e "  ${WHITE}- HTML Report: ${HTML_FILE}${NC}"
    echo -e "  ${WHITE}- Text Report: ${REPORT_FILE}${NC}"
}

print_terminal_summary() {
    echo ""
    print_stage "FINAL SCAN SUMMARY" "$BG_GREEN"
    
    local FOUND_ANY=0

    # [NEW] Iterate subdirectories
    for txt_file in "$BASE_OUTPUT_DIR"/*/scan_*.txt; do
        [ -e "$txt_file" ] || continue
        FOUND_ANY=1
        
        local HOST_DIR=$(dirname "$txt_file")
        local BASE_NAME=$(basename "$txt_file" .txt | sed 's/scan_//')
        local IP_TAG=$(echo "$BASE_NAME" | sed 's/_/./g')
        
        local CRED_FILE="$HOST_DIR/creds_${BASE_NAME}.txt"
        local VULN_FILE="$HOST_DIR/vuln_${BASE_NAME}.txt"
        local WEB_FILE="$HOST_DIR/web_${BASE_NAME}.txt"

        echo -e "${CYAN}------------------------------------------------------------${NC}"
        echo -e "${BOLD}HOST: $IP_TAG${NC}"
        
        if [[ -s "$CRED_FILE" ]]; then
            echo -e "${RED}${BOLD}[!!!] COMPROMISED CREDENTIALS FOUND:${NC}"
            cat "$CRED_FILE" | sed "s/^/    ${RED}/" | sed "s/$/${NC}/"
        fi

        local OPEN_PORTS=$(grep "open" "$txt_file" | grep -v "SF:" | wc -l)
        if [[ "$OPEN_PORTS" -gt 0 ]]; then
            echo -e "${GREEN}[+] Open Ports: $OPEN_PORTS${NC}"
            grep "open" "$txt_file" | grep -v "SF:" | awk '{print "    " $1 " " $3}'
        else
            echo -e "${GRAY}[*] No open ports visible.${NC}"
        fi

        if [[ -s "$WEB_FILE" ]]; then
            local TITLE=$(grep -i "<title>" "$WEB_FILE" | head -n 1 | sed 's/.*<title>\(.*\)<\/title>.*/\1/')
            if [[ -n "$TITLE" ]]; then
                echo -e "${BLUE}[+] Web Title:${NC} $TITLE"
            else
                echo -e "${BLUE}[+] Web Server Detected${NC}"
            fi
        fi

        if [[ -s "$VULN_FILE" ]]; then
            local VULN_COUNT=$(wc -l < "$VULN_FILE")
            echo -e "${YELLOW}[!] Potential Exploits: $VULN_COUNT${NC}"
        fi
        echo ""
    done
    
    if [[ "$FOUND_ANY" -eq 0 ]]; then
        echo -e "${YELLOW}[*] No scan data found to display.${NC}"
    fi

    echo -e "${CYAN}------------------------------------------------------------${NC}"
    echo -e "${WHITE}${BOLD}GENERATED FILES (Manifest):${NC}"
    
    # [NEW] Recursive list
    find "$BASE_OUTPUT_DIR" -type f | sort | while read -r f; do
        local REL_PATH=${f#$BASE_OUTPUT_DIR/}
        local SIZE=$(du -h "$f" | cut -f1)
        # Highlight directories vs files visually
        if [[ "$REL_PATH" == *"/"* ]]; then
             echo -e "  ${GRAY}- $REL_PATH ${WHITE}(${SIZE})${NC}"
        else
             echo -e "  ${WHITE}* $REL_PATH ${GRAY}(${SIZE})${NC}"
        fi
    done
    echo ""
}

finalize_results() {
    generate_report
    print_terminal_summary
    
    print_stage "SESSION COMPLETE" "$BG_GREEN"
    
    # [FIX] Force keyboard input to be visible
    stty echo 2>/dev/null
    
    while true; do
        draw_line
        echo -e "${CYAN}  [ACTIONS]${NC}"
        echo -e "  ${WHITE}S)${NC} Search Logs"
        echo -e "  ${WHITE}Z)${NC} Zip & Clean (Recommended)"
        echo -e "  ${WHITE}K)${NC} Keep Raw Files"
        echo -e "  ${WHITE}D)${NC} Delete All"
        draw_line
        read -e -p "  > Choice: " FIN_OPT

        case "${FIN_OPT^^}" in
            S)
                while true; do
                    echo -e "\n${CYAN}  [SEARCH MODE]${NC} (Press ENTER to go back)"
                    read -e -p "  > Query: " SEARCH_QUERY
                    if [[ -z "$SEARCH_QUERY" ]]; then break; fi
                    echo ""
                    grep -r -i --color=always "$SEARCH_QUERY" "$BASE_OUTPUT_DIR" || echo -e "  ${YELLOW}[!] No matches found.${NC}"
                    echo ""
                done
                ;;
            Z)
                zip -r -q "${DIR_NAME}.zip" "$DIR_NAME"
                if [[ -f "${DIR_NAME}.zip" ]]; then
                    if [[ -n "$SUDO_USER" ]]; then
                        chown "$SUDO_USER":"$SUDO_USER" "${DIR_NAME}.zip"
                    fi
                    rm -rf "$BASE_OUTPUT_DIR"
                    
                    # [NEW] Show Absolute Path
                    local FULL_PATH="$(pwd)/${DIR_NAME}.zip"
                    echo -e "\n  ${GREEN}[✓] Data archived to: ${WHITE}$FULL_PATH${NC}"

                    # [NEW] Auto-Open Folder (as normal user, not root)
                    if command -v xdg-open &> /dev/null; then
                        echo -e "  ${CYAN}[*] Opening folder...${NC}"
                        if [[ -n "$SUDO_USER" ]]; then
                            sudo -u "$SUDO_USER" xdg-open . > /dev/null 2>&1
                        else
                            xdg-open . > /dev/null 2>&1
                        fi
                    fi
                fi
                break
                ;;
            K)
                fix_ownership "$BASE_OUTPUT_DIR"
                echo -e "\n  ${GREEN}[✓] Files kept in: $BASE_OUTPUT_DIR${NC}"
                
                # [NEW] Auto-Open Folder for Keep option too
                if command -v xdg-open &> /dev/null; then
                     if [[ -n "$SUDO_USER" ]]; then
                         sudo -u "$SUDO_USER" xdg-open "$BASE_OUTPUT_DIR" > /dev/null 2>&1
                     else
                         xdg-open "$BASE_OUTPUT_DIR" > /dev/null 2>&1
                     fi
                fi
                break
                ;;
            D)
                echo -e "\n  ${RED}[!] Deleting all evidence...${NC}"
                rm -rf "$BASE_OUTPUT_DIR"
                break
                ;;
            *)
                echo -e "  ${RED}[!] Invalid option.${NC}"
                ;;
        esac
    done
    
    echo ""
    cleanup
}

# MAIN
check_root
check_dependencies
show_banner
get_user_input
configure_passwords
perform_scan
finalize_results