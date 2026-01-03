# ZX301 - Remote Anonymized Security Audit Framework

![ZX301 Cover Image](ZX301.png)

---

## 📖 Executive Summary

The **ZX301 Security Framework** is a comprehensive Bash-based tool designed to perform automated, anonymous, and remote network reconnaissance.

Traditional scanning from a local machine can expose the auditor's identity and location. ZX301 addresses this by establishing a secure SSH connection to a remote server and utilizing that server as a **pivot point**. All scanning traffic originates from the pivot server, keeping the auditor's local network disassociated from the target.

Crucially, the tool enforces strict Operational Security (OpSec) during the setup and control phases by routing local traffic through the **Tor network** using **NIPE**, ensuring the auditor's location remains obfuscated even while communicating with the pivot server.

---

## ✨ Key Features

* **🛡️ Anonymity & OpSec (NIPE Integration):** Routes local control traffic through Tor. Includes a "Geo-Location Kill Switch" that verifies the Tor exit node location and refuses to proceed if the exit IP is located in the auditor's home country (specifically filtering against "IL").
* **📡 Remote Execution Architecture:** Utilizes `sshpass` for non-interactive authentication, executing scanning commands (`nmap`, `whois`, `ping`) directly on the remote pivot server to minimize local bandwidth usage.
* **🔍 Intelligent Hybrid Scanning Engine:** Implements a "Fast then Deep" logic to optimize scanning speed and reduce noise.
* **💾 Fail-Safe Data Recovery:** Features a robust signal trapping mechanism. If the script is interrupted (e.g., Ctrl+C), it attempts to connect to the remote server and securely download partial data before cleaning up remote traces.
* **📊 Automated Reporting:** Parses raw scan outputs to generate readable Markdown and plain text reports, highlighting discovered ports, services, and potential vulnerabilities.

---

## ⚙️ Technical Implementation

### 1. OpSec & Geo-Location Kill Switch
Before any connection is made, the script verifies the anonymity layer. It ensures the assigned Tor exit node is not local to avoid accidental exposure.

```bash
# Verify anonymity: Ensure exit node is NOT Israel (IL)
RESULT=$(curl -s --max-time 8 [https://wtfismyip.com/json](https://wtfismyip.com/json))
COUNTRY=$(echo "$RESULT" | jq -r '.YourFuckingCountryCode // empty')

if [[ "$COUNTRY" != "IL" ]]; then
    echo -e "${GREEN}[NIPE] Anonymity verified.${RESET}"
    log "Anonymity achieved — Exit IP: $EXIT_IP Country: $COUNTRY"
    return 0
else
    # If exit is IL, force NIPE restart to get new circuit
    echo -e "${RED}[NIPE] Still IL exit. Retrying...${RESET}"
fi
2. Remote Pivot Execution
Commands are injected over SSH without interactive prompts using sshpass.

Bash

# Execute commands remotely without user interaction
# -o StrictHostKeyChecking=no: Prevents host key confirmation prompts
sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$REMOTE_PORT" \
    "$REMOTE_USER@$REMOTE_HOST" "command_to_run"
3. Hybrid Scan Workflow
To speed up the process, a fast SYN scan is performed first. The detected ports are extracted, and a heavy vulnerability scan is run only on those active ports.

Bash

# 1. FAST SCAN: High rate SYN scan to find open ports quickly
nmap -Pn -p- -T3 --max-retries 1 --min-rate 300 ... -oG output.gnmap $TARGET

# 2. EXTRACT PORTS: Parse Grepable Nmap output for open ports
OPEN_PORTS=$(grep -oP '\d+(?=/open)' output.gnmap | paste -sd, -)

# 3. DEEP SCAN: Targeted service versioning and vulnerability scripts on open ports only
nmap -Pn -sV --script vuln -p $OPEN_PORTS -T3 -oA deep_scan $TARGET
4. Fail-Safe Data Recovery (Cleanup Trap)
Operational security requires leaving zero footprints. This function ensures remote temporary files are wiped, but attempts to recover data first if the script crashes unexpectedly.

Bash

# Trap system signals (like Ctrl+C) to trigger cleanup
trap cleanup SIGINT
trap cleanup ERR

cleanup() {
    log "Interrupt detected — inspecting remote directory..."
    
    # Attempt SCP recovery of partial data before deletion
    sshpass -p "$SSH_PASS" scp -r ... "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" "$LOCAL_SAVE/"
    
    # Securely remove remote evidence
    sshpass ... "rm -rf $REMOTE_DIR"
}
🚀 Getting Started
System Requirements
OS: Kali Linux (recommended) or Debian-based distribution.

Privileges: Must be run as root (via sudo).

Remote Pivot: A VPS or remote server with SSH access and sudo rights.

Dependencies
The script is designed to auto-install missing dependencies on the local machine upon first run. Key dependencies include:

Perl & Nipe (for Tor routing)

Tor

SSHPass

Nmap

JQ (JSON processor)

Git

Installation & Usage
Clone the repository:

Bash

git clone [https://github.com/ibrianoz/ZX301.git](https://github.com/ibrianoz/ZX301.git)
cd ZX301
Make the script executable:

Bash

chmod +x zx301.sh
Run as root:

Bash

sudo ./zx301.sh
Follow the on-screen prompts to configure the remote pivot server details and select a scanning mode (Single IP or Network Scan).

📂 Output Structure
All session data is saved locally within the script directory:

Plaintext

nipe_tool/
├── Sessions/
│   └── SessionName_Date_Time/
│       ├── raw_archives/       # Raw data downloaded via SCP from pivot
│       ├── extracted/          # Processed scan files (nmap, xml, gnmap)
│       ├── report.md           # Generated Markdown summary report
│       ├── report.txt          # Plain text version of the report
│       └── session.log         # Full audit trail of the session
└── nipe/                       # Local Nipe installation
⚠️ Disclaimer
This tool is created for educational purposes and authorized security auditing only. The author is not responsible for any misuse or damage caused by this software. Ensure you have explicit permission before scanning any network or system.
