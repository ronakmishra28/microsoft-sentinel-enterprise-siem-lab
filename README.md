# Microsoft Sentinel Enterprise SIEM Lab

**SC-200 Certified** | CompTIA Security+ | ISC2 CC

This lab simulates a real enterprise SOC environment built entirely from scratch. I connected two virtual machines (Windows 11 and Ubuntu 22.04) to Microsoft Sentinel via Azure Arc, ingested security logs from both endpoints, and used a Kali Linux VM as an attacker to simulate real-world threats including SSH brute force, RDP brute force, and post-exploitation reconnaissance. I then detected those attacks using custom KQL analytics rules, investigated them using threat hunting queries, responded using the NIST incident response framework, and automated the response using a SOAR playbook. Every step is documented with screenshots taken directly from the live environment.

This is not a guided lab or a walkthrough — every component was configured manually, every detection rule was written from scratch, and every incident was investigated end-to-end.

---

## How to Navigate This Repo

| If you want to see... | Go to... |
|----------------------|----------|
| How the lab was set up | [Day 1](./Day01-Environment-Setup/) |
| Multi-endpoint onboarding + first attack | [Day 2](./Day02-Multi-Endpoint-Attack-Simulation/) |
| Incident response investigation | [Day 3](./Day03-Threat-Hunting-Incident-Response/) + [IR Report](./Day03-Threat-Hunting-Incident-Response/IR-2026-001-SSH-Brute-Force.pdf) |
| Windows attack detection | [Day 4](./Day04-Windows-Attack-Simulation/) |
| KQL threat hunting queries | [Day 5](./Day05-KQL-Threat-Hunting/) |
| SOAR automation playbook | [Day 6](./Day06-SOAR-Automation/) |
| SOC Dashboard | [Day 7](./Day07-SOC-Dashboard/) |
| All KQL queries in one place | [Analytics Rules](#analytics-rules) + [Hunting Queries](#threat-hunting-queries) |
| MITRE ATT&CK coverage | [MITRE ATT&CK Coverage](#mitre-attck-coverage) |
| Screenshots | [Day01](./Day01-Environment-Setup/screenshots/) through [Day07](./Day07-SOC-Dashboard/screenshots/) |

---

## Lab Architecture

```
MacBook M4 Pro (Host)
└── Parallels
    ├── Windows 11 Enterprise — RONAKMISHRA345C (10.0.0.32)  → Monitored Endpoint
    ├── Ubuntu 22.04 — ronak (10.0.0.33)                     → Monitored Endpoint
    └── Kali Linux 2025.2 (10.0.0.100)                       → Attack Machine

Microsoft Azure
└── Resource Group: sc200-rg (East US)
    ├── Log Analytics Workspace: sc200-lab
    ├── Microsoft Sentinel
    ├── Azure Arc (connects both VMs to Azure)
    ├── Azure Monitor Agent (on Windows + Ubuntu)
    ├── Data Collection Rules (Windows Security Events + Linux Syslog)
    └── Logic App: Sentinel-Block-IP-Playbook (SOAR)
```

---

## What Was Built

| Component | Details |
|-----------|---------|
| SIEM Platform | Microsoft Sentinel on Log Analytics Workspace |
| Monitored Endpoints | Windows 11 Enterprise + Ubuntu 22.04 via Azure Arc |
| Data Sources | Windows Security Events (AMA) + Linux Syslog (AMA) |
| Analytics Rules | 3 custom detection rules (SSH BF, RDP BF, Recon) |
| Hunting Queries | 4 custom KQL threat hunting queries |
| Incidents | 3 auto-generated incidents from analytics rules |
| SOAR | Logic App playbook + Automation Rule |
| Incident Report | IR-2026-001 (SSH Brute Force — Resolved) |

---

## Lab Timeline

### Day 1 — Environment Setup & Windows Endpoint
- Deployed Microsoft Sentinel workspace (`sc200-lab`)
- Connected Windows VM to Azure Arc
- Installed Azure Monitor Agent on Windows
- Created Data Collection Rule for Windows Security Events
- Connected Windows Security Events via AMA connector
- Verified SecurityEvent logs flowing into Sentinel
- Simulated Windows brute force — detected EventID 4625 failed logons

### Day 2 — Multi-Endpoint Onboarding & Attack Simulation
- Connected Ubuntu VM to Azure Arc
- Installed Azure Monitor Agent on Ubuntu
- Created Linux Syslog Data Collection Rule
- Verified Syslog data flowing from Ubuntu into Sentinel
- Ran Hydra SSH brute force from Kali against Ubuntu — 260 failed attempts detected
- Built custom analytics rule: **SSH Brute Force Attack Detected** (High severity, MITRE T1110.001, runs every 5 min)
- Incident auto-generated: ID 1 — SSH Brute Force Attack Detected — High — Active

### Day 3 — Threat Hunting & Incident Response
- Built attack timeline chart showing 3 attack waves (48, 120, 88 attempts)
- Identified attacker IP (10.0.0.100) and targeted username via KQL forensics
- Confirmed no successful authentication
- Contained attacker IP via UFW: `sudo ufw deny from 10.0.0.100 to any port 22`
- Confirmed block — Kali SSH connection timed out
- Wrote incident report: [IR-2026-001-SSH-Brute-Force](./Day03-Threat-Hunting-Incident-Response/IR-2026-001-SSH-Brute-Force.pdf)

### Day 4 — Windows Attack Simulation
- Ran Nmap from Kali against Windows VM — discovered ports 445 (SMB) and 3389 (RDP) open
- Ran Hydra RDP brute force — 14 failed logons (EventID 4625) detected in Sentinel
- Ran reconnaissance commands on Windows (whoami, net user, ipconfig) — detected via EventID 4688
- Built **RDP Brute Force Attack Detected** analytics rule (High, MITRE T1110)
- Built **Suspicious Reconnaissance Commands Detected** analytics rule (Medium, MITRE T1082)
- 3 active analytics rules total

### Day 5 — KQL Threat Hunting
Built 4 custom hunting queries in Microsoft Sentinel:

| Query | Tactic | Technique |
|-------|--------|-----------|
| Failed Logon Summary by Account | Credential Access | T1110 |
| Suspicious Process Creation on Windows | Execution | T1204 |
| Privilege Escalation Detection | Privilege Escalation | T1068 |
| Linux Recon Detection | Discovery | T1082 |

### Day 6 — SOAR Automation
- Built Logic App playbook: `Sentinel-Block-IP-Playbook`
  - Trigger: Microsoft Sentinel incident
  - Action: Add automated comment to incident with response instructions
- Created Automation Rule: `Auto-Respond to SSH Brute Force`
  - Fires when incident created matching SSH Brute Force analytics rule
  - Automatically runs the playbook
- Granted Sentinel Automation Contributor permissions on resource group

### Day 7 — SOC Dashboard (Azure Monitor Workbooks)
- Built a full enterprise SOC dashboard in Azure Monitor Workbooks connected to the sc200-lab Log Analytics workspace
- Dashboard contains 6 live sections powered by KQL queries:

| Section | Visualization | Data Source |
|---------|--------------|-------------|
| Failed Logon Analysis (Windows) | Bar chart | SecurityEvent — EventID 4625 |
| SSH Brute Force Attack Timeline | Line chart | Syslog — Failed password events |
| Top Attacker IPs | Grid | Syslog — Parsed attacker IP |
| Windows Security Event Distribution | Pie chart | SecurityEvent — EventID 4624/4625/4688/4672 |
| Reconnaissance Commands Detected | Grid | SecurityEvent — EventID 4688 |
| Active Incidents | Grid | SecurityIncident |

---

## Analytics Rules

### Rule 1: SSH Brute Force Attack Detected
```kql
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password" or SyslogMessage contains "authentication failure"
| where Computer == "ronak"
| summarize FailedAttempts = count() by Computer, HostName, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```
- **Severity:** High
- **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
- **Schedule:** Every 5 minutes

### Rule 2: RDP Brute Force Attack Detected
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedLogons = count() by IpAddress, Account, Computer
| where FailedLogons > 5
```
- **Severity:** High
- **MITRE ATT&CK:** T1110 — Brute Force
- **Schedule:** Every 5 minutes

### Rule 3: Suspicious Reconnaissance Commands Detected
```kql
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(1h)
| where CommandLine has_any ("whoami", "net user", "ipconfig", "systeminfo", "tasklist", "net localgroup")
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
```
- **Severity:** Medium
- **MITRE ATT&CK:** T1082 — System Information Discovery
- **Schedule:** Every 5 minutes

---

## Threat Hunting Queries

### Failed Logon Summary by Account
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedLogons = count() by Account, Computer, IpAddress
| where FailedLogons > 5
| order by FailedLogons desc
```

### Suspicious Process Creation on Windows
```kql
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(7d)
| where CommandLine has_any ("whoami", "net user", "ipconfig", "systeminfo", "tasklist", "net localgroup")
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine, IpAddress
| order by TimeGenerated desc
```

### Privilege Escalation Detection
```kql
SecurityEvent
| where EventID in (4672, 4728, 4732, 4756)
| where TimeGenerated > ago(7d)
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| order by TimeGenerated desc
```

### Linux Recon Detection
```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has_any ("whoami", "uname", "ifconfig", "netstat", "ps aux", "id", "cat /etc/passwd")
| project TimeGenerated, HostName, SyslogMessage, Facility, SeverityLevel
| order by TimeGenerated desc
```

---

## Incident Report

**IR-2026-001 — SSH Brute Force Attack Against Ubuntu Server**

| Field | Value |
|-------|-------|
| Date | May 16, 2026 |
| Analyst | Ronak Mishra |
| Severity | High |
| Status | Resolved |
| Attacker IP | 10.0.0.100 (Kali Linux) |
| Target | ronak (Ubuntu 22.04, 10.0.0.33) |
| Total Attempts | 260 failed SSH authentication attempts |
| Attack Duration | ~28 minutes across 3 waves |
| Successful Auth | None |
| MITRE ATT&CK | T1110.001 — Brute Force: Password Guessing |

**Attack Timeline:**
- 05:05 UTC — First wave begins (48 attempts)
- 05:25 UTC — Second wave (120 attempts)
- 05:30 UTC — Third wave (88 attempts)
- 05:45 UTC — Attacker IP identified via KQL forensics
- 05:50 UTC — Containment: `sudo ufw deny from 10.0.0.100 to any port 22`
- 05:52 UTC — Block confirmed, SSH from Kali timed out

Full report: [IR-2026-001-SSH-Brute-Force](./Day03-Threat-Hunting-Incident-Response/IR-2026-001-SSH-Brute-Force.pdf)

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Method |
|--------|-----------|-----------------|
| Credential Access | T1110 — Brute Force | Analytics Rule + Hunting Query |
| Credential Access | T1110.001 — Password Guessing | Analytics Rule |
| Discovery | T1082 — System Information Discovery | Analytics Rule + Hunting Query |
| Execution | T1204 — User Execution | Hunting Query |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation | Hunting Query |

---

## Key Skills Demonstrated

- Azure Arc deployment for hybrid endpoint management
- Azure Monitor Agent installation and Data Collection Rule configuration
- Windows Security Event log analysis (EventID 4625, 4624, 4688, 4672)
- Linux Syslog ingestion and analysis
- KQL query writing for detection, investigation, and hunting
- Custom analytics rule creation with MITRE ATT&CK mapping
- Incident response following NIST IR framework
- Threat containment via UFW firewall rules
- SOAR playbook development with Azure Logic Apps
- Automation rule configuration for automated incident response

---

## Screenshots

| Day | Folder | Contents |
|-----|--------|----------|
| Day 1 | [Day01/](./Day01-Environment-Setup/) | Workspace setup, Arc connection, AMA install, DCR, first logs, KQL queries |
| Day 2 | [Day02/](./Day02-Multi-Endpoint-Attack-Simulation/) | Ubuntu onboarding, Hydra attack detection, analytics rule, incident creation |
| Day 3 | [Day03/](./Day03-Threat-Hunting-Incident-Response/) | Attack timeline, IR forensics, containment, IR report |
| Day 4 | [Day04/](./Day04-Windows-Attack-Simulation/) | Nmap scan, RDP brute force, recon detection, 3 analytics rules |
| Day 5 | [Day05/](./Day05-KQL-Threat-Hunting/) | 4 custom threat hunting queries |
| Day 6 | [Day06/](./Day06-SOAR-Automation/) | SOAR playbook, automation rule, triggered response |
| Day 7 | [Day07/](./Day07-SOC-Dashboard/) | SOC dashboard — 6 sections, live KQL visualizations |

---

## Author

**Ronak Mishra**
- Portfolio: [ronakmishra28.github.io](https://ronakmishra28.github.io)
- Blog: [ronakonweb.medium.com](https://ronakonweb.medium.com)
- LinkedIn: [www.linkedin.com/in/ronakmishra/](https://www.linkedin.com/in/ronakmishra)
- Certifications: SC-200 | CompTIA Security+ | ISC2 CC