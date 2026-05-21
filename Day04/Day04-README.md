# Day 4 — Windows Attack Simulation

## Overview
Day 4 shifts the attack focus to the Windows 11 Enterprise endpoint. Three attacks are simulated from the Kali Linux machine — an Nmap network reconnaissance scan, a Hydra RDP brute force attack, and manual post-exploitation reconnaissance commands. Each attack is detected in Sentinel and two additional custom analytics rules are built, bringing the total to 3 active detection rules covering both Linux and Windows endpoints.

---

## Attacks Simulated

| Attack | Tool | Target | EventIDs |
|--------|------|--------|----------|
| Network Reconnaissance | Nmap | Windows 11 (10.0.0.32) | Network scan |
| RDP Brute Force | Hydra | Windows 11 Port 3389 | 4625 |
| Post-Exploitation Recon | Manual commands | Windows 11 | 4688 |

---

## Step-by-Step Walkthrough

### Step 1 — Nmap Reconnaissance Scan
Before attacking a target, a real attacker performs reconnaissance to discover what services are running. Nmap is run from Kali Linux against the Windows VM to discover open ports.

**Command executed on Kali:**
```bash
nmap -sV -p 1-1000 10.0.0.32
```

**Results:**
- Port 445 — SMB (Server Message Block) — open
- Port 3389 — RDP (Remote Desktop Protocol) — open

**Why this matters:** Finding RDP open on port 3389 tells the attacker that Remote Desktop is enabled and potentially accessible. This immediately becomes an attack vector for brute force or exploitation. In real SOC work, detecting Nmap scans is important because they often precede attacks.

**MITRE ATT&CK:** T1046 — Network Service Discovery

![Kali Nmap Windows Scan](./01-kali-nmap-windows-scan.png)
> Nmap scan results from Kali Linux against Windows VM (10.0.0.32). Ports 445 (SMB) and 3389 (RDP) confirmed open — attack surface identified.

---

### Step 2 — RDP Brute Force Detected in Sentinel
With RDP discovered open, Hydra is used to brute force the RDP login. 14 failed logon attempts are generated against the Windows VM, each producing EventID 4625 in the Windows Security Event log, which flows into Sentinel via the existing AMA pipeline.

**Command executed on Kali:**
```bash
hydra -l ronakmishra -P /usr/share/wordlists/rockyou.txt rdp://10.0.0.32
```

**EventID 4625 fields for RDP:**
- Logon Type: 10 (RemoteInteractive) — confirms RDP attempt
- Source IP: 10.0.0.100 (Kali)
- Account: ronakmishra

**Why this matters:** RDP brute force is one of the most common attack vectors in real enterprise environments. Organizations with RDP exposed to the internet face constant brute force attempts. Detecting this pattern quickly is a core L1 SOC skill.

**MITRE ATT&CK:** T1110 — Brute Force

![Windows RDP Brute Force Detected](./02-windows-rdp-brute-force-detected.png)
> Sentinel Logs showing 14 EventID 4625 failed logon events from 10.0.0.100 against Windows endpoint. RDP brute force confirmed detected.

---

### Step 3 — RDP Analytics Rule KQL Query
A new custom analytics rule is built to detect RDP brute force patterns. The query counts EventID 4625 events per source IP and fires when more than 5 failures are detected within 1 hour.

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedLogons = count() by IpAddress, Account, Computer
| where FailedLogons > 5
```

**Why threshold of 5:** RDP brute force tools typically fire faster than SSH brute force tools. A lower threshold catches attacks earlier without generating too many false positives from legitimate users forgetting their passwords.

![Windows Analytics Rule Query](./03-windows-analytics-rule-query.png)
> KQL query for RDP brute force detection returning results. Source IP 10.0.0.100 shows 14 failed logons against ronakmishra account on RONAKMISHRA345C.

---

### Step 4 — Both Analytics Rules Active
After creating the RDP brute force rule, the Analytics page now shows two active rules — the SSH Brute Force rule from Day 2 and the new RDP Brute Force rule. Both are enabled and running every 5 minutes.

**Why this matters:** Building a detection library is a core responsibility of a SOC engineer. Each analytics rule covers a specific attack pattern. Over time, a mature SOC builds hundreds of rules covering the full MITRE ATT&CK matrix.

![Both Analytics Rules Active](./04-both-analytics-rules-active.png)
> Sentinel Analytics page showing SSH Brute Force Attack Detected and RDP Brute Force Attack Detected rules both active and enabled.

---

### Step 5 — Reconnaissance Commands Detected
Post-exploitation reconnaissance commands are manually executed on the Windows VM to simulate what an attacker would do after gaining access. The commands run are:

```cmd
whoami
net user
ipconfig
```

Each command generates EventID 4688 (process creation) in the Windows Security Event log with the full command line visible. These events flow into Sentinel immediately.

**Why attackers run these commands:**
- `whoami` — identifies which user account they're running as and privilege level
- `net user` — lists all local user accounts on the system
- `ipconfig` — reveals the network configuration, subnet, and gateway

**Why this matters:** Post-exploitation reconnaissance is one of the clearest indicators of compromise in Windows environments. A legitimate user doesn't typically run whoami and net user in sequence. Detecting this pattern is a strong signal that an account has been compromised.

**MITRE ATT&CK:** T1082 — System Information Discovery, T1087 — Account Discovery

![Recon Commands Detected](./05-recon-commands-detected.png)
> Sentinel Logs showing EventID 4688 process creation events for whoami, net user, and ipconfig commands on RONAKMISHRA345C. Full command line visible in CommandLine field.

---

### Step 6 — Recon Analytics Rule Built
A third custom analytics rule is created to detect suspicious reconnaissance commands. The rule uses the has_any operator to match any of the known recon command names in the CommandLine field of EventID 4688 events.

```kql
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(1h)
| where CommandLine has_any ("whoami", "net user", "ipconfig", "systeminfo", "tasklist", "net localgroup")
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
```

**Why this matters:** This rule demonstrates detection engineering — building a query that catches real attacker behavior while minimizing false positives. The has_any operator allows matching multiple suspicious commands in a single rule without writing separate rules for each.

![Recon Analytics Rule](./06-recon-analytics-rule.png)
> Suspicious Reconnaissance Commands Detected analytics rule configuration. Severity set to Medium, MITRE T1082, runs every 5 minutes.

---

### Step 7 — Three Analytics Rules Active
All three custom analytics rules are now active in Sentinel, providing coverage across SSH brute force, RDP brute force, and post-exploitation reconnaissance — covering both Linux and Windows endpoints.

| Rule | Severity | MITRE | Endpoint |
|------|----------|-------|----------|
| SSH Brute Force Attack Detected | High | T1110.001 | Ubuntu |
| RDP Brute Force Attack Detected | High | T1110 | Windows |
| Suspicious Reconnaissance Commands Detected | Medium | T1082 | Windows |

![Three Analytics Rules Active](./07-three-analytics-rules-active.png)
> Sentinel Analytics page showing all three custom detection rules active. Full coverage across SSH brute force, RDP brute force, and reconnaissance detection.

---

## Key Concepts Learned

- Nmap is the standard tool for network reconnaissance — finding open ports reveals attack surface
- RDP (port 3389) is one of the most commonly attacked services in enterprise environments
- EventID 4625 with Logon Type 10 indicates a failed RDP authentication attempt
- EventID 4688 captures every process execution with full command line — essential for detecting post-exploitation activity
- The has_any KQL operator matches any value in a list — efficient for detecting multiple suspicious patterns in one rule
- Building multiple analytics rules creates layered detection coverage across different attack types
- Detection engineering means writing rules that catch real attacker behavior while minimizing false positives

## MITRE ATT&CK
- T1046 — Network Service Discovery (Nmap scan)
- T1110 — Brute Force (RDP brute force via Hydra)
- T1082 — System Information Discovery (whoami, ipconfig)
- T1087 — Account Discovery (net user)
