# Day 2 — Multi-Endpoint Onboarding & Attack Simulation

## Overview
Day 2 expands the lab to a true multi-endpoint environment by connecting the Ubuntu 22.04 VM to Azure Arc and Sentinel. A real SSH brute force attack is then executed from the Kali Linux attack machine using Hydra, generating 260 failed authentication attempts against the Ubuntu endpoint. A custom analytics rule is built to detect this attack pattern, and Sentinel automatically generates an incident — demonstrating the full detection pipeline from attack to alert to incident.

---

## What Was Built

| Component | Details |
|-----------|---------|
| Second Endpoint | Ubuntu 22.04 — ronak (10.0.0.33) |
| Attack Machine | Kali Linux 2025.2 (10.0.0.100) |
| Data Source | Linux Syslog via Azure Monitor Agent |
| Data Collection Rule | sc200-linux-dcr |
| Analytics Rule | SSH Brute Force Attack Detected (High, T1110.001) |
| First Incident | ID 1 — SSH Brute Force Attack Detected — High |

---

## Step-by-Step Walkthrough

### Step 1 — Connect Ubuntu VM to Azure Arc
The Ubuntu 22.04 VM is connected to Azure Arc using the same process as the Windows VM. The Arc agent is installed on Ubuntu, registering it in Azure and giving Sentinel visibility into the Linux endpoint.

**Why this matters:** Most enterprise environments run a mix of Windows and Linux servers. A SOC analyst must be able to monitor both. Adding the Ubuntu VM creates a realistic multi-OS environment.

![Ubuntu Arc Connected](./01-ubuntu-arc-connected.png)
> Ubuntu 22.04 VM (ronak) successfully registered in Azure Arc. Arc agent installed and reporting Connected status.

---

### Step 2 — Both Endpoints Connected (Money Shot)
With both VMs connected to Azure Arc, the Azure Arc Machines page now shows two connected endpoints — RONAKMISHRA345C (Windows) and ronak (Ubuntu). This confirms the multi-endpoint monitoring environment is fully operational.

**Why this matters:** This screenshot demonstrates enterprise-scale endpoint coverage. In a real SOC, you would see hundreds or thousands of machines in this view. Having multiple endpoints in a single Sentinel workspace is the foundation of centralized security monitoring.

![All Endpoints Arc Connected](./02-all-endpoints-arc.png)
> Azure Arc Machines page showing both endpoints connected — RONAKMISHRA345C (Windows 11) and ronak (Ubuntu 22.04). Both show Connected status.

---

### Step 3 — Install Azure Monitor Agent on Ubuntu
The Azure Monitor Linux Agent is installed on the Ubuntu VM. This is the equivalent of the Windows AMA but for Linux systems. It will collect Syslog data from the Ubuntu endpoint.

**Why this matters:** Linux uses Syslog as its primary logging mechanism. Authentication events including SSH login attempts are logged to /var/log/auth.log and forwarded via Syslog. AMA captures these and sends them to Sentinel.

![Ubuntu AMA Installed](./03-ubuntu-ama-installed.png)
> Azure Monitor Linux Agent installed successfully on Ubuntu VM ronak. Extension status shows Succeeded.

---

### Step 4 — Data Collection Rule Overview
The sc200-linux-dcr Data Collection Rule is configured to collect Syslog data from the Ubuntu endpoint. The DCR specifies which Syslog facilities to collect (authpriv for authentication events) and sends them to the sc200-lab workspace.

**Why this matters:** Linux Syslog has multiple facilities — authpriv handles authentication, daemon handles background services, kern handles kernel messages. Configuring the DCR to collect authpriv specifically ensures SSH authentication attempts are captured without ingesting unnecessary data.

![DCR Overview](./04-dcr-overview.png)
> Data Collection Rule overview showing both sc200-windows-dcr and sc200-linux-dcr configured. Linux DCR collecting Syslog from Ubuntu endpoint.

---

### Step 5 — Ubuntu Syslog Flowing into Sentinel
After the DCR is configured, verification confirms that Linux Syslog data is flowing into the Sentinel Syslog table. SSH authentication events from the Ubuntu endpoint are now visible in Sentinel.

```kql
Syslog
| where HostName == "ronak"
| where TimeGenerated > ago(1h)
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

![Ubuntu Syslog in Sentinel](./05-ubuntu-syslog-sentinel.png)
> Syslog table in Sentinel showing live events from Ubuntu endpoint ronak. Authentication events confirmed flowing into workspace.

---

### Step 6 — Hydra SSH Brute Force Detected in Sentinel
A real SSH brute force attack is launched from the Kali Linux VM using Hydra against the Ubuntu endpoint (10.0.0.33) targeting the ronak account. Hydra attempts 260 password combinations. Each failed attempt generates a Syslog entry containing "Failed password" which is immediately ingested into Sentinel.

**The Hydra command used:**
```bash
hydra -l ronak -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.33
```

**What the Syslog entries look like:**
```
sshd[1234]: Failed password for ronak from 10.0.0.100 port 54321 ssh2
```

**Why this matters:** SSH brute force is one of the most common real-world attacks. Any Linux server with SSH exposed to the internet receives hundreds of brute force attempts daily. This simulation recreates exactly what a SOC analyst would see in production.

![Kali Brute Force Detected in Sentinel](./06-kali-brute-force-detected-sentinel.png)
> Sentinel Logs showing 260 failed SSH authentication attempts from Kali Linux (10.0.0.100) against Ubuntu endpoint (10.0.0.33). Attack confirmed detected in real time.

---

### Step 7 — Analytics Rule Configuration (General Tab)
A custom scheduled analytics rule is created to automatically detect SSH brute force patterns. The rule is configured with:
- Name: SSH Brute Force Attack Detected
- Severity: High
- MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
- Schedule: Every 5 minutes

**Why this matters:** Analytics rules are the automated detection engine of Sentinel. Without them, Sentinel is just a log storage system. This rule transforms the raw Syslog data into actionable security alerts.

![Analytics Rule General Tab](./07-analytics-rule-general.png)
> Analytics rule configuration showing name, severity (High), description, and MITRE ATT&CK mapping (T1110.001).

---

### Step 8 — Analytics Rule KQL Query
The KQL query powering the analytics rule counts failed SSH authentication attempts per host within a 5-minute window. When the count exceeds 10, the rule fires.

```kql
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password"
|    or SyslogMessage contains "authentication failure"
| where Computer == "ronak"
| summarize FailedAttempts = count() by Computer, HostName, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

**Why threshold of 10:** Normal SSH authentication might fail once or twice (mistyped password). 10 failures in 5 minutes from the same source is statistically anomalous and indicates automated brute force activity.

![Analytics Rule Query](./08-analytics-rule-query-results.png)
> KQL query results showing failed SSH attempts summarized by 5-minute bins. Query returns results confirming the detection logic works against real attack data.

---

### Step 9 — Analytics Rule Created
The analytics rule is saved and activated. It will now run every 5 minutes, automatically scanning incoming Syslog data for SSH brute force patterns.

![Analytics Rule Created](./09-analytics-rule-created.png)
> SSH Brute Force Attack Detected analytics rule active in Sentinel. Rule shows Enabled status and will run every 5 minutes.

---

### Step 10 — Brute Force KQL Summary
A KQL query summarizes the brute force attack showing total attempt count, source IP, and targeted hostname.

![Brute Force Summary KQL](./10-brute-force-summary-kql.png)
> KQL query summarizing SSH brute force — 260 total failed attempts from 10.0.0.100 against ronak endpoint confirmed.

---

### Step 11 — Incident Auto-Generated
Within 90 minutes of the attack, the analytics rule fires and Sentinel automatically creates Incident ID 1: SSH Brute Force Attack Detected — High severity. This demonstrates the end-to-end detection pipeline working as intended.

**Alert vs Incident distinction:**
- An alert is a single firing of the analytics rule
- An incident is a case created from one or more grouped alerts
- SOC analysts work incidents, not individual alerts

![Incident Generated](./11-incident-generated.png)
> Microsoft Sentinel Incidents page showing auto-generated Incident ID 1 — SSH Brute Force Attack Detected — High severity — Active status.

---

### Step 12 — Incident Details
Opening the incident reveals the full attack context — alert count, activity timeline, entities involved, and the analytics rule that triggered it.

![Incident Details](./12-incident-details.png)
> Incident details showing attack timeline, 2 active alerts, entities (attacker IP 10.0.0.100, target ronak), and linked analytics rule.

---

### Step 13 — Incident Assigned
The incident is assigned to analyst Ronak Mishra and status is changed to In Progress, beginning the formal incident response workflow.

**Why this matters:** Incident assignment and status tracking is how SOC teams manage their workload. In real environments, incidents are assigned based on analyst availability, expertise, and severity. Tracking status ensures nothing falls through the cracks.

![Incident Assigned](./13-incident-assigned.png)
> Incident ID 1 assigned to Ronak Mishra. Status changed to In Progress. Formal incident response workflow initiated.

---

## Key Concepts Learned

- Linux Syslog is the primary log source for SSH authentication events on Ubuntu
- Azure Monitor Linux Agent collects authpriv Syslog facility for authentication monitoring
- Hydra is a common brute force tool — understanding attacker tools helps build better detections
- Analytics rules are scheduled KQL queries that automatically create incidents when thresholds are exceeded
- The alert-to-incident pipeline is the core workflow of a SIEM-based SOC
- Incident assignment and status tracking are essential SOC operational practices

## MITRE ATT&CK
- T1110.001 — Brute Force: Password Guessing (SSH brute force via Hydra)
