# Day 7 — SOC Dashboard (Azure Monitor Workbooks)

## Overview
Day 7 builds a full enterprise SOC dashboard using Azure Monitor Workbooks connected to the sc200-lab Log Analytics workspace. The dashboard visualizes all security data collected throughout the lab in a single unified view — failed logon analysis, SSH brute force attack timeline, top attacker IPs, Windows security event distribution, reconnaissance commands detected, and active incidents. All visualizations are powered by live KQL queries pulling real data from the lab environment.

---

## Dashboard Overview

**Tool:** Azure Monitor Workbooks  
**Workspace:** sc200-lab (East US)  
**Sections:** 6 live KQL-powered visualizations  
**Data Sources:** SecurityEvent + Syslog + SecurityIncident

| Section | Visualization Type | KQL Table | Purpose |
|---------|-------------------|-----------|---------|
| Failed Logon Analysis | Bar chart | SecurityEvent | Credential attack monitoring |
| SSH Brute Force Timeline | Line chart | Syslog | Attack pattern visualization |
| Top Attacker IPs | Grid | Syslog | Attacker attribution |
| Windows Event Distribution | Pie chart | SecurityEvent | Security event baseline |
| Recon Commands Detected | Grid | SecurityEvent | Post-exploitation detection |
| Active Incidents | Grid | SecurityIncident | SOC triage overview |

---

## Why Workbooks?

Azure Monitor Workbooks is the native dashboarding tool for Microsoft Sentinel. Every Microsoft-stack SOC uses Workbooks for:
- Executive security reporting
- Real-time attack monitoring
- Compliance dashboards
- Incident trend analysis
- SOC performance metrics

Unlike static reports, Workbooks refresh automatically and always show current data. The KQL queries powering each visualization are the same queries analysts use for investigation — making the dashboard a live operational tool, not just a reporting artifact.

---

## Dashboard Screenshots

### Section 1 — Dashboard Overview, Key Metrics & Failed Logon Analysis

The dashboard opens with a header showing the lab name and a key metrics summary table providing an at-a-glance view of the entire security posture:

| Incidents | Endpoints | Rules | Hunting Queries | SOAR |
|-----------|-----------|-------|-----------------|------|
| 3 Active | 2 Connected | 3 Active | 4 Custom | 1 Deployed |

Below the metrics, Section 1 shows the Failed Logon Analysis bar chart powered by this KQL query:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(7d)
| summarize FailedLogons = count() by Account
| order by FailedLogons desc
```

**What this shows:** The ronakmishra account has 14 failed logon attempts — consistent with the RDP brute force simulation from Day 4. In a real environment, an analyst would investigate any account showing an unusual number of failures.

![Dashboard Overview](./01-dashboard-overview.png)
> Dashboard header with key metrics table showing 3 incidents, 2 endpoints, 3 rules, 4 hunting queries, and 1 SOAR playbook. Section 1 bar chart showing 14 failed logons for ronakmishra account from Day 4 RDP brute force simulation.

---

### Section 2 — SSH Brute Force Timeline & Section 3 — Top Attacker IPs

**Section 2** visualizes the SSH brute force attack timeline as a line chart, showing the intensity of failed authentication attempts over time grouped into 1-hour buckets.

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

**What this shows:** 751 total failed SSH authentication attempts. The spike visible in the chart corresponds to the Hydra brute force attack waves simulated on Day 2. The timeline makes the attack pattern immediately visible — this is exactly what a SOC analyst would use to brief management on an attack.

**Section 3** shows the Top Attacker IPs grid — a parsed table identifying which source IPs generated the most failed authentication attempts.

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| parse SyslogMessage with * "from " AttackerIP " port" *
| summarize TotalAttempts = count() by AttackerIP, HostName
| order by TotalAttempts desc
```

**What this shows:** 10.0.0.100 (Kali Linux) generated all 751 failed attempts against the ronak Ubuntu endpoint — single source IP dominance is a clear indicator of targeted automated brute force.

![SSH Timeline and Attacker IPs](./02-dashboard-ssh-timeline-attackerip.png)
> Section 2 line chart showing 751 SSH brute force attempts over time with visible attack spike. Section 3 grid showing 10.0.0.100 as sole attacker IP with 751 total attempts against ronak endpoint.

---

### Section 4 — Windows Security Event Distribution

A pie chart showing the distribution of Windows Security Event types across the monitoring period. The query filters for the four most security-relevant EventIDs.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4625, 4624, 4688, 4672)
| summarize Count = count() by EventID, Activity
| order by Count desc
```

**What this shows:** 18,600 total events distributed across:
- EventID 4688 — Process Creation (4.69k) — every command execution captured
- EventID 4672 — Special Privileges Assigned (4.67k) — privilege assignment events
- EventID 4625 — Failed Logon (4.63k) — all failed authentication attempts
- EventID 4624 — Successful Logon (4.62k) — all successful authentications

**Why this matters:** Understanding the baseline event distribution helps analysts identify anomalies. If EventID 4625 suddenly spikes to 50k while normally sitting at 4.63k, that's an immediate red flag. This chart establishes the baseline.

![Windows Event Distribution](./03-dashboard-windows-events.png)
> Section 4 pie chart showing 18.6k total Windows security events. Even distribution across EventID 4688 (process creation), 4672 (privileges), 4625 (failed logons), and 4624 (successful logons).

---

### Section 5 — Reconnaissance Commands Detected

A grid showing all suspicious reconnaissance commands detected on the Windows endpoint via EventID 4688, with timestamp, account, computer, and full command line visible.

```kql
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(7d)
| where CommandLine has_any ("whoami", "net user", "ipconfig", "systeminfo", "tasklist")
| project TimeGenerated, Account, Computer, CommandLine
| order by TimeGenerated desc
```

**What this shows:** All recon command executions from Day 4 simulation — whoami, ipconfig, net user commands with exact timestamps and the RONAKMISHRA345C\ronakmishra account context. In a real incident, this grid would show an analyst exactly what commands a threat actor ran and in what sequence.

![Recon Commands Detected](./04-dashboard-recon-commands.png)
> Section 5 grid showing all reconnaissance commands detected on RONAKMISHRA345C. whoami, ipconfig, net user, and cmd.exe executions visible with timestamps and account context from Day 4 simulation.

---

### Section 6 — Active Incidents

A grid showing all active Sentinel incidents with title, severity, status, and owner — providing a complete SOC triage overview.

```kql
SecurityIncident
| where TimeGenerated > ago(7d)
| project TimeGenerated, Title, Severity, Status, Owner
| order by TimeGenerated desc
```

**What this shows:** All 4 incidents generated during the lab:
- Suspicious Reconnaissance Commands Detected — Medium — New (x2)
- SSH Brute Force Attack Detected — High — New (x2)

**Why this matters:** In a real SOC, this section would be the first thing an analyst checks at the start of their shift. It provides an immediate overview of what needs attention, prioritized by severity and creation time.

![Active Incidents](./05-dashboard-incidents.png)
> Section 6 incidents grid showing 4 active Sentinel incidents. SSH Brute Force incidents (High) and Suspicious Reconnaissance Commands incidents (Medium) with creation timestamps and status.

---

## KQL Queries Summary

All 6 dashboard visualizations are powered by KQL queries that analysts can copy directly into Sentinel Logs for deeper investigation:

```kql
-- Section 1: Failed Logon Analysis
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(7d)
| summarize FailedLogons = count() by Account
| order by FailedLogons desc

-- Section 2: SSH Attack Timeline
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc

-- Section 3: Top Attacker IPs
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| parse SyslogMessage with * "from " AttackerIP " port" *
| summarize TotalAttempts = count() by AttackerIP, HostName
| order by TotalAttempts desc

-- Section 4: Windows Event Distribution
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4625, 4624, 4688, 4672)
| summarize Count = count() by EventID, Activity
| order by Count desc

-- Section 5: Recon Commands
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(7d)
| where CommandLine has_any ("whoami", "net user", "ipconfig", "systeminfo", "tasklist")
| project TimeGenerated, Account, Computer, CommandLine
| order by TimeGenerated desc

-- Section 6: Active Incidents
SecurityIncident
| where TimeGenerated > ago(7d)
| project TimeGenerated, Title, Severity, Status, Owner
| order by TimeGenerated desc
```

---

## Key Concepts Learned

- Azure Monitor Workbooks is the native SOC dashboarding tool in Microsoft Sentinel environments
- Workbooks are powered by KQL queries — the same queries used for investigation power the dashboard
- Dashboards provide at-a-glance security posture visibility without requiring analyst queries
- Baseline charts (like the event distribution pie chart) help analysts identify anomalies by comparison
- A good SOC dashboard surfaces the most important information immediately — incidents by severity, top attackers, attack timelines
- Workbooks refresh automatically showing live data — not static snapshots
- The same KQL query can power both a hunting investigation and a dashboard visualization

## Tools Used
- Azure Monitor Workbooks
- KQL (Kusto Query Language)
- Microsoft Sentinel Log Analytics Workspace (sc200-lab)
