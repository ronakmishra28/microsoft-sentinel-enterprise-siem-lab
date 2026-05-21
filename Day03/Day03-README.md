# Day 3 — Threat Hunting & Incident Response

## Overview
Day 3 focuses on the full incident response lifecycle for the SSH brute force incident detected on Day 2. Using KQL forensic investigation, the attack timeline is reconstructed, the attacker IP and targeted account are confirmed, and the absence of successful authentication is verified. The attacker IP is then blocked via UFW on the Ubuntu endpoint, the block is confirmed, and a professional incident report is written documenting the entire investigation.

---

## Incident Details

| Field | Value |
|-------|-------|
| Incident ID | IR-2026-001 |
| Title | SSH Brute Force Attack Detected |
| Severity | High |
| Status | Resolved |
| Attacker IP | 10.0.0.100 (Kali Linux) |
| Target | ronak (Ubuntu 22.04, 10.0.0.33) |
| Total Attempts | 260 failed SSH authentication attempts |
| Attack Duration | ~28 minutes across 3 waves |
| Successful Auth | None |
| MITRE ATT&CK | T1110.001 — Brute Force: Password Guessing |

---

## Incident Response Process (NIST Framework)

This investigation follows the NIST Incident Response Framework:
**Preparation → Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned**

---

## Step-by-Step Walkthrough

### Step 1 — Attack Timeline Chart
The first step of the investigation is building a visual attack timeline using KQL. The query groups failed SSH attempts into 1-hour buckets and renders them as a time chart, revealing the pattern and intensity of the attack.

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| summarize FailedAttempts = count() by bin(TimeGenerated, 30m)
| render timechart
```

**What the timeline revealed:**
- Wave 1: 48 attempts (05:05 UTC)
- Wave 2: 120 attempts — highest intensity (05:25 UTC)
- Wave 3: 88 attempts (05:30 UTC)
- Total: 260 attempts over ~28 minutes

The multi-wave pattern is characteristic of automated brute force tools that pause between wordlist segments. This is consistent with Hydra behavior.

**Why this matters:** Building a timeline is the first step in any incident investigation. It establishes when the attack started, how long it lasted, and whether there were patterns that indicate attacker behavior.

![Attack Timeline Chart](./01-attack-timeline-chart.png)
> KQL time chart showing 3 distinct waves of SSH brute force activity. Wave 2 shows highest intensity at 120 attempts. Attack spans approximately 28 minutes.

---

### Step 2 — Attacker IP and Username Identification
KQL forensic investigation confirms the exact source IP of the attack and the targeted username. The parse operator extracts the IP address directly from the Syslog message text.

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(7d)
| parse SyslogMessage with * "from " AttackerIP " port" *
| parse SyslogMessage with * "for " TargetUser " from" *
| summarize TotalAttempts = count() by AttackerIP, TargetUser, HostName
| order by TotalAttempts desc
```

**Results confirmed:**
- Attacker IP: 10.0.0.100 (Kali Linux VM)
- Target username: ronak
- Target host: ronak (Ubuntu 22.04)

**Why this matters:** Identifying the exact source IP and targeted account is essential for containment. You cannot block the right IP or protect the right account without this information. In real incidents, the attacker IP would be looked up in threat intelligence databases to determine if it is a known malicious actor.

![Attacker IP and Username](./02-attacker-ip-username.png)
> KQL query results confirming attacker IP (10.0.0.100), targeted username (ronak), and total attempt count (260). Attribution confirmed.

---

### Step 3 — Successful Login Verification
A critical step in any brute force investigation is confirming whether the attack succeeded. This KQL query searches for successful SSH authentications from the attacker IP during the attack window.

```kql
Syslog
| where SyslogMessage contains "Accepted password"
|    or SyslogMessage contains "Accepted publickey"
| where TimeGenerated > ago(7d)
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

**Result: No successful authentications found.**

This confirms the attack failed completely — the attacker did not gain access to the Ubuntu endpoint at any point.

**Why this matters:** Determining whether an attack succeeded changes the severity of the response. A failed brute force requires containment. A successful one requires full incident response including password resets, forensic investigation of attacker activity, and potential breach notification.

![Successful Logins Check](./03-successful-logins-check.png)
> KQL query showing zero successful authentication events from attacker IP during the attack window. Attack confirmed unsuccessful — no compromise occurred.

---

### Step 4 — Containment: Block Attacker IP via UFW
With the investigation complete and no compromise confirmed, the attacker IP is blocked on the Ubuntu endpoint using UFW (Uncomplicated Firewall). The deny rule prevents any further SSH connection attempts from 10.0.0.100.

**Command executed on Ubuntu:**
```bash
sudo ufw deny from 10.0.0.100 to any port 22
sudo ufw status
```

**Why UFW was used:** UFW is Ubuntu's built-in firewall management tool. In a real enterprise environment, this block would be implemented at the network perimeter firewall or via an automated SOAR playbook. For this lab environment, UFW provides an equivalent containment mechanism.

**Why this matters:** Containment is the most time-critical phase of incident response. Every second the attacker IP remains unblocked is another opportunity for a successful breach. Speed of containment directly impacts blast radius.

![Attacker IP Blocked](./04-attacker-ip-blocked.png)
> UFW deny rule deployed on Ubuntu endpoint. Rule shows: DENY IN from 10.0.0.100 to any port 22. Containment actioned.

---

### Step 5 — Block Confirmed
The containment is verified by attempting an SSH connection from the Kali Linux VM (10.0.0.100) to the Ubuntu endpoint after the UFW rule is deployed. The connection times out — confirming the block is working correctly.

**Verification command on Kali:**
```bash
ssh ronak@10.0.0.33
```

**Result: Connection timed out — no route to host on port 22.**

**Why this matters:** Never assume a containment action worked. Always verify. In real SOC environments, failed containment actions due to misconfiguration are a documented failure mode. Verification closes the loop on the incident response process.

![Attack Blocked Confirmed](./05-attack-blocked-confirmed.png)
> SSH connection attempt from Kali Linux (10.0.0.100) to Ubuntu (10.0.0.33) timing out after UFW rule deployment. Containment confirmed effective.

---

## Incident Report

A full professional incident report was written documenting this investigation:

**[IR-2026-001-SSH-Brute-Force.docx](./IR-2026-001-SSH-Brute-Force.docx)**

The report covers:
- Executive summary
- Complete attack timeline
- Attack details and technical indicators
- Detection method and KQL query
- Investigation findings
- Containment actions taken
- Recommendations to prevent recurrence
- Lessons learned

---

## Key Concepts Learned

- KQL forensic investigation is the primary tool for incident analysis in Sentinel
- The parse operator extracts structured data from unstructured Syslog messages
- Confirming no successful authentication is a required step in every brute force investigation
- UFW is Ubuntu's built-in firewall — deny rules block specific IPs from reaching specific ports
- Containment must always be verified — never assume it worked
- Professional incident reports document the full investigation for audit, compliance, and knowledge transfer purposes
- The NIST IR Framework provides the structured methodology: Detection → Analysis → Containment → Eradication → Recovery

## MITRE ATT&CK
- T1110.001 — Brute Force: Password Guessing (detected and contained)
