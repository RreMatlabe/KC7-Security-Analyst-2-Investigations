# KC7-Security-Analyst-2-Investigations

**KC7 Cyber Operations & Incident Response Portfolio — Security Analyst II**

This repository documents hands-on threat hunting, network investigation and Kusto Query Language (KQL) telemetry analysis completed through the **KC7 Security Analyst II** career path.

> **Status: in progress — 3 of 6 modules completed.** Write-ups are added as each module is finished.
>
> Previous path: [KC7-Security-Analyst-1-Investigations](https://github.com/RreMatlabe/KC7-Security-Analyst-1-Investigations) (7/7 modules completed).

Where the Analyst I path was guided, Analyst II asks for more independent judgement: connecting evidence across systems, applying common external datasets and tools, and deciding for myself when to dig deeper and when to move on. So far that has meant learning how networks are laid out and how traffic moves through them (Whiskermania), then using that to rebuild a full kill chain against an industrial control system vendor, from reconnaissance to data exfiltration (Solvi Systems).

**KC7 profile and certificates:** [kc7cyber.com/profile/StoicInvestigator1607](https://kc7cyber.com/profile/StoicInvestigator1607)

---

## 🗺️ Curriculum & Progress

```
Module 1: The Blame Game — Why Hackers Are Hacking          ✅
                ↓
Module 2: Whiskermania — An Intro to Network Concepts       ✅
                ↓
Module 3: Solvi Systems — A Tale of Supply Chains and ICS   ✅
                ↓
Module 4: (to be added)                                     ⏳
                ↓
Module 5: (to be added)                                     ⏳
                ↓
Module 6: (to be added)                                     ⏳
```

| # | Module | Level | Status | Completed | Write-up | Certificate ID |
|---|---|---|---|---|---|---|
| 1 | The Blame Game: Why Hackers Are Hacking | Easy | ✅ Complete | — | _write-up to come_ | — |
| 2 | Whiskermania: An Intro to Network Concepts | Challenging | ✅ Complete | Oct 6, 2026 | [modules/Whiskermania.md](modules/Whiskermania.md) | 94971 |
| 3 | Solvi Systems: A Tale of Supply Chains and ICS | Easy | ✅ Complete | Nov 17, 2026 | [modules/Solvi-Systems.md](modules/Solvi-Systems.md) | 102427 |
| 4 | _to be added_ | | ⏳ | | | |
| 5 | _to be added_ | | ⏳ | | | |
| 6 | _to be added_ | | ⏳ | | | |

---

## 📚 Module Summaries

### Module 1: The Blame Game — Why Hackers Are Hacking
Write-up to come.

### Module 2: Whiskermania — An Intro to Network Concepts

**Scenario:** Whiskers & Wonders, an animal sanctuary and nonprofit, runs its fundraising through a public donation portal. A previous analyst's notes flag a suspicious external IP and workstations talking to it. Working alone, the objective is to explain the network, then trace the traffic.

**Topics:** `networking` · `dns` · `c2-beaconing` · `phishing`

**Skills practiced:**
- Telling public from private IP addresses, and reading a network's layout from its VLAN ranges (workstations, servers, DMZ, restricted zone)
- Ports, TCP vs. UDP, and how DNS, firewall and proxy logs record the same web request
- Following one request across `DnsEvents`, `NetworkFlow` and `ProxyEvents`
- Pivoting from an indicator to the hosts, connections and URL patterns behind it
- Writing detections at the DNS, firewall and proxy layers

**Findings:**

| Phase | Observed activity | Primary table |
|---|---|---|
| Initial access | Lookalike HR domain `whiskersandwonders-hr.com` sent an "Employee Benefits Update Required" email to 3 employees | `Email` |
| C2 | 3 workstations resolved `update-cdn-service.xyz` (`185.174.137.42`) and connected over TCP 443 | `DnsEvents`, `NetworkFlow` |
| Beaconing | Repeated `GET /api/v1/status` and `/api/v1/config` requests that looked like normal API traffic | `ProxyEvents` |
| Duration | C2 active for about 4.8 days across the three hosts | `DnsEvents` |
| Impact | Compromised users included a Development Officer and two Adoption Coordinators with access to the donation system | `Employees` |

[Full write-up →](modules/Whiskermania.md)

### Module 3: Solvi Systems — A Tale of Supply Chains and ICS

**Scenario:** Solvi Systems builds DOCKS, industrial control system (ICS) software, and trades with energy-sector partners. The task is to work out how an attacker who gets into a software vendor could reach the product's development documents, and what that means for customers downstream.

**Topics:** `critical-infrastructure` · `phishing` · `remote-services-exploitation` · `malware`

**Learning objectives:**
- Investigate a supply chain attack involving Industrial Control Systems
- Understand how an attack on ICS software can have downstream impact
- Combine network logs, DNS and authentication events into a timeline from reconnaissance to exfiltration

**Findings:**

| Phase | Observed activity | Primary table |
|---|---|---|
| Alert triage | XSS probe against the public feedback form (`Opera/8.64`, 404) | `InboundNetworkEvents` |
| Reconnaissance | 4 attacker IPs browsing the site and researching the DOCKS product | `InboundNetworkEvents` |
| Infrastructure | Passive DNS pivot from the IPs to 3 lookalike energy-news domains | `PassiveDns` |
| Initial access | 56 phishing emails to 5 roles; first victim a Sales Representative | `Email` |
| Execution & C2 | `ecobug.exe` dropped; beacon to `98.117.26.236:1337`; 38 machines connected to that IP company-wide | `FileCreationEvents`, `NetworkFlow` |
| Persistence | Rogue local account `gu@rd!an` created and added to Administrators | `ProcessEvents` |
| Discovery & lateral | `net view`, `net share`, `net use`; `net use /PERSISTENT:YES` on 3 hosts | `ProcessEvents` |
| Collection | Software development lifecycle documents copied from a network share and archived as `CollectedData.zip` | `ProcessEvents` |
| Exfiltration | `curl` upload to `api.eco-awareness-update.net` | `ProcessEvents` |

The same infrastructure ran through the whole attack: the reconnaissance IP was also the C2 server, and one of the phishing domains received the stolen archive.

[Full write-up →](modules/Solvi-Systems.md)

### Modules 4–6
To be added as completed.

---

## 🛠️ Essential KQL Query Library

All queries below were run during the investigations.

**1. Pivot from attacker IPs to their domains**
```kql
let attacker_ips = dynamic(["105.78.23.64", "13.201.46.208", "56.6.30.190", "98.117.26.236"]);
PassiveDns
| where ip in (attacker_ips)
| distinct domain
```

**2. Find emails by the domains in their links**
```kql
let attacker_domains = PassiveDns
    | where ip in (attacker_ips)
    | distinct domain;
Email
| where link has_any (attacker_domains)
| count
```

**3. Who is talking to a suspicious domain**
```kql
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| summarize count() by client_ip
| order by count_ desc
```

**4. Read the URL pattern behind the beaconing**
```kql
ProxyEvents
| where domain == "update-cdn-service.xyz"
| project timestamp, src_ip, url, method, status_code
| order by timestamp asc
```

**5. Persistence and discovery commands on an endpoint**
```kql
ProcessEvents
| where timestamp >= datetime(2024-05-02)
| where process_commandline has_any ("net user", "useradd", "localgroup") or process_name has_any ("net.exe", "net1.exe")
| project timestamp, hostname, username, process_name, process_commandline
| order by timestamp asc
```

**6. Exfiltration commands**
```kql
ProcessEvents
| where process_commandline has_any ("curl", "eco-awareness-update.net", "DataExfil")
| project timestamp, hostname, username, process_commandline
| order by timestamp asc
```

---

## 🛡️ Key Lessons & Defensive Insights

- **Start from a known indicator, then pivot.** IPs lead to domains, domains to emails, emails to victims, victims to endpoint and network evidence.
- **Know which column and table hold the evidence.** In Solvi Systems my first query returned zero because the attacker's domains sat in the email `link` field, not `sender`. A phishing email can come from Gmail and still point at an attacker domain.
- **One user action leaves many log entries.** A single web request appears in DNS, flow and proxy logs; correlate all three.
- **Encrypted traffic still leaves evidence.** With SSL inspection at the proxy, URL paths such as `/api/v1/status` expose C2 beaconing even over port 443.
- **Frequency is not maliciousness.** Counting the most common domains returned noise; pivoting from threat indicators found the real ones.
- **Block at several layers.** DNS (the domain), firewall (the IP) and proxy (the URL pattern) each catch the attacker differently, and behavioral detections such as regular beacon intervals survive infrastructure changes.
- **Reused infrastructure ties an attack together.** Recon, C2 and exfiltration shared IPs and domains in Solvi Systems.

---

## About This Portfolio

Completed as part of the **KC7 Security Analyst II** training path, following the Analyst I path. This repository is intended to demonstrate practical, hands-on SIEM/KQL investigation skills for SOC Analyst and GRC Analyst roles, including log triage, network and endpoint analysis, and structured incident reporting.

_Last updated: November 2026_
