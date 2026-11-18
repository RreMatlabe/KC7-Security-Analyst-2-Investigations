# Whiskermania — An Intro to Network Concepts (KC7)

**Security Analyst II path, Module 2** · Completed Oct 6, 2026 · KC7 Foundation certificate ID 94971

---

## Scenario

Whiskers & Wonders is an animal sanctuary (a nonprofit) whose donations come through a public `DonationPortal`. A previous analyst, Jamie, left behind notes flagging a suspicious external IP, `185.174.137.42`, and workstations talking to it. A colleague, Morgan, walks the new analyst through how the network is laid out, then leaves the analyst to investigate alone.

**Dataset:** `WhiskersAndWonders` (Azure Data Explorer, KC7)

**Tables available (16):** ALittleHelp, AuthenticationEvents, DeviceInfo, DnsEvents, DomainRegistrations, Email, Employees, FileCreationEvents, FirewallEvents, NetworkFlow, PassiveDns, ProcessEvents, ProxyEvents, SecurityAlerts, VPNAuthEvents, WebAppFirewall

---

## Section 2 — Network layout and IP addressing

### IP addressing: public vs. private

An IPv4 address has four octets (8 bits each, values 0–255). Private ranges are not routable on the internet:

| Range | Notes |
|---|---|
| `10.0.0.0` – `10.255.255.255` | anything starting with 10 |
| `172.16.0.0` – `172.31.255.255` | 172.16 through 172.31 |
| `192.168.0.0` – `192.168.255.255` | anything starting with 192.168 |

Everything else is public.

| IP | Answer | Why |
|---|---|---|
| `10.10.16.5` | private | starts with 10 |
| `8.8.8.8` | public | Google's public DNS server |
| `192.168.1.1` | private | common home router address |
| `172.20.50.1` | private | 172.20 is inside 172.16–172.31 |
| `52.214.98.1` | public | AWS cloud server, not in any private range |
| `185.174.137.42` | public | Jamie's circled IP, flagged twice |

### Network segmentation (VLANs)

```kql
DeviceInfo
| summarize device_count=count() by vlan
| order by device_count desc
```

| VLAN | Devices | IP range |
|---|---|---|
| workstations | 36 | `10.10.16.x` |
| servers | 9 | `10.10.1.x` |
| dmz | 6 | `10.10.0.x` |
| restricted | 1 | `10.10.2.x` |
| perimeter | 1 | — |

**5 VLANs in total; workstations has the most devices.** The IP range tells you where a device lives.

### Key devices

| Question | Answer |
|---|---|
| IP of `DonationPortal` (DMZ) | `10.10.0.3` |
| IP of `MailServer01` (servers) | `10.10.1.2` |
| Device in the restricted zone | `DomainController` (`10.10.2.1`) |
| VLAN for `10.10.1.x` | servers |
| Workstation range | `10.10.16.x` |
| IP of `DNS-Server` | `10.10.1.7` |
| Table that shows DNS lookups | `DnsEvents` |
| Zone containing the Domain Controller | restricted |

**DMZ devices (from the query output):**

| Name | IP |
|---|---|
| Proxy-Server | `10.10.0.1` |
| WebServer01 | `10.10.0.2` |
| DonationPortal | `10.10.0.3` |
| KittenCamServer | `10.10.0.4` |
| VPN-Gateway | `10.10.0.5` |
| Web-Server | `10.10.0.6` |

---

## Section 3 — Ports, protocols and tracing traffic

### Ports and protocols

| Port | Service |
|---|---|
| 22 | SSH (remote command line) |
| 25 | SMTP (sending email) |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 3389 | RDP (Windows remote desktop) |

- Port range: 0 to **65535**.
- **SMTP** = Simple Mail Transfer Protocol.
- **TCP** (Transmission Control Protocol): reliable and ordered, uses a handshake. **UDP** (User Datagram Protocol): fast, no delivery confirmation.
- DNS primarily uses **UDP**.
- Protocol split on this network (`NetworkFlow`): **TCP 241,244** flows vs. **UDP 26,922**, so TCP carries the majority.

```kql
NetworkFlow
| summarize count() by protocol
| order by count_ desc
```

**Busiest destination ports (Q6):**

```kql
NetworkFlow
| summarize traffic=count() by dest_port
| order by traffic desc
| take 5
```

| dest_port | Service | Flows |
|---|---|---|
| 25 | SMTP (email) | 62,759 |
| 443 | HTTPS | 37,113 |
| 8443 | alternate HTTPS | 36,386 |
| 53 | DNS | 16,541 |
| 80 | HTTP | 12,619 |

**Answer: 25.** SMTP carries the most traffic on this network. Note that 443 is only second, and 53 (DNS) is fourth even though every web request starts with a lookup.

### DNS

- **DNS** = Domain Name System. It runs before any connection is made.
- `query_name` is the column holding the looked-up domain in `DnsEvents`.
- An **A record** maps a domain to an IPv4 address (AAAA = IPv6, MX = mail server, CNAME = alias).
- **TTL** = Time To Live: how long the client caches the answer.

`DnsEvents` columns seen: `timestamp`, `client_ip`, `query_name`, `query_type`, `resolved_ips`, `dns_server`, `ttl`.

### Tracing one request across log sources

Worked example with `docs.google.com` from workstation `10.10.16.14`:

| Step | Table | What it shows | Result |
|---|---|---|---|
| 1 | `DnsEvents` | Domain → IP | `docs.google.com` → `152.52.146.99` |
| 2 | `NetworkFlow` | UDP to DNS server, port 53 | UDP, dest `10.1.1.1` |
| 3 | `NetworkFlow` | TCP to website, port 443 | `10.10.16.14` → `152.52.146.99`, TCP 443 |
| 4 | `ProxyEvents` | Full URL and response | status code **200** |

**The DNS lookup happens first**, then the TCP connection. One user action creates entries in several tables, so you have to correlate across them.

```kql
DnsEvents
| where query_name == "docs.google.com"
| where query_type == "A"
| project timestamp, client_ip, query_name, resolved_ips
| take 1

NetworkFlow
| where src_ip == "10.10.16.14"
| where timestamp between (datetime(6/3/2025, 8:39:19 AM) .. datetime(6/3/2025, 8:59:19 AM))
| where dest_port == "53"
| project timestamp, src_ip, dest_ip, dest_port, protocol
| limit 10

ProxyEvents
| where src_ip == "10.10.16.14"
| where domain == "docs.google.com"
| where timestamp between (datetime(2025-06-03 08:50:00) .. datetime(2025-06-03 09:00:00))
| project timestamp, src_ip, url, status_code
| take 1
```

### Proxy and HTTP

- `ProxyEvents` logs the full URL (the shelter does SSL inspection), in the `url` column.
- Status codes: **200** OK/success, 301/302 redirect, 403 forbidden, 404 not found, 500 server error.
- Methods: GET (retrieve), **POST** (submit form data), PUT (update), DELETE (remove).

---

## Section 4 — Investigating the compromise

### Following Jamie's suspicious IP (Q1–Q5)

```kql
DnsEvents
| where resolved_ips has "185.174.137.42"
| distinct query_name
```

The domain behind the IP is **`update-cdn-service.xyz`** (plus a `www.` variant). It is an **external** domain. The `.xyz` TLD is cheap and often used by attackers, and the name is made to look like boring CDN infrastructure.

**Who queried it:**

```kql
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| summarize count() by client_ip
| order by count_ desc
```

| Internal IP | DNS queries |
|---|---|
| `10.10.16.14` | 6 |
| `10.10.16.7` | 3 |
| `10.10.16.24` | 3 |

**3 distinct internal hosts** queried the domain. All three are workstations (`10.10.16.x`).

**Network connections to the IP:**

```kql
NetworkFlow
| where dest_ip == "185.174.137.42"
| project timestamp, src_ip, dest_ip, dest_port, protocol, bytes
| take 10
```

All connections are **TCP 443** (HTTPS), 6 records in total:

| Time (UTC) | Source |
|---|---|
| 2025-06-02 23:52:35 | `10.10.16.14` |
| 2025-06-03 09:13:43 | `10.10.16.14` |
| 2025-06-05 18:12:44 | `10.10.16.7` |
| 2025-06-05 18:39:44 | `10.10.16.7` |
| 2025-06-07 19:11:55 | `10.10.16.24` |
| 2025-06-07 19:54:55 | `10.10.16.24` |

Attackers use 443 because it is almost always allowed through firewalls and looks like normal browsing.

### Proxy logs: the C2 pattern (Q6–Q8)

```kql
ProxyEvents
| where domain == "update-cdn-service.xyz"
| project timestamp, src_ip, url, method, status_code
| order by timestamp asc
```

Repeated URL paths: `/api/v1/status`, `/api/v1/config`, `/api/v1`.

- The first request is `GET https://update-cdn-service.xyz/api/v1/status` from `10.10.16.14` at **2025-06-02 23:52:35**, status **404**.
- `/status` means "I'm still here, any instructions?" and `/config` means "send me my configuration".
- **C2** = Command and Control. Regular, predictable check-ins are **beaconing**. Common intervals are 5 min, 15 min, 30 min or 1 hour. Legitimate browsing is random; beacons are not.

### Initial access: phishing (Q10–Q12)

```kql
Email
| where sender !endswith "@whiskersandwonders.org"
| where sender contains "whiskersandwonders"
| project timestamp, sender, recipient, subject
```

- Lookalike sender domain: **`whiskersandwonders-hr.com`** (the legitimate domain is `whiskersandwonders.org`).
- Sender seen: `noreply@whiskersandwonders-hr.com`, 9 records, 2025-06-02 16:00 through 2025-06-05 16:00.
- Subject: **`[EXTERNAL] Important: Employee Benefits Update Required`**. The urgency marker and the impersonated HR authority are textbook social engineering: create pressure, then get people to click before they think.

```kql
Email
| where sender contains "whiskersandwonders-hr.com"
| distinct recipient
```

**3 employees** received it: `alex_rivera`, `jessica_huang` and `david_okonkwo` (all `@whiskersandwonders.org`).

### Were all three compromised? (Q13)

```kql
// Phishing recipients
Email
| where sender contains "whiskersandwonders-hr.com"
| distinct recipient

// Compare to C2 DNS queries
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip
```

Three phishing targets, and three distinct machines (`10.10.16.14`, `10.10.16.7`, `10.10.16.24`) querying the C2 domain. That is not a coincidence. **Answer: yes.**

### When did the emails arrive? (Q15)

```kql
Email
| where sender contains "whiskersandwonders-hr.com"
| project timestamp, recipient
| order by timestamp asc
```

**Answer: 6/2/2025, 4:00:00 PM** (2025-06-02 16:00 UTC), delivered to Alex, Jessica and David at the same time. The sender then re-sent on 06-03 (12:00), 06-04 (15:00) and 06-05 (16:00) to Alex and Jessica, so the campaign ran in several waves.

### When did the C2 traffic start? (Q16)

```kql
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| summarize first_query=min(timestamp) by client_ip
| order by first_query asc
```

| Host | First C2 query (UTC) |
|---|---|
| `10.10.16.14` | 2025-06-02 23:52:31 |
| `10.10.16.7` | 2025-06-05 18:12:41 |
| `10.10.16.24` | 2025-06-07 19:11:52 |

From the first email at 16:00 to the first beacon at 23:52 is roughly **7.9 hours** (the platform accepted answers in the 6–8 hour range).

> **Analyst note:** that window only describes the first victim. `10.10.16.7` and `10.10.16.24` beaconed days later, so they likely clicked on a later wave of the email. In a real report, match each victim to the specific email they clicked.

### Web requests to the malicious domain (Q17)

```kql
ProxyEvents
| where domain == "update-cdn-service.xyz"
| project timestamp, src_ip
| order by timestamp asc
```

**6 requests**, two per victim machine, at the same times as the network connections listed above.

### Building the IOC list (Q18–Q20)

```kql
// Malicious domain
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct query_name

// Malicious IP
DnsEvents
| where query_name == "update-cdn-service.xyz"
| distinct tostring(resolved_ips)

// Phishing domain
Email
| where sender contains "whiskersandwonders-hr"
| distinct sender
```

| IOC | Value | Type |
|---|---|---|
| C2 domain | `update-cdn-service.xyz` | Domain |
| C2 IP | `185.174.137.42` | IPv4 |
| Phishing sender domain | `whiskersandwonders-hr.com` | Domain |
| Phishing sender address | `noreply@whiskersandwonders-hr.com` | Email |

The IP query also returned an empty `[]` row alongside `["185.174.137.42"]`. Some lookups of this domain had no resolved IP, most likely the AAAA (IPv6) queries. Worth a footnote in a formal report.

### Destination port (Q21)

```kql
NetworkFlow
| where src_ip has "185.174.137.42"
| project src_port, timestamp, dest_port
```

**Answer: 443.** This query filters on the C2 server as the *source*, so the 443 shows up as `src_port` (the server's side of the connection) and the victims' ephemeral ports (for example 52928 and 65090) appear as `dest_port`. For the victim-to-C2 direction use `dest_ip == "185.174.137.42"`, where `dest_port` is 443 (see Q29).

### Who was compromised (Q22–Q24)

```kql
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip
| join kind=inner (Employees | project ip_addr, name, username, role) on $left.client_ip == $right.ip_addr
| project name, username, role
```

| Name | Username | Role |
|---|---|---|
| David Okonkwo | `daokonkwo` | Adoption Coordinator |
| Alex Rivera | `alrivera` | Development Officer |
| Jessica Huang | `jehuang` | Adoption Coordinator |

- The compromised Development Officer is **Alex Rivera** (Q22).
- Two of the three share the role **Adoption Coordinator** (Q23).

**Why these three (Q24):** the targets were not random. Alex Rivera, a Development Officer, handles donor relationships, and the two Adoption Coordinators have access to donor and adopter data. The attacker went after people with access to the donation system, and the sanctuary's big fundraiser is five days away, which raises the stakes.

### Remediation by network layer (Q25–Q27)

| Layer | What to block | Answer |
|---|---|---|
| DNS | The domain lookup, so malware can't resolve the C2 address | `update-cdn-service.xyz` |
| Firewall | The IP directly | `185.174.137.42` |
| Proxy | The URL path pattern | `/api/v1` (beacon paths seen: `/api/v1/status` and `/api/v1/config`) |

```kql
ProxyEvents
| where domain == "update-cdn-service.xyz"
| distinct url
```

### Writing detection rules (Q28–Q30)

```kql
// Detection 1: DNS query to known C2
DnsEvents
| where query_name in ("update-cdn-service.xyz")

// Detection 2: Traffic to C2 IP
NetworkFlow
| where dest_ip == "185.174.137.42"

// Detection 3: Proxy pattern matching
ProxyEvents
| where url matches regex @"/api/v\d+/(status|config)"
| where domain endswith ".xyz"
```

| Question | Answer |
|---|---|
| Q28: table for C2 domain lookups | `DnsEvents` (8 records returned, including A and AAAA queries) |
| Q29: table for connections to the C2 IP | `NetworkFlow` (6 records, all TCP 443) |
| Q30: table for the `/api/v1/status` beaconing pattern | `ProxyEvents` (6 records, all `GET`) |

**Strengths and weaknesses of each rule:**

- **DNS and IP rules** are precise (almost no false positives) but easy for the attacker to evade by moving to new infrastructure.
- **The proxy regex** is a good hunting query but would probably be noisy as a production alert, because it matches those paths on *any* `.xyz` domain.
- **Beacon behavior** (regular check-ins from a few hosts) is the most durable signal, because it survives infrastructure changes.

### The attack chain (Q31)

```
Phishing Email  ->  Click  ->  Malware Install  ->  C2 Beacon
     |                |              |                  |
   Email         (FileCreation)  (ProcessEvents)    DnsEvents
   table                                            NetworkFlow
                                                    ProxyEvents
```

Every step leaves a trace in the logs, but the network tables only see the final step. The two middle steps (click and malware install) live in `FileCreationEvents` and `ProcessEvents`, which this module doesn't query. That is the gap to close in a follow-up.

### Final timeline summary (Q32)

```kql
DnsEvents
| where query_name has "update-cdn-service.xyz"
| summarize
    first_beacon = min(timestamp),
    last_beacon = max(timestamp),
    total_queries = count()
  by client_ip
```

| Host | First beacon (UTC) | Last beacon (UTC) | DNS queries |
|---|---|---|---|
| `10.10.16.14` | 2025-06-02 23:52:31 | 2025-06-03 09:13:40 | 6 |
| `10.10.16.7` | 2025-06-05 18:12:41 | 2025-06-05 18:39:42 | 3 |
| `10.10.16.24` | 2025-06-07 19:11:52 | 2025-06-07 19:54:54 | 3 |

Across all hosts the C2 was active from 06-02 23:52 to 06-07 19:54, about **4.8 days** (the platform accepted 3–5 days).

**Attack summary:**

- **Initial access:** phishing via `whiskersandwonders-hr.com`
- **Targets:** 3 employees with donation system access
- **C2 domain:** `update-cdn-service.xyz`
- **C2 IP:** `185.174.137.42`
- **Port:** 443 (HTTPS, blending with normal traffic)
- **Duration:** about 4.8 days active
- **Proxy IOCs:** `/api/v1/status`, `/api/v1/config`

**Recommended actions:**

1. Block the C2 domain at DNS
2. Block the C2 IP at the firewall
3. Block the URL patterns at the proxy
4. Isolate the compromised hosts
5. Reset credentials for the affected users

---

## Full timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2025-06-02 16:00 | First lookalike HR phishing email, sent to Alex, Jessica and David | `Email` |
| 2025-06-02 23:52:31 | `10.10.16.14` resolves `update-cdn-service.xyz` (about 7.9 hours after the email) | `DnsEvents` |
| 2025-06-02 23:52:35 | First TCP 443 connection to `185.174.137.42`; first `GET /api/v1/status` (404) | `NetworkFlow`, `ProxyEvents` |
| 2025-06-03 09:13:40 | Last beacon from `10.10.16.14` | `DnsEvents` |
| 2025-06-03 to 06-05 | Further phishing waves to Alex and Jessica | `Email` |
| 2025-06-05 18:12:41 | `10.10.16.7` begins beaconing (3 queries, last at 18:39) | `DnsEvents`, `NetworkFlow` |
| 2025-06-07 19:11:52 | `10.10.16.24` begins beaconing (3 queries, last at 19:54) | `DnsEvents`, `NetworkFlow` |

---

## Lessons

- **One action, many logs.** A single web request shows up in `DnsEvents`, `NetworkFlow` and `ProxyEvents`. Correlate all three.
- **Start from the indicator.** Jamie's IP led to the domain (`DnsEvents`), then to the hosts, the connections and the URL pattern.
- **Encrypted traffic still leaves evidence.** Because the proxy inspects SSL, the full URL path (`/api/v1/status`) exposes the C2 pattern even over 443.
- **`take 1` is not a filter.** The `docs.google.com` lookup returned a row from `10.10.16.35`, while the rest of the module follows `10.10.16.14`. Pin the host with `where src_ip == ...` before reading a result.
- **Check which table holds the data.** `DeviceInfo` has `ip_address`; `DnsEvents` uses `client_ip`; `NetworkFlow` uses `src_ip` and `dest_ip`; `Employees` uses `ip_addr`.
- **Mind the direction of a flow.** Filtering `NetworkFlow` on `src_ip` versus `dest_ip` flips which side's port you see.
- **Don't treat the first victim as the whole story.** Each host has its own timeline, so measure email-to-beacon time per host.

## Open points to verify

- The DNS server in `NetworkFlow` and `DnsEvents` shows as `10.1.1.1`, while `DeviceInfo` lists `DNS-Server` at `10.10.1.7`. Check whether these are two different resolvers.
- The Q22 join confirms the three compromised hosts belong to Alex, Jessica and David as a group, but the projected output doesn't include `client_ip`, so the one-to-one mapping of each IP to a person is not yet confirmed. Add `client_ip` to the projection to check.
- Match each victim to the specific email wave they clicked, and check `FileCreationEvents` and `ProcessEvents` for the click and malware install steps.
