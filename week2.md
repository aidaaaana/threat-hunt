# Week 2: Data Collection Process

## 1. Overview & Theoretical Framework
Data collection is the foundation of Cyber Threat Intelligence (CTI) and physical security auditing. This phase focuses on gathering telemetry, threat data, and reconnaissance metadata from diverse sources.

### OSINT vs. Closed Source Data
* **Open Source Intelligence (OSINT):** Publicly available data (e.g., Shodan, Censys, VirusTotal, Maltego, Intelligence X, public code repositories, social media exposure). High volume, highly accessible, but requires normalization and verification.
* **Closed Source / Internal Data:** Proprietary threat feeds, internal logs (SIEM, ACS/СКУД, EDR), commercial threat intelligence feeds (e.g., Recorded Future, CrowdStrike). High precision, directly relevant to the organization's asset surface.

---

## 2. OSINT Tools & Collection Methodology
Based on *Michael Bazzell — Open Source Intelligence Techniques*:

1. **Shodan & Censys:** Passive scanning for exposed web servers, open ports, and SSL/TLS certificates.
2. **VirusTotal:** Analyzing file hashes, domain reputations, and URL indicators.
3. **Maltego:** Graph-based link analysis and entity mapping (mapping IP addresses, DNS names, MX records, and WHOIS emails to construct infrastructure topographies).
4. **Intelligence X:** Historical breach database searches for domain exposures, subdomains, and leaked metadata.

---

## 3. Real-World Case Studies

## 3. Case Study A - Infrastructure Exposure: `websfm.kz`

### 3.1 Raw findings (IntelX, screenshots captured this week)

<img width="1280" height="526" alt="image" src="https://github.com/user-attachments/assets/093253f5-1f88-485c-8a3e-b5984abaf996" />
<img width="1280" height="526" alt="image" src="https://github.com/user-attachments/assets/d1502229-edfc-4c37-bd5a-a59a2d4eaedf" />



A domain search for `websfm.kz` in IntelX returned:

- **14 archived website HTML snapshots**, **1 domain record**, **1 CSV file**, **1 text file**.
- Snapshot date range: **2023-06-14 → 2026-02-13**, meaning the site's historical footprint has been crawled/archived for close to 3 years.
- Under the `websfm.kz` node, IntelX's path tree shows sub-paths named `fatf` and `terrorism/1`, `terrorism/3`, `terrorism/4`, each indexed **2025-12-09 → 2026-03-10**. The naming is notable on its own: page paths referencing "fatf" (Financial Action Task Force) and "terrorism" suggest the site hosts or hosted compliance/AML-related content - which raises the stakes of any leak, since it implies the domain is tied to financial-crime-adjacent reporting, not just a generic business site.
- The **CSV hit** comes from a much larger breach compilation - `domains-detailed_20250207_20.csv`, and the visible fragment is only **"Part 118 of 257"**, meaning this single leaked file alone contains at least 257 parts of bulk Kazakhstani domain records. Sample rows visible in the same part (not `websfm.kz` itself, but domains bundled in the same dump) show the consistent record shape: `domain; nameservers; IP; country-code; webserver; contact-email; phone`. This confirms that whatever leaked, leaked in bulk and in a structured, easily-parseable format - which lowers the effort for an attacker to pivot from one victim domain to hundreds of others in the same file.
- The **text-file hit** is from an even larger compilation, **"154 million DNS TXT records"**, dated 2025-01-08. The visible fragment shows other domains' SPF/DKIM/`google-site-verification` TXT records rather than `websfm.kz`'s own - but it establishes that `websfm.kz`'s SPF/verification records are very likely present somewhere in that same 154-million-record dataset, since it's indexed as a hit for that domain.

### 3.2 Analysis

- No customer database or credentials for `websfm.kz` itself surfaced in these three hits - so we are **not** looking at a direct data breach of the site's backend.
- What *is* confirmed is that the domain's **technical fingerprint** (hosting history, DNS configuration, and possibly SPF/mail-auth records) has been swept into large, already-circulating Kazakhstani-domain breach compilations, and that the site has a multi-year public crawl history including compliance-themed subpages.
- From a threat-hunting standpoint, this is a **reconnaissance-enablement** finding, not a breach: an attacker doesn't need to break in - they can pull `websfm.kz`'s DNS/IP/mail-auth posture straight out of a public leak index, then use it to plan spoofing (if SPF is missing/misconfigured) or targeted phishing against whoever manages the "fatf/terrorism" compliance pages.
- **Next collection step:** run the specific IP(s) tied to `websfm.kz` (once isolated from the full CSV, not just the sampled part) through Shodan for open services and through VirusTotal for reputation flags, to see whether the exposure has already been weaponized.

---

## 4. Case Study B - Supply-Chain Compromise: Nx Console / GitHub

### 4.1 Verified timeline (cross-checked against public incident reporting)

Open-source incident write-ups on this breach are broadly consistent on the following chain of events:

- **March 2026:** A threat actor tracked as **TeamPCP** (also referenced as UNC6780) began a credential-harvesting campaign by abusing mutable GitHub Actions version tags in an unrelated scanner tool, eventually compromising CI/CD pipelines at scale.
- **May 11, 2026:** That access chain led to a supply-chain compromise of the **TanStack** npm ecosystem - malicious versions were published across dozens of `@tanstack/*` packages. During that incident a routine pnpm install of a malicious TanStack package exfiltrated an Nx contributor's GitHub CLI OAuth token.
- **May 18, 2026, ~03:18 UTC:** Using that stolen token, the attacker pushed a malicious orphan commit into the official `nrwl/nx` GitHub repository.
- **May 18, 2026, ~12:30–12:48 UTC:** A trojanized release, **Nx Console v18.95.0** (VS Code extension, 2.2M+ installs), went live on the VS Code Marketplace. The malicious extension did not require any user action to install - VS Code's auto-update mechanism pushed the backdoored release to existing users automatically, which is what made an exposure window as short as roughly 11-18 minutes still high-impact.
- **During the exposure window:** any workspace opened with the malicious version installed triggered a payload that silently fetched and executed an obfuscated payload hidden inside the official nrwl/nx repository, which then harvested tokens and secrets from GitHub, npm, AWS, HashiCorp Vault, Kubernetes and 1Password and exfiltrated them over multiple channels.
- **May 18–19, 2026:** A GitHub employee's device was compromised this way while the extension was live, giving the attacker a foothold inside GitHub's own environment.
- **May 19, 2026:** GitHub publicly disclosed that roughly 3,800 of its internal source-code repositories were exfiltrated as a result. Customer-facing data was not reported as affected.
- **Attribution / tracking IDs:** the campaign is attributed to **TeamPCP**; the Nx Console compromise has an advisory reference (**GHSA-c9j4-9m59-847w**) and the earlier TanStack compromise is tracked separately (**GHSA-g7cv-rxg3-hmpx**).

### 4.2 Why this matters for an insider-threat / trusted-access project

This case is a textbook example of **trust-chain abuse**: the attacker never touched GitHub's perimeter directly. They abused (1) a legitimate developer's stolen credential, (2) a legitimate, auto-updating distribution channel (VS Code Marketplace), and (3) a legitimate employee's routine action (opening a workspace). Each step individually looks like "trusted access" - which is exactly the pattern our project is built to detect (see the badge/ACS "impossible travel" and "offboarding failure" logic from Week 3 - the same *behavioral-anomaly* mindset applies to token/extension misuse, just in the software supply chain instead of a physical building).

---

## 4. Data Source Mapping

| Data Source | Type | What It Captures | Analytical Value |
| :--- | :--- | :--- | :--- |
| **Badge / ACS (СКУД) Logs** | Internal / Physical | Entry/exit timestamps, door IDs, badge numbers, employee IDs | Tailgating detection, impossible travel, former employee access. |
| **CCTV Metadata** | Internal / Physical | Camera ID, timestamp, motion detection zone, access event cross-ref | Visual verification of badge events without raw video analysis. |
| **Maltego Entities** | External / OSINT | Domain nodes, DNS aliases, IP transforms, WHOIS owner emails | Graph-based visualization of threat actor infrastructure. |
| **VS Code / Extension Logs** | Internal / Endpoint | Extension ID, process execution trees, workspace load events | Detecting malicious extensions, supply-chain payload execution. |
| **GitHub Audit / PAT Logs** | Hybrid / SaaS | Token creation, API requests, IP addresses, repo clone actions | Identifying token abuse, bulk repository cloning, anomalous API activity. |
| **Intelligence X / Shodan** | External / OSINT | Leaked domain records, IP bindings, DNS records, public exposures | Uncovering attack surface exposure and credential leaks. |

---

## 5. Recommended Reading
* Michael Bazzell, *Open Source Intelligence Techniques*
* Pellera Technologies, *Physical Security Risks Exposed*
* StepSecurity & Snyk Security Advisories on VS Code Marketplace Supply Chain Attacks

## 6. Sources

- StepSecurity, "Nx Console VS Code Extension Compromised" (May 18, 2026)
- Cloud Security Alliance, "VSCode Marketplace Poisoning: How 18 Minutes Breached GitHub" (May 25, 2026)
- Rankiteo, incident summary on GitHub/npm/Microsoft/Nx compromise (May 2026)
- IntelX search results for `websfm.kz` (captured this week, screenshots on file)
