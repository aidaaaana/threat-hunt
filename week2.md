# Week 2: Data Collection Process - OSINT Research

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)
**Project topic:** Insider threat via trusted access - covered across two tracks in this project: **physical** (badge/ACS misuse) and **digital** (software supply-chain / developer-tooling misuse). Both tracks share the same underlying pattern - a legitimate, trusted credential or channel being abused - just in different environments, and both are carried through Weeks 2-4.
**Deliverables covered:** OSINT data collection (Shodan/VirusTotal/Maltego-class tooling), data source mapping for analysis

---

## 1. Objective

This week's deliverable moves from theory to practice. We ran real OSINT reconnaissance and cross-checked public reporting for three case studies spanning both project tracks:

- **Track: Physical** - badge cloning via OSINT-sourced photos (Case Study 1)
- **Track: Digital** - the Nx Console/GitHub supply-chain breach (Case Study 2) and the `websfm.kz` infrastructure exposure (Case Study 3)

---

## 2. Case Study 1 - Physical: Badge Cloning via Social Media OSINT

- **Scenario:** Badge cloning and physical unauthorized access enabled entirely through publicly available OSINT.
- **Attack vector:** Threat actors collected high-resolution photos of employee ID badges posted on LinkedIn and Facebook. Combined with building blueprints and interior photos shared by partners/contractors, this let them identify the badge's RFID technology and produce a working replica using a long-range RFID reader/cloner.
- **Impact:** Physical entry into restricted facility zones without triggering perimeter alarms - the clone reads as a legitimate credential to the access-control system.
- **Reference:** Pellera Technologies, *"Physical Security Risks Exposed: Real-World Penetration Testing Lessons."*
- **Why this matters for the project:** this is the purest example of the physical track - no system was "hacked"; a legitimate credential's physical signature was harvested from public data and reproduced. It's the direct counterpart to the token-theft pattern in Case Study 2 below.

---

## 3. Case Study 2 - Digital: Supply-Chain Compromise (Nx Console / GitHub)

### 3.1 Verified timeline (cross-checked against public incident reporting)

- **March 2026:** A threat actor tracked as **TeamPCP** (also referenced as UNC6780) began a credential-harvesting campaign by abusing mutable GitHub Actions version tags in an unrelated scanner tool, eventually compromising CI/CD pipelines at scale.
- **May 11, 2026:** That access chain led to a supply-chain compromise of the **TanStack** npm ecosystem - malicious versions were published across dozens of `@tanstack/*` packages. During that incident, a routine `pnpm install` of a poisoned TanStack package exfiltrated an Nx contributor's GitHub CLI OAuth token.
- **May 18, 2026, ~03:18 UTC:** Using that stolen token, the attacker pushed a malicious orphan commit into the official `nrwl/nx` GitHub repository.
- **May 18, 2026, ~12:30–12:48 UTC:** A trojanized release, **Nx Console v18.95.0** (VS Code extension, 2.2M+ installs), went live on the VS Code Marketplace. The malicious version didn't require manual installation - VS Code's auto-update mechanism pushed it to existing users automatically, which is why an exposure window as short as roughly 11–18 minutes was still high-impact.
- **During the exposure window:** any workspace opened with the malicious version installed triggered a payload that fetched and ran obfuscated code hidden inside the official `nrwl/nx` repository, which then harvested tokens and secrets from GitHub, npm, AWS, HashiCorp Vault, Kubernetes, and 1Password, exfiltrating them over multiple channels.
- **May 18–19, 2026:** A GitHub employee's device was compromised this way while the extension was live, giving the attacker a foothold inside GitHub's own environment.
- **May 19, 2026:** GitHub publicly disclosed that roughly 3,800 of its internal source-code repositories had been exfiltrated. Customer-facing data was not reported as affected.
- **Attribution / tracking IDs:** attributed to **TeamPCP**; advisory references **GHSA-c9j4-9m59-847w** (Nx Console) and **GHSA-g7cv-rxg3-hmpx** (TanStack).

<img width="1200" height="600" alt="week3_nx_timeline" src="https://github.com/user-attachments/assets/994febe6-700e-4b9e-ac6b-0805a0cedb28" />


### 3.2 Why this parallels Case Study 1

Neither attacker "broke in" in the traditional sense. Case Study 1 harvested a badge's *physical* signature from public photos; Case Study 2 harvested a developer's *digital* token from a poisoned dependency. Both then rode a **legitimate, trusted channel** - an access-control reader in one case, an auto-updating Marketplace extension in the other - straight past the perimeter. This is the common thread the project tracks across both domains.

---

## 4. Case Study 3 - Digital: Infrastructure Exposure (`websfm.kz`)

### 4.1 Raw findings (IntelX, screenshots captured this week)

A domain search for `websfm.kz` in IntelX returned:

- **14 archived website HTML snapshots**, **1 domain record**, **1 CSV file**, **1 text file**.
- Snapshot date range: **2023-06-14 → 2026-02-13**.
- Sub-paths `fatf` and `terrorism/1`, `terrorism/3`, `terrorism/4`, indexed **2025-12-09 → 2026-03-10** - the naming suggests compliance/AML-related content, raising the stakes of any exposure.
- **CSV hit**: `domains-detailed_20250207_20.csv`, visible fragment **"Part 118 of 257"** - a bulk Kazakhstani-domain breach compilation with at least 257 parts, in a consistent structured format (`domain; nameservers; IP; country-code; webserver; contact-email; phone`).
- **Text-file hit**: a **154-million-record DNS TXT dataset** (dated 2025-01-08); the visible fragment shows other domains' SPF/DKIM/`google-site-verification` records, establishing that `websfm.kz`'s own records are very likely present in the same dataset.
<img width="1280" height="526" alt="image" src="https://github.com/user-attachments/assets/093253f5-1f88-485c-8a3e-b5984abaf996" />
<img width="1280" height="526" alt="image" src="https://github.com/user-attachments/assets/d1502229-edfc-4c37-bd5a-a59a2d4eaedf" />
[154 million DNSTXT records.txt [Part 2159 of 2892] - Intelligence X.pdf](https://github.com/user-attachments/files/32848340/154.million.DNSTXT.records.txt.Part.2159.of.2892.-.Intelligence.X.pdf)
[domains-detailed_20250207_domains-detailed_20250207_20.csv [Part 118 of 257] - Intelligence X.pdf](https://github.com/user-attachments/files/32848337/domains-detailed_20250207_domains-detailed_20250207_20.csv.Part.118.of.257.-.Intelligence.X.pdf)

### 4.2 Quantitative analysis of the sampled CSV rows (n=8)

The visible fragment of `domains-detailed_20250207_20.csv` (Part 118/257) contains 8 domain records alongside `websfm.kz` in the same bulk dump. We tabulated them directly:

<img width="900" height="600" alt="week2_ns_distribution" src="https://github.com/user-attachments/assets/1b48501d-2755-4f28-96e3-1c1470c16326" />


4 of the 8 sampled domains share the same nameserver provider (`ps.kz`), and 2 more share `promdns.net`. This is a concentration risk: compromising one shared DNS/hosting provider would expose multiple unrelated domains bundled in the same leak at once - not just `websfm.kz`.

<img width="900" height="600" alt="week2_country_distribution" src="https://github.com/user-attachments/assets/90337ffe-8063-4332-9b84-257170827611" />


4 of 8 records are tagged `KZ`; one each `FR`/`RU`; one field was unreadable in the source scan (`"F1"` on `crypta.kz`, likely an OCR artifact worth re-checking against the raw file); one record (`vaz-tuning.kz`) has no IP or country code at all, which is itself an anomaly worth flagging.

**Methodological note:** n=8 is one visible fragment out of 257 parts, so these proportions are a pilot sample, not representative of the full dump. A full quantitative pass requires parsing all 257 parts - flagged as a next step in §6.

### 4.3 Analysis

- No customer database or credentials for `websfm.kz` itself surfaced - this is **not** a direct backend breach.
- What's confirmed is that the domain's **technical fingerprint** (hosting history, DNS configuration, likely SPF/mail-auth records) is swept into large, already-circulating Kazakhstani-domain breach compilations, alongside a multi-year public crawl history that includes compliance-themed subpages.
- This is a **reconnaissance-enablement** finding: an attacker doesn't need to breach `websfm.kz` - they can pull its DNS/IP/mail-auth posture straight from a public leak index to plan spoofing or targeted phishing.

---

## 5. Updated Data Source Mapping

| Data Source | Type | Track | What It Captures | Analytical Value |
|---|---|---|---|---|
| Badge / ACS (СКУД) Logs | Internal / Physical | Physical | Entry/exit timestamps, door IDs, badge numbers | Tailgating, impossible travel, offboarding failure |
| CCTV Metadata | Internal / Physical | Physical | Camera ID, timestamp, motion zone | Visual cross-check of badge events |
| Social media / public imagery | External / OSINT | Physical | Badge photos, building layout leaks | Detects reconnaissance enabling badge cloning |
| IntelX (breach/leak archives) | External / OSINT | Digital | Domain snapshots, bulk DNS/WHOIS dumps, SPF/TXT records | Reconnaissance-enablement exposure for a domain |
| npm / GitHub Actions publish logs | External / SaaS | Digital | Package publish events, tag mutation, CI run metadata | Root-cause detection for supply-chain compromise |
| VS Code / Extension Marketplace logs | Internal / Endpoint | Digital | Extension version, install/update timestamp, workspace load | Detects trojanized-extension execution window |
| GitHub Audit / PAT Logs | Hybrid / SaaS | Digital | Token creation, API requests, repo clone volume | Token abuse, bulk repo cloning |

---

## 6. Next Steps (feeding into Week 3)

1. Isolate the exact IP(s)/nameservers tied specifically to `websfm.kz` from the full 257-part CSV and run them through Shodan + VirusTotal.
2. Pull the GHSA advisories (GHSA-c9j4-9m59-847w, GHSA-g7cv-rxg3-hmpx) for file hashes/commit SHAs to use as MISP IOC attributes.
3. Add "npm publish log" and "badge photo exposure" as formal rows in the Week-3 MISP event schema, so both tracks are represented at the data-modeling stage too.

---

## 7. Recommended Reading

- Michael Bazzell, *Open Source Intelligence Techniques*
- Pellera Technologies, *Physical Security Risks Exposed: Real-World Penetration Testing Lessons*
- StepSecurity / Cloud Security Alliance advisories on the May 2026 Nx Console / TanStack incident chain

## 9. Sources

- Pellera Technologies, "Physical Security Risks Exposed: Real-World Penetration Testing Lessons"
- StepSecurity, "Nx Console VS Code Extension Compromised" (May 18, 2026)
- Cloud Security Alliance, "VSCode Marketplace Poisoning: How 18 Minutes Breached GitHub" (May 25, 2026)
- Rankiteo, incident summary on GitHub/npm/Microsoft/Nx compromise (May 2026)
- IntelX search results for `websfm.kz` (captured this week, screenshots on file)
