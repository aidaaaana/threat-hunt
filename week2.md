# Week 2: Data Collection Process

## 1. Overview & Theoretical Framework
Data collection is the foundation of Cyber Threat Intelligence (CTI) and physical security auditing. This phase focuses on gathering telemetry, threat data, and reconnaissance metadata from diverse sources.

### OSINT vs. Closed Source Data
* **Open Source Intelligence (OSINT):** Publicly available data (e.g., Shodan, Censys, VirusTotal, Intelligence X, public code repositories, social media exposure). High volume, highly accessible, but requires normalization and verification[cite: 1, 2, 4].
* **Closed Source / Internal Data:** Proprietary threat feeds, internal logs (SIEM, ACS/СКУД, EDR), commercial threat intelligence feeds (e.g., Recorded Future, CrowdStrike). High precision, directly relevant to the organization's asset surface[cite: 1, 2, 3].

---

## 2. Real-World Case Studies

### Case Study 1: Physical Security & Badge Exposure
* **Scenario:** Badge cloning and physical unauthorized access via OSINT reconnaissance[cite: 2].
* **Attack Vector:** Threat actors gathered high-resolution photos of employee ID badges posted on LinkedIn and Facebook[cite: 2]. Using building blueprints and interior photos shared by partners, they identified badge RFID technology and printed replica badges equipped with long-range RFID readers[cite: 2].
* **Impact:** Physical breach of restricted facility zones without triggering perimeter alarms[cite: 2].
* **Reference:** Pellera Technologies, *"Physical Security Risks Exposed: Real-World Penetration Testing Lessons"*[cite: 2].

### Case Study 2: Supply-Chain Compromise (TanStack -> Nx Console -> GitHub Breach)
* **Chronology (May 2026):**
  * **May 11:** Supply-chain attack targeting `TanStack` JS libraries; compromise of an Nx developer's GitHub token.
  * **May 18:** Threat actors publish malicious version `v18.95.0` of the **Nx Console** extension on the VS Code Marketplace (>2.2 million installs).
  * **May 18–19:** A GitHub engineer with the extension installed opens a workspace. Obfuscated JavaScript (~2.7–3 KB) inside `main.js` executes upon workspace initialization.
  * **Execution & Impact:** Payload collected local SSH keys, GitHub tokens, AWS credentials, and system credentials, sending them to C2. Using stolen developer keys, attackers cloned **~3,800 private GitHub repositories** before detection and removal.

### Case Study 3: Infrastructure Leak Analysis (Kaznet OSINT / Intelligence X)
* **Scenario:** Passive reconnaissance of Kaznet infrastructure via Intelligence X dumps (`websfm.kz`, `domains-detailed_20250207.csv`)[cite: 4, 5].
* **Findings:** While raw database credentials for `websfm.kz` were not publicly exposed, complete technical exposure (IP addresses: `213.130.74.24`, `185.4.181.132`; Name Servers: `ns1.ps.kz`, `hoster.kz`; Web Servers: Nginx versions) was leaked in 2025–2026 Kaznet breach dumps[cite: 4, 5].
* **Impact:** Reduces attacker effort for targeted spear-phishing, infrastructure spoofing, and perimeter exploitation[cite: 4, 5].

---

## 3. Data Source Mapping

| Data Source | Type | What It Captures | Analytical Value |
| :--- | :--- | :--- | :--- |
| **Badge / ACS (СКУД) Logs** | Internal / Physical | Entry/exit timestamps, door IDs, badge numbers, employee IDs[cite: 2, 3] | Tailgating detection, impossible travel, former employee access. |
| **CCTV Metadata** | Internal / Physical | Camera ID, timestamp, motion detection zone, access event cross-ref[cite: 2] | Visual verification of badge events without raw video analysis[cite: 2]. |
| **VS Code / Extension Logs** | Internal / Endpoint | Extension ID, process execution trees, workspace load events | Detecting malicious extensions, supply-chain payload execution. |
| **GitHub Audit / PAT Logs** | Hybrid / SaaS | Token creation, API requests, IP addresses, repo clone actions | Identifying token abuse, bulk repository cloning, anomalous API activity. |
| **Intelligence X / Shodan** | External / OSINT | Leaked domain records, IP bindings, DNS records, public exposures[cite: 1, 4, 5] | Uncovering attack surface exposure and credential leak leaks[cite: 4, 5]. |

---

## 4. OSINT Collection Methodology
Based on *Michael Bazzell — Open Source Intelligence Techniques*[cite: 1]:
1. **Target Identification:** Mapping domains (`websfm.kz`), GitHub organizations, and employee exposure[cite: 2, 4].
2. **Passive Footprinting:** Querying Intelligence X, VirusTotal, and Shodan without sending packets directly to the victim[cite: 1, 4].
3. **Data Structuring:** Transforming unstructured CSV/TXT leaks into searchable mappings[cite: 1, 4, 5].

---

## 5. Recommended Reading
* Michael Bazzell, *Open Source Intelligence Techniques*[cite: 1].
* Pellera Technologies, *Physical Security Risks Exposed*[cite: 2].
* StepSecurity & Snyk Security Advisories on VS Code Marketplace Supply Chain Attacks.
