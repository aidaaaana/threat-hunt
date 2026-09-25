# Week 3: Data Processing and Exploitation

## 1. Overview
Once raw threat telemetry and OSINT data are collected, they must be processed, normalized, enriched, and ingested into analytics platforms (such as MISP and Elastic Stack) to identify anomalies and indicators of compromise (IOCs).

---

## 2. Adapting MISP for Heterogeneous Threat Intelligence
MISP (Malware Information Sharing Platform) is traditionally used for network and file IOCs. In this project, MISP is expanded to handle physical security events, supply-chain alerts, and OSINT infrastructure leaks.

### Event Structure & Custom Indicators
* **Event 1: Physical Access Anomaly (ACS/СКУД)**
  * Custom Attributes: `badge_id`, `access_zone`, `employee_hr_status`, `door_id`.
* **Event 2: VS Code Supply-Chain Compromise**
  * Attributes: `extension_id` (`nx-console`), `sha256_hash` of `main.js`, `c2_domain`, `stolen_key_type`.
* **Event 3: Infrastructure Leak Exposure**
  * Attributes: `domain` (`websfm.kz`), `ip_address` (`213.130.74.24`), `nameserver` (`ns1.ps.kz`).

### Indicator Reference Table

| Indicator Type | Indicator Value / Pattern | Threat / Anomaly Suggested |
| :--- | :--- | :--- |
| **Behavioral (Physical)** | Badge-in with no corresponding badge-out | Tailgating or badge sharing. |
| **Behavioral (Physical)** | Badge entry at two geographically distant doors in <5 mins | Cloned RFID badge ("Impossible Travel" for badges). |
| **Behavioral (Physical)** | Access attempt after employee termination date in HR | Offboarding failure / Unauthorized physical access. |
| **Supply-Chain** | Obfuscated JS code block (~2.7–3KB) in extension `main.js` | Malicious VS Code extension payload execution. |
| **Supply-Chain** | `git clone` bulk requests via Personal Access Tokens (PAT) | Automated repository exfiltration using stolen keys. |
| **OSINT / Infrastructure** | Exposed SPF / TXT records with wildcard includes (`websfm.kz`) | Email spoofing vulnerability / Domain hijacking vector. |

---

## 3. Data Processing Pipeline (Normalization & Filtering)

1. **Timestamp Normalization:** Convert all logs (ACS doors, GitHub PAT access, VS Code execution logs) to standard UTC/ISO-8601 timestamps.
2. **Identity Cross-Referencing:** Map `Badge_ID` $\rightarrow$ `Employee_ID` $\rightarrow$ `HR_Status` $\rightarrow$ `GitHub_User`.
3. **Baseline Filtering:** Filter out standard employee shift patterns, expected CI/CD IP ranges, and known developer machines to isolate anomalies.

---

## 4. Detection Rules & Correlation Logic

### A. Corrected KQL Query (Elastic Stack)
```kql
(process.parent.name: "code.exe" or process.parent.name: "code") 
and process.name: ("bash" or "sh" or "powershell.exe" or "cmd.exe" or "curl") 
and process.args: ("*~/.ssh*" or "*~/.config/gh*" or "*credentials*")
