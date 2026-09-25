# Week 3: Data Processing and Exploitation

## 1. Overview
Once raw threat telemetry and OSINT data are collected, they must be processed, normalized, enriched, and ingested into analytics platforms (such as MISP and Elastic Stack) to identify anomalies and indicators of compromise (IOCs).

---

## 2. Adapting MISP for Heterogeneous Threat Intelligence
MISP (Malware Information Sharing Platform) is traditionally used for network and file IOCs. In this project, MISP is expanded to handle physical security events, supply-chain alerts, and OSINT infrastructure leaks[cite: 3].

### Event Structure & Custom Indicators
* **Event 1: Physical Access Anomaly (ACS/СКУД)**[cite: 3]
  * Custom Attributes: `badge_id`, `access_zone`, `employee_hr_status`, `door_id`[cite: 3].
* **Event 2: VS Code Supply-Chain Compromise**
  * Attributes: `extension_id` (`nx-console`), `sha256_hash` of `main.js`, `c2_domain`, `stolen_key_type`.
* **Event 3: Infrastructure Leak Exposure**[cite: 4]
  * Attributes: `domain` (`websfm.kz`), `ip_address` (`213.130.74.24`), `nameserver` (`ns1.ps.kz`)[cite: 4, 5].

### Indicator Reference Table

| Indicator Type | Indicator Value / Pattern | Threat / Anomaly Suggested |
| :--- | :--- | :--- |
| **Behavioral (Physical)** | Badge-in with no corresponding badge-out[cite: 3] | Tailgating or badge sharing[cite: 2, 3]. |
| **Behavioral (Physical)** | Badge entry at two geographically distant doors in <5 mins[cite: 3] | Cloned RFID badge ("Impossible Travel" for badges)[cite: 3]. |
| **Behavioral (Physical)** | Access attempt after employee termination date in HR[cite: 3] | Offboarding failure / Unauthorized physical access[cite: 3]. |
| **Supply-Chain** | Obfuscated JS code block (~2.7–3KB) in extension `main.js` | Malicious VS Code extension payload execution. |
| **Supply-Chain** | `git clone` bulk requests via Personal Access Tokens (PAT) | Automated repository exfiltration using stolen keys. |
| **OSINT / Infrastructure** | Exposed SPF / TXT records with wildcard includes (`websfm.kz`)[cite: 4] | Email spoofing vulnerability / Domain hijacking vector[cite: 4]. |

---

## 3. Data Processing Pipeline (Normalization & Filtering)

1. **Timestamp Normalization:** Convert all logs (ACS doors, GitHub PAT access, VS Code execution logs) to standard UTC/ISO-8601 timestamps[cite: 3].
2. **Identity Cross-Referencing:** Map `Badge_ID` $\rightarrow$ `Employee_ID` $\rightarrow$ `HR_Status` $\rightarrow$ `GitHub_User`[cite: 3].
3. **Baseline Filtering:** Filter out standard employee shift patterns, expected CI/CD IP ranges, and known developer machines to isolate anomalies[cite: 3].

---

## 4. Detection Rules & Correlation Logic

### A. Elastic KQL Query: Detecting VS Code Suspicious Child Process Execution
```kql
process.parent.name: "code.exe" or process.parent.name: "code" 
and process.name: ("bash", "sh", "powershell.exe", "cmd.exe", "curl")
and process.args: ("*~/.ssh*", "*~/.config/gh*", "*credentials*")
