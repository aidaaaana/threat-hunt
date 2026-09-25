# Week 1: Threat Intelligence Fundamentals & Threat Classification

## 1. Overview
Cyber Threat Intelligence (CTI) is the process of collecting, analyzing, and organizing data about cyber threats, malicious actors, and attack vectors to protect organizational assets and reduce risk.

---

## 2. Classification of Threats & Threat Actors

To properly analyze threat intelligence, threats are categorized based on **Intent**, **Capability**, and **TTPs (Tactics, Techniques, and Procedures)**.

### Threat Actor Categories
* **Nation-State / Advanced Persistent Threats (APTs):** High capability, high resources, motivated by espionage, geopolitical power, or strategic disruption.
* **Cybercriminals (Financially Motivated):** Moderate to high capability, motivated by financial gain (Ransomware-as-a-Service, extortion, credential theft).
* **Insider Threats:** Malicious or negligent employees, contractors, or partners with legitimate access to organizational assets, physical premises, or code repositories.
* **Hacktivists:** Low to moderate capability, motivated by political, social, or ideological causes.

### Threat Classification Matrix

| Threat Category | Motivation | Common TTPs / Attack Vectors | Primary Target / Impact |
| :--- | :--- | :--- | :--- |
| **Supply-Chain Compromise** | Widespread Access / Financial / Espionage | Malicious package updates, compromised developer tokens, malicious IDE extensions | Source code theft, widespread enterprise infection |
| **Physical Insider Threat** | Data Theft / Unauthorized Entry | Badge cloning, social engineering, tailgating into secure zones | Physical access to server rooms, rogue hardware deployment |
| **Infrastructure Exposure** | Passive Reconnaissance | Open ports, exposed DNS TXT records, leaked CSV/DB metadata | Attack surface mapping, targeted spear-phishing |

---

## 3. Core CTI Frameworks & Sources

1. **MITRE ATT&CK Framework:** A globally accessible knowledge base of adversary tactics and techniques based on real-world observations.
2. **The Threat Intelligence Handbook (Recorded Future):** Framework for operationalizing CTI across Strategic, Tactical, Operational, and Technical levels.
3. **SANS CTI Summit Insights:** Best practices for threat hunting, adversary emulation, and indicator sharing.
4. **ENISA Threat Landscape Report:** Annual reporting on top cyber threats, trends, and risk vectors across critical infrastructure.

---

## 4. Recommended Reading
* *The Threat Intelligence Handbook* (Recorded Future)
* *SANS CTI Summit Research Papers*
* *ENISA Threat Landscape Report*
* *MITRE ATT&CK Matrix for Enterprise*
