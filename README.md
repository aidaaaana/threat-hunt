Threat Intelligence Project

About the Project

This repository contains our work for the Cyber Threat Intelligence course.

The main idea of the project is to understand how information about cyber threats can be collected and analyzed. We look at different types of threats and use OSINT tools to collect public information about infrastructure.

During the project we work with several areas:

* Cyber Threat Intelligence
* OSINT
* threat actors
* physical insider threats
* supply chain attacks
* infrastructure exposure
* threat detection

⸻

Week 1 — Threat Intelligence Fundamentals

In Week 1 we studied the basic concepts of Cyber Threat Intelligence.

We looked at different threat actors:

* Nation-State and APT groups
* Cybercriminals
* Insider Threats
* Hacktivists

We also learned how threats can be classified by their intent, capability and TTPs.

The main threat examples in our work are:

* Supply Chain Compromise
* Physical Insider Threat
* Infrastructure Exposure

We also reviewed several CTI sources and frameworks such as MITRE ATT&CK, ENISA, SANS and Recorded Future.

⸻

Week 2 — Data Collection

Week 2 focuses on collecting information.

We work with two main types of data.

OSINT

OSINT is information that is publicly available.

For this part we use tools such as:

* Shodan
* Censys
* VirusTotal
* Maltego
* Intelligence X

These tools can help us find information about domains, IP addresses, DNS records, open services and other infrastructure data.

Internal Data

Internal data comes from systems inside an organization.

Examples include:

* SIEM logs
* EDR logs
* badge access logs
* GitHub audit logs
* endpoint logs

OSINT gives us information about what can be seen from outside. Internal logs help us understand what is happening inside the organization.

⸻

Case Studies

We also looked at several security cases.

Physical Security

Public photos and social media posts can sometimes reveal information about employee badges, office locations or physical security systems.

This information can be useful for reconnaissance and social engineering.

Supply Chain Attack

We studied an example involving a malicious VS Code extension.

This case shows how attackers can compromise a trusted developer tool and then use it to steal credentials or access repositories.

Infrastructure Exposure

We also performed passive OSINT research on websfm.kz.

The purpose was to see what technical information can be found from public sources without attacking the target.

We looked at information such as:

* IP addresses
* DNS records
* name servers
* hosting information
* server technologies

This information helps us understand the external attack surface.

⸻

Week 3 — Data Processing

After collecting data we need to process it.

The main steps are:

1. Normalize the data
2. Remove unnecessary or duplicate information
3. Verify important findings
4. Connect information from different sources
5. Look for suspicious activity

For example we can connect:

Badge ID
   ↓
Employee ID
   ↓
User Account
   ↓
System Activity

This can help us understand whether several security events are related.

⸻

Tools

During the project we use or study:

* MITRE ATT&CK
* Shodan
* Censys
* VirusTotal
* Maltego
* Intelligence X
* MISP
* Elastic Stack
* KQL
* GitHub logs

⸻

Project Workflow

Threat Identification
        ↓
Data Collection
        ↓
Data Verification
        ↓
Data Processing
        ↓
Correlation
        ↓
Threat Analysis

⸻

Main Idea

The main idea of this project is simple.

One security source usually does not show the full situation.

OSINT can show what is publicly visible. Internal logs can show what actually happens inside the organization. When we combine information from different sources we can understand threats better and make more reliable conclusions.
