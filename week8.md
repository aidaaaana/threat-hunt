# Week 8: Creating a Plan to Emulate an Attacker's Action

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)
**Project topic:** Insider threat via trusted access: physical and digital tracks.
**Syllabus tasks:** "Develop a simple adversary emulation plan (initial access → persistence → data exfiltration)" and "Document the plan using ATT&CK techniques." Sources: MITRE Engenuity, Red Teaming resources; recommended reading: MITRE CALDERA documentation.

---

## 0. Summary

**What this is.** A plan to emulate, step by step, two kinds of insider-style attacker against the detections we built in Weeks 3–5, so that we can later measure what we catch and what we miss. The plan is **not executed yet** (execution is planned for Week 9); every "expected" result below is a prediction.

| | Variant A: compromised developer ("Insider-X") | Variant B: malicious employee ("Insider-Y") | Physical track |
|---|---|---|---|
| Who | External attacker using a developer's trusted access | A real employee abusing access they already have | Attacker with a cloned badge |
| Initial access | T1195.002 trusted IDE extension update | None needed: access already exists (T1078) | Cloned badge (no ATT&CK ID) |
| Persistence | T1176.002 extension stays installed | Not needed: legitimate access is the persistence | Badge stays valid until revoked |
| Exfiltration | T1567 web service | T1567.002 cloud storage / T1052.001 USB | Removable media (tabletop) |

**Expected result of the plan (prediction, Section 7).** Of the six emulated steps in Variant A, our existing detections address two (credential-file access from the IDE), partly address one (exfiltration), and miss three (malicious extension, extension persistence, data staging). Variant B is not covered by any of our hunts.

**Top recommendations (Section 8).**
1. Control IDE extensions on developer machines (allowlist, pinned versions, update review).
2. Add file-access telemetry and decoy ("canary") credential files for credential stores.
3. Tighten GitHub tokens and alert on bulk repository cloning.

---

## 1. Purpose and scenario

An adversary emulation plan describes how a chosen adversary would act, which ATT&CK techniques each step uses, what traces it should leave, and how we will know whether our detections caught it. It turns the detections of Weeks 3–5 from "rules we wrote" into "rules we can test against a defined attack".

Our project topic is insider threat via trusted access, so the plan covers both ways an insider's access becomes dangerous:

- **Variant A, compromised insider:** an attacker takes over a developer's trusted tools and credentials. The system sees a known user and a known tool, so identity-based rules stay silent and only behavior can reveal it. This is built from our own cases: the Nx Console / GitHub supply-chain breach (Week 2), hunt H2 (Week 5) and the Week 3 KQL rule.
- **Variant B, malicious insider:** an employee uses legitimate access for data theft. MITRE's insider-threat research (CTID Insider Threat TTP Knowledge Base, CrowdStrike summary, see Section 13) reports that real cases typically use low-tech techniques and existing access or valid accounts, stage data before exfiltration, and use cloud storage, email or removable media to move it out.
- **Physical track:** the badge-cloning scenario from Weeks 1–3, emulated as a tabletop and with synthetic logs.

## 2. Scope, safety and rules of engagement

This is a plan. Anything executed later (Week 9) follows these rules:

| Rule | Detail |
|---|---|
| Where | Only on the team's own laptops or a lab VM. No university, company or third-party systems. |
| Data | Only **canary data**: fake files containing `LAB-CANARY-NOT-A-SECRET`. No real SSH keys, tokens or cloud credentials are read, copied or sent. |
| Network | The "exfiltration" target is `127.0.0.1` (a local listener). Nothing leaves the machine. No real cloud account or USB device is used. |
| Code | No malware, no real extension is published to any marketplace, no real extension folder is modified. The "extension" is an empty dummy folder. |
| Physical | Badge cloning, tailgating and entering buildings are **not** performed. The physical track uses a tabletop scenario and synthetic access-control logs only. |
| Cleanup | Every Caldera ability has a cleanup step that deletes the `lab_emulation` folder. |
| Authorization | The team owns the lab machines and approves each run. |

## 3. Adversary profiles

| Attribute | Insider-X (Variant A) | Insider-Y (Variant B) |
|---|---|---|
| Type | Compromised insider (external actor) | Malicious insider (employee) |
| Goal | Steal source code and credentials | Take source code or data for personal gain or grievance |
| Access at start | Developer workstation with VS Code; GitHub token stored by the GitHub CLI | The employee's own accounts and permissions |
| Skill / tooling | Low to medium; built-in tools (shell, `curl`) | Low; normal tools such as `git`, archive tools, cloud upload, USB |
| Constraint | Must stay unnoticed; uses a trusted tool (the IDE) as the parent of every action | Must look like normal work |
| Real-world basis | Nx Console supply-chain case (Week 2); MITRE insider research | MITRE insider research (trends in Section 1) |

## 4. Variant A: compromised developer (digital track)

The three syllabus phases are the core of the plan. Supporting steps (execution, credential access, staging) sit inside the phase they belong to.

### Phase 1: Initial access

| Step | Tactic | ATT&CK technique | Emulated procedure | Expected evidence |
|---|---|---|---|---|
| 1.1 | Initial Access | **T1195.002** Supply Chain Compromise: Compromise Software Supply Chain | A trusted IDE extension is replaced by a malicious update delivered through the normal marketplace channel (the Nx Console pattern). **Emulated as "assumed breach":** we start after this point and manually place a dummy extension folder in the lab. No marketplace is involved. | Extension installed or updated on the developer host; version or publisher change |
| 1.2 | Initial Access | **T1078** Valid Accounts (alternative entry) | The attacker uses a stolen developer token instead of an extension. Documented, **not emulated**. | Token or login use from a new location or client |

### Phase 2: Persistence and foothold

| Step | Tactic | ATT&CK technique | Emulated procedure | Expected evidence |
|---|---|---|---|---|
| 2.1 | Persistence | **T1176.002** Software Extensions: IDE Extensions | The extension stays installed and loads each time the IDE starts, so access survives reboots. Emulated by a dummy folder `lab.fake-extension-0.0.1` with a `package.json` (Caldera ability 01). | New folder or files under an IDE plugin path; abnormal outbound connections from the IDE |
| 2.2 | Execution | **T1059.003** Windows Command Shell / **T1059.004** Unix Shell | The IDE process starts a shell or `curl`. Emulated by manual commands typed in the VS Code integrated terminal, so the parent process is `Code.exe` / `code`. | Process creation with parent = IDE |
| 2.3 | Credential Access | **T1552.001** Credentials In Files; **T1552.004** Private Keys; **T1528** Steal Application Access Token | The shell reads `.ssh` keys, GitHub CLI `hosts.yml` and cloud `credentials`. Emulated with fake canary copies (Caldera ability 02). | Command line contains `.ssh`, `hosts.yml` or `credentials` (hunt H2) |

### Phase 3: Collection and exfiltration

| Step | Tactic | ATT&CK technique | Emulated procedure | Expected evidence |
|---|---|---|---|---|
| 3.1 | Collection | **T1213.003** Data from Information Repositories: Code Repositories | The attacker clones or reads repositories the developer can access. Documented, **not emulated** (would need real repositories). | Unusual volume of `git clone` or API reads for one user |
| 3.2 | Collection | **T1074.001** Data Staged: Local Data Staging | Canary files are copied into one staging folder (Caldera ability 03). | File creation or copy burst in a new folder |
| 3.3 | Exfiltration | **T1567** Exfiltration Over Web Service (a real attacker could use T1567.001 Exfiltration to Code Repository) | The staged canary file is POSTed with `curl` to `127.0.0.1:8000` (Caldera ability 04). | Outbound request from a process whose parent is the IDE |

Order of execution matches the Caldera adversary profile `Insider-X` (abilities 01 → 04). Step 1.1, step 2.2 (parent = IDE) and the real-data steps (1.2, 3.1) are manual or documented only, because a Caldera agent cannot make `Code.exe` the parent of a command.

## 5. Variant B: malicious employee

An insider does not need initial access or persistence: the access they already have is both. This changes the shape of the plan, and it is also why this variant is harder to detect, because every action is done with legitimate rights.

| Step | Tactic | ATT&CK technique | Emulated procedure | Expected evidence |
|---|---|---|---|---|
| B1 | (Access already exists) | **T1078** Valid Accounts | The employee uses their own account within their permissions. No action to emulate. | Nothing unusual by itself |
| B2 | Collection | **T1213.003** Code Repositories | Bulk clone or download of repositories beyond the employee's current work. Documented, **not emulated**. | Many clones in a short period; repositories the user has never touched |
| B3 | Collection | **T1074.001** Local Data Staging | Data is copied into one folder or archive. Emulated with the same canary ability 03. | File-copy burst; new large archive |
| B4 | Exfiltration | **T1567.002** Exfiltration to Cloud Storage; **T1052.001** Exfiltration over USB | Upload to a personal cloud account or copy to a USB drive. Technical proxy: canary ability 04 (local sink). The cloud and USB routes are documented only. | Upload to unsanctioned cloud service; USB mass-storage device connected followed by large file writes |

**Context signals.** MITRE's insider-threat work also describes "Observable Human Indicators": context about the person (for example, a resignation notice or access outside their normal role) that technical logs alone do not show. For Variant B these signals are likely more useful than any single technical rule, and we have no data source for them.

## 6. Physical track (tabletop + synthetic logs)

ATT&CK does not describe physical access, so these steps have **no ATT&CK ID**; we describe them in plain language and map them to the Kill Chain ideas from Week 4.

| Step | Phase | Procedure (tabletop) | Expected evidence |
|---|---|---|---|
| P1 | Reconnaissance | Staff badges are photographed in public social-media posts (Week 2, OSINT) | none in internal logs |
| P2 | Initial access | A cloned badge is used at a second site. **Not performed**; represented by a log entry | same badge at two distant sites within minutes |
| P3 | Persistence | The cloned badge stays valid until someone notices and revokes it | repeated use of one badge over days |
| P4 | Access abuse / exfiltration | After-hours entry to a restricted room; data could leave on removable media (T1052.001 as the nearest ATT&CK match) | server-room entry at night |

**Hunts run on synthetic badge logs** (`acs_emulation_sample.jsonl`, 8 events; script `acs_check.py`). This is a logic check, not real access-control data and not a SIEM run.

| Hunt | Logic | Hits | True positives | False positives | Missed |
|---|---|---|---|---|---|
| Impossible travel | Same badge, different site, under 10 minutes | 1 | 1 | 0 | 0 |
| Anti-passback violation (tailgating) | Badge-out with no earlier badge-in that day | 1 | 1 | 0 | 0 |
| After-hours server room | Server-room door between 22:00 and 05:00 | 1 | 1 | 0 | 0 |

Zero false positives only reflects how small and clean the sample is. In production, shift workers, shared doors and reader outages would create false positives, so each rule needs allowlists and an owner. This takes H3 from Week 5 from "designed, not executed" to "logic-checked on synthetic data"; it has not been run on real access-control data.

## 7. Detection coverage and gaps (prediction, before running)

| Step | Covered by | Status | Comment |
|---|---|---|---|
| A 1.1 Malicious extension update | None yet | **Gap** | Needs an extension inventory (allowlist of extension IDs and versions) and update alerts. |
| A 2.1 Extension persistence | None yet | **Gap** | Needs file-creation telemetry for IDE plugin paths. |
| A 2.2 / 2.3 Shell with credential paths from IDE | Hunt H2 (Week 5), KQL rule (Week 3) | **Covered, with a blind spot** | Works only if the path appears in a *command line*. Malware running inside the IDE's own process can read the files without starting a child process; that needs file-access telemetry (auditd, EDR). |
| A 3.1 / B2 Bulk repository cloning | None in our project; Elastic publishes a prebuilt rule "GitHub Exfiltration via High Number of Repository Clones by User" as a reference | **Gap (reference exists)** | Needs GitHub audit-log ingestion; check exact event fields before reuse. |
| A 3.2 / B3 Staging | None yet | **Gap** | File-copy bursts are noisy; needs baselining. |
| A 3.3 Exfiltration | H2 partly (`curl` in the command) | **Partial** | Network telemetry (proxy or Sysmon Event ID 3) is not part of our test data. |
| B4 Cloud / USB exfiltration | None | **Gap** | Needs proxy or CASB data and USB device events. |
| Physical P2–P4 | Three rules checked on synthetic logs (Section 6) | **Logic only** | Not tested on real access-control data. |

## 8. Findings and recommendations

These follow from the predicted gaps in Section 7. They are proposals for the team to confirm, not measured results.

| Priority | Gap | Why it matters | Recommended action |
|---|---|---|---|
| 1 | Malicious or updated IDE extension (A 1.1, 2.1) | The extension is trusted and persists across reboots; this is the Nx Console pattern | Inventory extensions on developer machines, allow only approved IDs, pin versions or review updates before they roll out |
| 2 | Credential stores read without a visible command line (A 2.3) | H2 misses code that reads files inside the IDE process | Add file-access telemetry (auditd or EDR) for `.ssh`, `hosts.yml`, cloud credentials; place decoy ("canary") credential files that alert when read |
| 3 | Token and repository abuse (A 1.2, 3.1, B2) | A stolen or misused token looks like a normal developer | Use short-lived, fine-grained tokens; stream GitHub audit logs; alert on bulk cloning |
| 4 | Exfiltration channels (A 3.3, B4) | Both variants end with data leaving through a normal-looking channel | Monitor outbound traffic from developer hosts; control USB storage; flag uploads to unsanctioned cloud services |
| 5 | Physical access (P2–P4) | A cloned badge is indistinguishable from the real one at the door | Enable anti-passback and impossible-travel alerts; discourage publishing badge photos; review after-hours restricted-room access |
| 6 | Malicious insider context (B) | Technical logs alone rarely separate misuse from normal work | Combine technical alerts with HR and role context where policy allows |

## 9. Success criteria for the run

| Metric | Definition | Result |
|---|---|---|
| Detection coverage | Steps detected / steps executed | to be measured in Week 9 |
| Evidence match | For each executed step, the expected evidence in Sections 4–5 appears in the logs | to be measured in Week 9 |
| False positives | Benign events matching the same query | to be measured in Week 9 |
| Blind spots confirmed | Steps that leave evidence but were not detected | to be measured in Week 9 |

## 10. CALDERA mapping

CALDERA (MITRE's adversary emulation platform) works with: **agents** (programs on the target that run instructions and report back, such as Sandcat), **abilities** (single instructions mapped to an ATT&CK technique), **adversary profiles** (ordered groups of abilities) and **operations** (a run of a profile against agents, automatic or with operator approval).

| Plan step | Caldera ability file | Tactic | Technique |
|---|---|---|---|
| A 2.1 | `01_persistence_fake_ide_extension.yml` | persistence | T1176.002 |
| A 2.3 | `02_credential_access_canary_files.yml` | credential-access | T1552.001 |
| A 3.2, B3 | `03_staging_canary_copy.yml` | collection | T1074.001 |
| A 3.3, B4 (proxy) | `04_exfil_to_local_sink.yml` | exfiltration | T1567 |
| Variant A as a whole | `adversary_insider_x.yml` (profile "Insider-X (compromised developer) - LAB") | | |

Variant B reuses abilities 03 and 04 as its technical proxy; no separate profile is needed.

Status: the files follow Caldera's ability and adversary YAML structure and parse as valid YAML. They have **not been loaded into a Caldera instance**; field names may need small adjustments for the installed version. All abilities use canary data and the local sink and include cleanup.

## 11. Lab preparation for execution (planned, Week 9)

1. A Windows or Linux lab machine (own laptop or VM) with VS Code.
2. Process-creation logging: Sysmon (Windows) or auditd (Linux), sent to the Elastic index used in Week 5.
3. A local listener: `python3 -m http.server 8000`.
4. Caldera server and one agent on the lab machine, or run the commands from the abilities manually.
5. Run the four abilities in order, then run step 2.2 manually from the VS Code terminal.
6. Run hunt H2 (Week 5) and compare with Section 7; record real results in Section 9.
7. Run cleanup and delete the `lab_emulation` folder.

## 12. Connection to previous weeks and limitations

- **Week 2:** Variant A is modeled on the Nx Console case; the physical track on the badge OSINT case.
- **Week 3:** the VS Code credential KQL rule is the detection for steps A 2.2–2.3; the physical rules from the data schema are run in Section 6.
- **Week 4:** the phases correspond to Kill Chain stages (Exploitation/Installation → Actions on Objectives).
- **Week 5:** hunts H2 and H3 are the detections the plan tests.

Limitations:
- The plan is not executed yet; all "expected" results are predictions.
- Initial access (A 1.1) and the real-data steps (A 1.2, 3.1, B2, B4 cloud and USB) are documented only.
- Variant B depends on human context that our data sources do not provide.
- The physical track has no ATT&CK mapping and is tested on synthetic logs only.
- Caldera files are not tested against a live Caldera server.
- Malware may read credential files inside the IDE process without any visible command line (blind spot in Section 7).
- Recommendations in Section 8 are proposals based on predicted gaps, not measured results.

## 13. Sources

- MITRE ATT&CK: [T1176 Software Extensions](https://attack.mitre.org/techniques/T1176/) (sub-technique T1176.002 IDE Extensions); [T1195.002](https://attack.mitre.org/techniques/T1195/002/); [T1078](https://attack.mitre.org/techniques/T1078/); [T1552](https://attack.mitre.org/techniques/T1552/); [T1528](https://attack.mitre.org/techniques/T1528/); [T1213.003](https://attack.mitre.org/techniques/T1213/003/); [T1074.001](https://attack.mitre.org/techniques/T1074/001/); [T1567](https://attack.mitre.org/techniques/T1567/); [T1052.001](https://attack.mitre.org/techniques/T1052/001/)
- MITRE Engenuity Center for Threat-Informed Defense (CTID): [Adversary Emulation Library](https://ctid.mitre.org/resources/adversary-emulation-library/) (full and micro emulation plans; micro plans include Data Exfiltration and File Access and File Modification)
- CTID: [Insider Threat TTP Knowledge Base](https://ctid.mitre.org/projects/insider-threat-ttp-knowledge-base-v1) (V1, February 2022) and [CTID roadmap](https://ctid.mitre.org/roadmap/) (expansion, Observable Human Indicators)
- CrowdStrike: [MITRE CTID partnership reveals insider threat techniques](https://www.crowdstrike.com/en-us/blog/mitre-ctid-partnership-reveals-insider-threat-techniques/)
- Elastic: [GitHub Exfiltration via High Number of Repository Clones by User](https://www.elastic.co/guide/en/security/8.19/github-exfiltration-via-high-number-of-repository-clones-by-user.html) (prebuilt detection rule, reference for A 3.1 and B2; not tested by us)
- MITRE Caldera documentation (recommended reading); concept summary: [NVISO, A beginner's guide to adversary emulation with Caldera](https://blog.nviso.eu/2023/08/25/a-beginners-guide-to-adversary-emulation-with-caldera/)
- This repository: Weeks 2–5

## 14. Team notes and use of AI

Team decisions: we cover both a compromised and a malicious insider because our topic, insider threat via trusted access, includes both. In the first case an attacker borrows an insider's trusted access (the Nx Console case); in the second the insider uses access they already have. Covering both also shows a real difference in the plan: a malicious insider needs no initial access or persistence, which makes them harder to detect. Changes to the first draft: we added Variant B (malicious employee), a summary at the start and a findings and recommendations section (Section 8), because the first version had no true insider scenario and no conclusion about what to fix first.

Generative AI was used to draft and structure this plan, to check technique names against attack.mitre.org. The scenario, scope and limitations were reviewed by the team: Aruzhan, Aidana, Yernar(confirm). 
