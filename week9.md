# Week 9: Atomic Red Team — Linux File and Directory Discovery

**Course:** Introduction to Threat Hunting &#40;AITU, 2026–2027&#41;
**Project topic:** Insider threat via trusted access — digital track\.
**Lab date:** 3 November 2026
**ATT&CK:** T1083 — File and Directory Discovery &#40;Discovery tactic&#41;\.
**Lab focus:** Execute a narrowly scoped Atomic Red Team behavior, collect Linux process evidence, and assess how it could support the team’s earlier threat\-hunting hypothesis\.

---

## 0\. Summary

**What this is\.** Unlike Week 8, which documented a *planned* adversary emulation, this Week 9 report describes a *performed* test\. On an isolated Kali Linux lab VM, two file\-discovery commands adapted from Atomic Red Team test \#4 for T1083 were run against two deliberately created files\. The commands ran as the ordinary `kali` user, not as root\.

|Question                                          |Observed result                                                                                                       |Interpretation                                                                                                        |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
|What was tested?                                  |PDF-name search and hidden-file-name search with `/usr/bin/find`                                                      |A limited instance of T1083                                                                                           |
|Was the test run?                                 |Yes; terminal output showed `./report.pdf` and `./.hidden-note`                                                       |Discovery worked within the lab directory                                                                             |
|Was host telemetry available?                     |auditd was enabled; supplied execution records used key `w9_exec`                                                     |Process execution was observable in local audit logs                                                                  |
|Was Elastic used?                                 |`week9-audit.log` was prepared in the upload interface, and the `week9-audit.log` data view was configured in Discover|An investigation workflow was set up; matching Discover hits are not independently documented in the supplied material|
|Was insider compromise or exfiltration reproduced?|No                                                                                                                    |The test isolates one discovery behavior, not the entire Week 8 attack chain                                          |

**Main finding\.** File discovery can be visible through process\-execution telemetry even when the activity runs under an ordinary authorized account\. However, `find` is also a common administrative tool, so this evidence by itself does not establish malicious intent\.

**Top recommendations:** Preserve the process arguments and audit rule key during ingestion; verify the actual Kibana matches and their timestamps; and correlate suspicious discovery with subsequent credential\-file access, staging, or network activity before escalating an alert\.

## 1\. Purpose and scenario

The Week 8 plan asked whether trusted access on a developer workstation could conceal preparatory behavior before data theft\. Week 9 narrows that question to one testable action: **can we observe a user\-level process enumerating potentially relevant files on Linux?**

The simulated actor is a user who already has access to a workstation\. A real attacker or malicious employee might search for documents before collection or exfiltration\. This lab reproduces only the discovery step\. No IDE extension was compromised, no credentials were accessed, and no data was transmitted out of the VM\.

**Test hypothesis:** If the user launches `/usr/bin/find` to enumerate files, auditd’s execution rule should provide process\-execution evidence that a threat hunter can identify and later correlate with other events\. The terminal output independently shows whether the discovery commands matched the test filenames\.

## 2\. Scope, safety, and rules of engagement

|Rule           |Implementation                                                                                       |
|---------------|-----------------------------------------------------------------------------------------------------|
|Endpoint       |Team-controlled Kali Linux x86-64 VM in Oracle VirtualBox                                            |
|User           |Local account `kali`; discovery commands without privilege elevation                                 |
|Data           |Only the text fixtures `report.pdf` and `.hidden-note`                                               |
|Search boundary|`/home/kali/week9-simple/demo`                                                                       |
|Network        |No simulated upload, external listener, or data exfiltration                                         |
|Tooling        |Two commands executed manually; no Invoke-AtomicRedTeam runner or Caldera agent                      |
|Evidence       |Local auditd events exported to `week9-audit.log`; Elastic used as a manual analysis interface       |
|Limitations    |Does not represent a compromised IDE, real secret access, persistence, or a full insider-threat chain|

## 3\. Atomic Red Team selection and ATT&CK mapping

|Field              |Value                                                 |
|-------------------|------------------------------------------------------|
|ATT&CK technique   |**T1083 — File and Directory Discovery**              |
|ATT&CK tactic      |Discovery                                             |
|Upstream test      |**Atomic Test #4: Nix File and Directory Discovery 2**|
|Test GUID          |`13c5e1ae-605b-46c4-a79f-db28c77ff24e`                |
|Supported platforms|Linux, macOS                                          |
|Upstream executor  |`sh`                                                  |
|Actual execution   |Two selected commands typed manually                  |
|Local test path    |`/home/kali/week9-simple/demo`                        |

The upstream test contains additional operations, including directory\-tree listing and reading `/etc/mtab`\. These were **not** executed in this experiment\. We selected only PDF and dotfile searches, quoted the wildcard patterns, and worked inside the training directory\. This is a **scoped adaptation**, not a full execution of the upstream test\.

![Atomic Red Team YAML showing the selected Linux-compatible test](images/01-atomic-definition.png)

*Figure 1\. Atomic Red Team definition for the selected Linux\-compatible T1083 test\. This image must exist at the repository\-relative path shown above to render in Markdown\.*

## 4\. Lab environment and telemetry

|Component                      |Role / status                                                                               |
|-------------------------------|--------------------------------------------------------------------------------------------|
|Kali Linux in Oracle VirtualBox|Linux test endpoint                                                                         |
|`kali` account                 |Runs test commands with ordinary user permissions                                           |
|`/usr/bin/find`                |File-discovery utility                                                                      |
|auditd                         |Collects execution telemetry                                                                |
|`w9_exec` rule key             |Identifies observed execution records                                                       |
|`w9_find` key                  |Additional `/usr/bin/find` execution watch; no execution events under this key were supplied|
|`week9-audit.log`              |Exported genuine audit records                                                              |
|Elastic Cloud / Kibana Discover|Manual import and investigation interface                                                   |
|`week9-audit.log` data view    |Selected source for investigation                                                           |

### 4\.1 Audit configuration

The process\-execution rule used in the lab was:

```bash
sudo /usr/sbin/auditctl -a always,exit -F arch=b64 -S execve \
  -F "euid=$(id -u)" -k w9_exec
```

It monitors `execve` for the selected effective user on the 64\-bit architecture\. This is **execution telemetry**, not a complete file\-access trace\. It does not, for example, prove that the contents of a matched file were opened or read\.

At the time of the audit status check, the supplied information showed `enabled 1`, a running audit daemon PID, and `lost 0`\. `failure 1` describes how audit failures are handled; it does **not** mean one audit event failed\. No end\-of\-run audit\-loss measurement was supplied\.

An additional execution watch on `/usr/bin/find` used key `w9_find`\. Searching for this key initially showed a rule\-configuration event rather than the test executions; the available execution records carried **`w9_exec`**\. Therefore, analysis follows the key actually present in the records\.

## 5\. Execution procedure

### 5\.1 Create harmless training files

```bash
mkdir -p ~/week9-simple/demo
printf 'training document\n' > ~/week9-simple/demo/report.pdf
printf 'hidden training note\n' > ~/week9-simple/demo/.hidden-note
cd ~/week9-simple/demo
```

The first fixture is plain text with a `.pdf` extension, not a structurally valid PDF\. That is enough for this experiment because `find` searches the **filename**, not the content\.

### 5\.2 Run the two selected commands

```bash
/usr/bin/find . -type f -iname '*.pdf'
/usr/bin/find . -type f -name '.*'
```

Observed terminal output:

```text
./report.pdf
./.hidden-note
```

The first command locates regular files ending in `.pdf` without regard to case\. The second finds regular files whose names begin with a dot\. Dotfiles are hidden by convention in many Linux listings, but are not inherently protected by access controls\.

### 5\.3 Audit evidence export

The lab produced a real audit export named `week9-audit.log`\. The supplied material does not specify the exact original export command\. For reproducibility, the following **example** exports events with the observed key &#40;it must not be treated as a record of the original operator’s keystrokes&#41;:

```bash
sudo ausearch -k w9_exec -i > ~/week9-simple/week9-audit.log
```

An analyst should review the exported records for the relevant `SYSCALL` and `EXECVE` messages, and associate audit records by their shared audit event identifier\. Where included, `CWD` records add working\-directory context\. The presence of an export file alone does not establish that Elastic correctly parsed every argument\.

### 5\.4 Elastic investigation setup

The export was prepared in Elastic’s manual file\-upload interface, and Discover was configured to use the `week9-audit.log` data view\. The material provided does **not** include a verifiable record count, two matching documents in Discover, or a screenshot demonstrating that the file\-upload import completed successfully\.

For a reproducible verification, select the data view, set the time range to include **3 November 2026** &#40;checking the VM’s timezone&#41;, inspect searchable fields, and locate the `w9_exec` records\. If the logs were ingested as plain\-text lines, a possible query **only if ****`message`**** exists and is indexed** is:

```kql
message: "w9_exec"
```

If the logs were parsed into process fields, a different starting query **only if ****`process.name`**** exists** is:

```kql
process.name: "find"
```

These are investigation examples, **not confirmed successful searches**\. Check the actual field names before using them; some Elastic audit integrations store raw text in `event.original`, which may not be indexed for search\.

## 6\. Observed results and evidence

|Evidence item                                    |What is supported                                            |Status                                |
|-------------------------------------------------|-------------------------------------------------------------|--------------------------------------|
|Terminal output                                  |Two expected filenames returned                              |**Observed**                          |
|auditd status                                    |Enabled; `lost 0` when checked                               |**Observed at one point in time**     |
|Local audit events                               |Execution records associated with `w9_exec`                  |**Observed in supplied account**      |
|`w9_find` search                                 |Initially surfaced rule setup rather than the test executions|**Observed**                          |
|Audit export                                     |`week9-audit.log` prepared                                   |**Reported / prepared**               |
|Discover matching events                         |Exact hits, document count, parsed fields, and timestamps    |**Not evidenced in supplied material**|
|Exfiltration, credential reading, IDE involvement|None performed                                               |**Out of scope**                      |

**Interpretation:** The two terminal outputs establish that file enumeration worked inside the controlled directory\. Local audit execution records provide a process\-level trace of the commands\. Neither observation proves that a malicious insider was present or that data was actually read, copied, or exported\.

## 7\. Detection logic: from telemetry to a hunt

**Candidate hunt:** identify file discovery by an ordinary user and examine whether it is unusual for the host, directory, and surrounding activity\.

|Signal           |What to inspect                                     |Why it matters                                                                  |
|-----------------|----------------------------------------------------|--------------------------------------------------------------------------------|
|Executable       |`/usr/bin/find` or `process.name: find` where parsed|Identifies the tool                                                             |
|Arguments        |`-type f`, `-iname`, `*.pdf`, `-name`, `.*`         |Distinguishes these searches from unrelated use of `find`                       |
|User             |Effective UID / username                            |Shows whose permissions were used                                               |
|Working directory|`/home/kali/week9-simple/demo` where available      |Establishes the controlled search scope                                         |
|Audit key        |`w9_exec`                                           |Locates the rule that captured the known events                                 |
|Parent process   |Inspect if available                                |Would help distinguish a shell, IDE child, or other origin; not established here|
|Follow-on actions|Copy, archive, credential access, upload            |Would strengthen a malicious-activity hypothesis; not included in this run      |

**Detection principle:** A `find` command is not inherently suspicious\. A stronger hunt would combine unusual paths, timing, parent process, a sequence of sensitive\-file discovery commands, and later staging or exfiltration\. This lab validates a source of evidence for that sequence, but **does not validate a production detection rule**\.

## 8\. Detection coverage and gaps &#40;measured versus untested&#41;

|Scenario step                                       |Week 9 coverage                                              |Assessment              |
|----------------------------------------------------|-------------------------------------------------------------|------------------------|
|Discovery of PDF filenames under current-user access|Manual `find` plus local audit telemetry                     |**Behavior reproduced** |
|Discovery of dotfiles under current-user access     |Manual `find` plus local audit telemetry                     |**Behavior reproduced** |
|Exact Kibana detection of both commands             |Discover data view configured, but matching hits not supplied|**Unverified**          |
|File-content access                                 |No read/open monitoring demonstrated                         |**Gap**                 |
|Discovery started by a compromised IDE              |Commands run manually, not from the IDE                      |**Not tested**          |
|Staging or data copying                             |No staging action                                            |**Not tested**          |
|Network or cloud exfiltration                       |No outbound transfer                                         |**Not tested**          |
|Malicious-insider intent                            |No role or behavioral context                                |**Cannot be determined**|
|Physical badge-access track                         |Not part of this Linux exercise                              |**Out of scope**        |

This table differs from Week 8’s prediction\-only coverage matrix: it separates **what actually ran** from **what still needs evidence**\.

## 9\. Success criteria and measurement

|Metric                  |Definition                                           |Result                                                        |
|------------------------|-----------------------------------------------------|--------------------------------------------------------------|
|Test completion         |Selected discovery commands executed                 |**2 of 2**                                                    |
|Discovery output        |Expected lab filenames returned                      |**2 of 2**                                                    |
|Local execution evidence|Relevant `find` execution events appear in audit logs|**Supported by reported `w9_exec` events; count not supplied**|
|Elastic evidence match  |Both commands searchable and identifiable in Discover|**Not yet verified from supplied evidence**                   |
|False positives         |Benign events incorrectly classified as malicious    |**Not measured**                                              |
|False negatives         |Expected execution events absent from the collection |**Not measured**                                              |
|End-of-run audit loss   |`auditctl -s` after the experiment                   |**Not supplied**                                              |

The numeric `2 of 2` entries refer to **manual terminal behaviors**, not a SIEM detection rate\. A quantitative detection rate cannot be reported without matched, independently reviewed Elastic events\.

## 10\. Findings and recommendations

|Priority|Finding / gap                                                                            |Recommendation                                                                                                      |
|--------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
|1       |The local audit records use `w9_exec`, not the expected secondary key `w9_find`          |Filter on the key actually observed; document active rule order and all matching keys                               |
|2       |Elastic import and matched hits are not demonstrated in the supplied evidence            |Save a Discover screenshot showing the correct data view, time window, and matching command events                  |
|3       |Process creation does not prove file-content access                                      |Add narrowly scoped file-access telemetry on approved canary paths if the future exercise needs read-access evidence|
|4       |`find` is widely used for legitimate development and maintenance                         |Avoid a high-severity rule on executable name alone; correlate with unusual directories and sequences               |
|5       |Manual shell execution does not reproduce the trusted-IDE parent relationship from Week 8|In an authorized follow-up, run the same canary searches from an IDE terminal and compare parent-process evidence   |
|6       |The full Week 8 chain remains untested                                                   |Keep staging and local-only exfiltration as separate, explicitly labeled future tests                               |

## 11\. Connection to previous weeks

|Earlier work                                |Relation to Week 9                                                                                         |
|--------------------------------------------|-----------------------------------------------------------------------------------------------------------|
|Week 2 — Nx Console / trusted tooling case  |Provides the real-world motivation for detecting behavior by apparently legitimate tools                   |
|Week 3 — process and credential-path hunting|Shows why command-line and process context are useful but limited signals                                  |
|Week 5 — trusted-tooling hypothesis (H2)    |Week 9 tests a narrower precursor: file discovery as the current user                                      |
|Week 8 — adversary emulation plan           |Week 9 executes **one discovery micro-test**, not the full initial access → persistence → exfiltration plan|
|Physical track                              |No physical-access events or synthetic badge logs were generated in this exercise                          |

## 12\. Limitations

- The experiment uses only two filenames and two manual commands in a controlled directory; it is not representative of a full filesystem scan\.
- The `.pdf` fixture is ordinary text, because the test matches filename extensions only\.
- auditd `execve` telemetry records process execution, not every operation that `/usr/bin/find` performs internally\.
- The audit\-loss value `lost 0` was observed at one check, not independently at the end of the run\.
- The exported audit evidence and Elastic data view are described, but no independently verifiable Kibana match count or parsed event samples were supplied\.
- There is no evidence of IDE compromise, credentials being read, files being copied, or data being exfiltrated\.
- No normal\-user baseline or negative\-control dataset was collected, so accuracy and false\-positive rates cannot be calculated\.
- Atomic Test \#4 was adapted: several upstream commands and the runner were intentionally omitted\.

## 13\. Sources

- MITRE ATT&CK: [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)\.
- Atomic Red Team: [T1083 — Atomic Test \#4, Nix File and Directory Discovery 2](https://www.atomicredteam.io/docs/atomics/T1083)\.
- Atomic Red Team source: [T1083 test definition on GitHub](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md)\.
- Elastic: [Auditd Logs integration](https://www.elastic.co/docs/reference/integrations/auditd)\.
- Elastic: [Discover documentation](https://www.elastic.co/docs/explore-analyze/discover)\.
- Elastic: [Kibana Query Language](https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql)\.
- Elastic: [Upload data files](https://www.elastic.co/docs/manage-data/ingest/upload-data-files)\.
- This team’s prior work: Weeks 2–5 and the Week 8 emulation plan\.

## 14\. Team notes and use of AI

**Team decision:** To make the Week 8 plan measurable without introducing real compromise or exfiltration, Week 9 focuses on a single Linux file\-discovery technique\. The test uses benign fixtures and ordinary\-user access; results are labeled as observed, reported, or not yet verified\.
