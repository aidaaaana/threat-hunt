# Week 9: Atomic Red Team — Linux File and Directory Discovery

**Course:** Introduction to Threat Hunting (AITU, 2026–2027)  
**Project topic:** Insider threat via trusted access — digital track.  
**Lab date:** 3 November 2026  
**ATT&CK:** T1083 — File and Directory Discovery.

---

## 1. Overview

This lab examines file discovery on a developer's Linux workstation. It extends Week 5's trusted-tooling hypothesis by testing one observable behavior: a process enumerating documents and hidden files under the current user's permissions.

Two commands from an Atomic Red Team test were executed manually in a dedicated training directory. Linux auditd captured process execution, and an exported audit log was prepared in Elastic's file-upload interface. Kibana Discover was configured to search the resulting data view.

The experiment uses real process telemetry and deliberately created files. It does not reproduce a compromised IDE, a supply-chain attack, credential theft, or exfiltration.

---

## 2. Selected Atomic Test

| Field | Value |
|---|---|
| Technique | T1083 — File and Directory Discovery |
| Test name | Nix File and Directory Discovery 2 |
| Test GUID | `13c5e1ae-605b-46c4-a79f-db28c77ff24e` |
| Supported platforms | Linux, macOS |
| Executor | `sh` |
| Execution method | Manual execution of two selected commands; no Invoke-AtomicRedTeam runner |
| Search scope | `/home/kali/week9-simple/demo` |

The upstream test includes several discovery operations. This lab selects PDF enumeration and hidden-file enumeration, adds quotes around wildcard patterns to prevent shell expansion, and limits execution to a training directory. It is a scoped adaptation, not a complete execution of the upstream test.

![Atomic Red Team YAML showing the selected Linux-compatible test](images/01-atomic-definition.png)

*Figure 1. The test definition identifies the technique's Linux discovery commands and supported platform.*

---

## 3. Lab Environment and Telemetry

| Component | Role |
|---|---|
| Kali Linux x86-64 in Oracle VirtualBox | Test endpoint |
| Local user `kali` | Executes discovery commands without elevation |
| auditd | Records execution events |
| Elastic Cloud / Kibana | Manual log import and search interface |
| `week9-audit.log` | Exported real audit records |
| `week9-audit.log` data view | Data source shown in Discover |

The audit status check showed `enabled 1`, a running daemon PID, and `lost 0` at the time of the check. The `failure 1` value is a failure-handling setting, not evidence of an audit error. A later end-of-run loss check was not supplied.

The active process-execution rule was:

```bash
sudo /usr/sbin/auditctl -a always,exit -F arch=b64 -S execve \
  -F "euid=$(id -u)" -k w9_exec
```

This records `execve` calls for the selected effective user. It does not capture every operation performed inside a running process.

An additional execution watch on `/usr/bin/find` used the key `w9_find`. The supplied execution events carried `w9_exec`, consistent with the earlier matching execution rule. Searching only for `w9_find` initially returned the rule-configuration event rather than the test executions. Analysis therefore used the key present in the actual records.

---

## 4. Execution

### 4.1 Training files

```bash
mkdir -p ~/week9-simple/demo
printf 'training document\n' > ~/week9-simple/demo/report.pdf
printf 'hidden training note\n' > ~/week9-simple/demo/.hidden-note
cd ~/week9-simple/demo
```

The `.pdf` file is a text fixture with a PDF filename extension, not a valid PDF document. That is sufficient here because the command matches filenames rather than file contents.

### 4.2 Selected discovery commands

```bash
/usr/bin/find . -type f -iname '*.pdf'
/usr/bin/find . -type f -name '.*'
```

Observed terminal output:

```text
./report.pdf
./.hidden-note
```

The first command matches PDF filenames without case sensitivity. The second matches filenames beginning with a dot. Neither command requests file-content output. Hidden filenames are a Linux naming convention, not an access-control boundary.

### 4.3 Evidence export

```bash
sudo /usr/sbin/ausearch -k w9_exec -x /usr/bin/find -ts today -i \
  | tee ~/week9-simple/audit-find.txt

sudo /usr/sbin/ausearch -a 5834 -ts today -i \
  | tee ~/week9-simple/pdf-event.txt

sudo /usr/sbin/ausearch -a 5839 -ts today -i \
  | tee ~/week9-simple/hidden-event.txt

sudo /usr/sbin/ausearch -k w9_exec -x /usr/bin/find -ts today --raw \
  > ~/Desktop/week9-audit.log
```

The daily export also contains earlier runs, including a previous credentials-discovery exercise. Those records are outside this report's T1083 result set. The two selected audit event IDs identify the final pair of discovery executions in the supplied evidence.

---

## 5. Execution Results

| Selected audit event ID | Process arguments | Working directory | Observed result |
|---|---|---|---|
| `5834` | `/usr/bin/find . -type f -iname *.pdf` | `/home/kali/week9-simple/demo` | `execve`, `success=yes`, `exit=0`; terminal returned `./report.pdf` |
| `5839` | `/usr/bin/find . -type f -name .*` | `/home/kali/week9-simple/demo` | `execve`, `success=yes`, `exit=0`; terminal returned `./.hidden-note` |

Both events identify the executable as `/usr/bin/find`, the user as `kali`, and the audit key as `w9_exec`.

Here, `success=yes` and `exit=0` refer to the `execve` system call: the program was launched successfully. They are not the eventual exit status of the `find` process. The discovered filenames are evidenced separately by the terminal output.

![Audit evidence for the PDF and hidden-file discovery executions](images/02-audit-events.png)

*Figure 2. Events 5834 and 5839 show the command arguments, working directory, user, and successful process execution.*
