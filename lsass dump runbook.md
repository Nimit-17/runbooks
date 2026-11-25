# LSASS credential dump triage

## Runbook details

Title: LSASS credential dump triage  
Id: lsass_credential_dump  
Summary: Confirm whether LSASS was accessed or dumped, judge malicious vs approved activity, and check for credential reuse.  
Use when: An alert or case suggests LSASS process access, LSASS memory dump, or credential dumping from LSASS. This maps to MITRE ATT&CK technique T1003.001 (OS Credential Dumping: LSASS Memory).  
Prerequisites: Host telemetry that can show process access to LSASS, process creation, and/or dump file creation (Sysmon, EDR, or equivalent). Auth logs help for follow-on checks.  
Priority: 80  
Review every: 180  
Owner: (your name / SOC content owner)  
Covers techniques: MITRE ATT&CK T1003.001  
Search phrases: lsass dump; credential dump lsass; lsass process access; lsass memdump; MITRE T1003.001  
References: https://attack.mitre.org/techniques/T1003/001/

### Applies when

1. Technique = MITRE ATT&CK T1003.001  
2. Rule = add your real detection rule IDs here when you have them

---

## Outline

### Phase 1 — Validate

#### Step 1 — Check
**Question:** Did a process open or dump LSASS on this host?

**Focus:** Whether the target process is `lsass.exe`; which process accessed it; what access rights were requested; whether a dump file was created; host; time.  
If Sysmon is present, process access is Event ID 10. If Windows object-access auditing is present, handle/access events are often 4656/4663. If file-create telemetry is present, check for an LSASS-related `.dmp` file.

**Escalate if:** Evidence shows access to `lsass.exe` with rights that allow memory read/dump, and/or an LSASS-related dump file created by the same process.

**Benign if:** No LSASS access and no LSASS-related dump file is present.

**Evidence before Done:** Cite the access event and/or dump-file event.

---

#### Step 2 — Check
**Question:** What access or dump pattern do the logs show?

**Focus:** Acting process name and path, command line, parent process, dump file path if any. Name the tool if obvious; otherwise describe the pattern (access only, access plus dump, or tool start plus dump).

**Escalate if:** An unexpected process accessed LSASS and/or wrote an LSASS-related dump, whether the tool is known or unknown.

**Benign if:** The process is a verified approved security, IR, or admin tool for this host and time.

**Evidence before Done:** Note the pattern, acting process, and dump path if present.

---

### Phase 2 — Context

#### Step 3 — Check
**Question:** Is the acting process expected and approved on this host?

**Focus:** Process path, user, parent process, approved EDR/AV/IR paths versus unusual locations such as Desktop, Temp, Downloads, or a renamed binary.

**Escalate if:** Path or parent is unexpected, ownership is unknown, or a normally legitimate binary was used to dump LSASS without an approved explanation.

**Benign if:** Owner or ticket confirms approved security, IR, or admin activity for this host and window.

**Evidence before Done:** Approved or unexpected, with owner or ticket if approved.

---

#### Step 4 — Lookup
**Title:** Related LSASS access and dump artifacts on the host

**Focus:** Same host near alert time: process access to `lsass.exe`, related process creation, dump file creation.

**Tool:** log search  
**Time window:** alert time ± 60 minutes  
**Limit:** 50  
**When:** When the runbook starts

---

#### Step 5 — Lookup
**Title:** Follow-on authentications after the dump

**Focus:** Successful logons or ticket use after dump time for users tied to the host; new source hosts or IPs; possible lateral movement.

**Tool:** log search  
**Time window:** dump time to +24 hours  
**Limit:** 50  
**When:** When the runbook starts

---

#### Step 6 — Check
**Question:** Were privileged credentials likely exposed or reused?

**Focus:** Users logged on near dump time; admin or service accounts; post-dump auth from new hosts or IPs; related lateral-movement alerts.

**Escalate if:** A privileged account was on the host at dump time, or those accounts show suspicious auth or movement afterward.

**Benign if:** No privileged exposure and no suspicious follow-on auth, and the actor is already confirmed approved.

**Evidence before Done:** Exposure and reuse findings, including account names and post-dump auth if any.

---

### Phase 3 — Decide

#### Step 7 — Decision
**Title:** Disposition

**Focus:** LSASS confirmation, approval status, exposure, and follow-on auth together.

**Escalate if:** Unexpected LSASS access or dump is confirmed, especially with privileged exposure or follow-on reuse.

**Benign if:** Activity is fully explained as approved security, IR, or admin work and the follow-on hunt is clean.

**Options:**
1. `true_positive` — Suspicious LSASS credential dump activity
2. `false_positive` — Approved or benign LSASS-related activity
3. `needs_human` — Missing, unclear, or conflicting evidence

---

### Phase 4 — Respond

#### Step 8 — Action
**Title:** Recommend containment when true positive

**Focus:** Host, exposed users, dump path, actor process evidence to preserve.

**Instructions:** Recommend host isolation or close monitoring, reset or revoke exposed credentials and sessions, preserve process dump and auth evidence, and widen the hunt. Record the recommendation only.

---

#### Step 9 — Record
**Title:** Write the triage note

**Focus:** Pattern, actor process, dump path, approval status, exposure, follow-on findings, disposition.

**Instructions:** Short evidence-based note only. No passwords, hashes, or secrets.
