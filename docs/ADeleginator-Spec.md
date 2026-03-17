# ADeleginator — Functional and Technical Specification

**Version:** 0.1
**Date:** 2026-03-17
**Repository:** [franklesniak/ADeleginator](https://github.com/franklesniak/ADeleginator)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Purpose & Goals](#2-purpose--goals)
3. [Prerequisites & Dependencies](#3-prerequisites--dependencies)
4. [Input Parameters](#4-input-parameters)
5. [Execution Workflow (Step-by-Step)](#5-execution-workflow-step-by-step)
6. [Output Artifacts](#6-output-artifacts)
7. [Detection Logic & Matching Rules](#7-detection-logic--matching-rules)
8. [Console Output & User Feedback](#8-console-output--user-feedback)
9. [Limitations & Assumptions](#9-limitations--assumptions)
10. [Glossary](#10-glossary)

---

## 1. Executive Summary

**ADeleginator** is an Active Directory security assessment tool that identifies insecure delegation configurations. It wraps the open-source [ADeleg](https://github.com/mtth-bfft/adeleg/) utility (by [@mtth-bfft](https://github.com/mtth-bfft)) to enumerate all delegation entries in a domain, then applies a set of risk-based filtering rules to surface two categories of findings:

1. **Insecure Trustee Delegations** — Permissions granted to overly broad or non-privileged trustees (e.g., `Domain Users`, `Authenticated Users`, `Everyone`, or the current user's non-Tier-0 group memberships) that allow dangerous operations.
2. **Insecure Resource Delegations** — Permissions granted to those same unsafe trustees on critical Tier 0 Active Directory objects (e.g., `Domain Admins`, `Enterprise Admins`, `krbtgt`, `AdminSDHolder`).

By automating ADeleg execution and post-processing, ADeleginator enables Active Directory administrators and security engineers to quickly discover misconfigured or excessive delegations that could be exploited for privilege escalation or lateral movement within a domain.

---

## 2. Purpose & Goals

### Security Problem Addressed

Active Directory environments commonly accumulate delegation entries (Access Control Entries, or ACEs) over time. Many of these entries grant powerful permissions — such as the ability to write all properties, create or delete child objects, or take ownership — to overly broad groups. An attacker who compromises any member of these broad groups can abuse these delegations to escalate privileges, modify critical objects, or gain full domain control.

### Specific Risks Detected

| Risk Category | Description |
|---|---|
| **Insecure Trustee Delegations** | Dangerous permissions (e.g., `owns`, `write all properties`) granted to broadly-scoped trustees such as `Domain Users`, `Authenticated Users`, `Everyone`, or the current operator's non-Tier-0 group memberships. These entries represent attack surface available to any authenticated user or group member. |
| **Insecure Resource Delegations** | The same category of dangerous permissions, but specifically targeting Tier 0 (critical) AD objects. These findings represent a direct path to domain compromise. |

### Relationship to ADeleg

ADeleginator is a **wrapper and companion tool** for [ADeleg](https://github.com/mtth-bfft/adeleg/). It does not perform any Active Directory delegation enumeration itself. However, it does make a small ADSI/LDAP query to resolve the current user's group memberships (via the `memberOf` attribute). Beyond that query, it:

1. **Orchestrates** ADeleg by invoking it with appropriate arguments to produce a CSV delegation report.
2. **Post-processes** the ADeleg output by applying filtering rules to identify findings of interest.
3. **Generates** focused, actionable reports containing only the insecure delegations.

ADeleg itself is an independent, open-source tool written by [@mtth-bfft](https://github.com/mtth-bfft) that queries Active Directory to enumerate all delegation entries (ACEs) and exports them in structured formats.

---

## 3. Prerequisites & Dependencies

### Runtime Environment

| Requirement | Details |
|---|---|
| **Domain-joined machine** | The tool must be run on a Windows machine that is joined to the Active Directory domain being assessed. |
| **Active Directory query permissions** | The executing user must have sufficient permissions to query AD objects and attributes, including the `memberOf` attribute of their own user object. Standard domain user permissions are typically sufficient. |
| **ADSI/LDAP availability** | The tool relies on ADSI (Active Directory Service Interfaces) to query the current user's group memberships via LDAP. The machine must have network connectivity to a domain controller. |
| **Console/terminal environment** | The tool is designed for interactive execution in a console session (it produces color-coded console output). |

### External Dependency: ADeleg

| Property | Details |
|---|---|
| **Executable** | `ADeleg.exe` |
| **Source** | [https://github.com/mtth-bfft/adeleg/releases](https://github.com/mtth-bfft/adeleg/releases) |
| **Required placement** | By default, `ADeleg.exe` must be placed in the **current working directory** (the directory from which the tool is run), since the default path resolves to `.\ADeleg.exe`. Note: the tool's warning message states "place ADeleg.exe in the same folder as this script," but the actual file-existence check uses `.\ADeleg.exe` relative to the current working directory, not relative to the script's location. The `PathToADeleg` input parameter is intended to allow a custom path, but see the **PathToADeleg parameter override** limitation below. |
| **Purpose** | Performs the actual Active Directory delegation enumeration and produces the raw CSV report that ADeleginator post-processes. |

> **Note:** ADeleg is not bundled with ADeleginator. Users must download it separately from the link above.

---

## 4. Input Parameters

ADeleginator accepts two optional input parameters:

| Parameter | Required | Default | Description |
|---|---|---|---|
| **PathToADeleg** | No | `.\ADeleg.exe` (current working directory) | The file system path to the ADeleg executable. If omitted, the tool assumes `ADeleg.exe` is located in the current working directory. |
| **Server** | No | *(none — uses default domain controller)* | Specifies a target domain controller to pass through to ADeleg. When omitted, ADeleg uses its own default domain controller discovery mechanism. |

### Default Behaviors

- **When `PathToADeleg` is omitted:** The tool looks for `ADeleg.exe` in the current working directory (`.\ADeleg.exe`). If not found, the tool displays a warning with download instructions and halts execution.
- **When `Server` is omitted:** The `--server` flag is not passed to ADeleg, allowing ADeleg to target whichever domain controller it discovers by default.

---

## 5. Execution Workflow (Step-by-Step)

The following describes the complete end-to-end execution flow of ADeleginator in language-agnostic terms.

### Step 1: Resolve Current User's Group Memberships

The tool queries Active Directory for the currently logged-in user's `memberOf` attribute using an LDAP/ADSI search filtered by the user's `sAMAccountName`. The returned values are Distinguished Names (DNs) of the form:

```
CN=GroupName,OU=SomeOU,DC=example,DC=com
```

The tool extracts only the **Common Name (CN)** component from each DN — i.e., the text between `CN=` and the first comma — yielding a list of human-readable group names (e.g., `Domain Users`, `IT Admins`).

### Step 2: Build the Unsafe Trustees List

The tool begins with a **baseline set of broadly-scoped, well-known trustees**:

| # | Baseline Unsafe Trustee |
|---|---|
| 1 | `Domain Users` |
| 2 | `Authenticated Users` |
| 3 | `Everyone` |

It then evaluates the current user's group memberships (from Step 1) against the Tier 0 resources list (see Step 3). The check filters the array of group names and returns only those that do **not** match any Tier 0 resource. If the filtered result is non-empty — meaning the user belongs to **at least one** non-Tier-0 group — then the **entire** original list of the user's groups is appended to the unsafe trustees string. This means that even Tier 0 group names the user belongs to will be included in the unsafe trustees list if the user also belongs to any non-Tier-0 group. Only if **every** group the user belongs to is a Tier 0 resource will the append be skipped entirely.

> **Note (all-or-nothing behavior):** This is a known quirk of the current implementation (v0.1). A correct re-implementation should append only the non-Tier-0 groups individually, rather than appending all groups unconditionally.

> **Note (space-join behavior):** In the current implementation, the group array is concatenated to the unsafe trustees regex string using `"|" + $CurrentUserGroups`. Because `$CurrentUserGroups` is an array, PowerShell coerces it to a **space-separated string** (e.g., `|GroupA GroupB GroupC`) rather than inserting `|` between each group. The entire space-joined sequence becomes a **single** regex alternative, so **none** of the individual group names will match unless the trustee field happens to contain the entire verbatim string `GroupA GroupB GroupC`. A correct re-implementation should join the group names with `|` (e.g., `GroupA|GroupB|GroupC`) or append each group as a separate regex alternative.

### Step 3: Define Tier 0 (Critical) Resources

The tool uses a hardcoded list of Active Directory objects considered **Tier 0** — the most sensitive and critical objects in a domain. Any delegation targeting these resources is subject to heightened scrutiny.

| # | Tier 0 Resource |
|---|---|
| 1 | `Account Operators` |
| 2 | `Administrator` |
| 3 | `Administrators` |
| 4 | `AdminSDHolder` |
| 5 | `Backup Operators` |
| 6 | `Cryptographic Operators` |
| 7 | `Distributed COM Users` |
| 8 | `Domain Admins` |
| 9 | `Domain Controllers` |
| 10 | `Domain Controllers (OU)` |
| 11 | `Domain root object` |
| 12 | `DnsAdmins` |
| 13 | `Enterprise Admins` |
| 14 | `GPO linked to Tier Zero container` |
| 15 | `krbtgt` |
| 16 | `Print Operators` |
| 17 | `RODC computer object` |
| 18 | `Schema Admins` |
| 19 | `Server Operators` |
| 20 | `Users (container)` |

### Step 4: Define Unsafe Delegation Types

The tool uses a hardcoded list of delegation detail patterns considered insecure. If a delegation entry's details match any of these patterns, the entry is flagged as potentially dangerous.

| # | Unsafe Delegation Type |
|---|---|
| 1 | `owns` |
| 2 | `write all properties` |
| 3 | `create child objects` |
| 4 | `delete child objects` |
| 5 | `Change the owner` |
| 6 | `add/delete delegations` |
| 7 | `delete` |

### Step 5: Validate the ADeleg Dependency

The tool checks whether the ADeleg executable exists at the resolved path. In the current implementation (v0.1), the `PathToADeleg` parameter is unconditionally overwritten with `.\ADeleg.exe` before this check (see the **PathToADeleg parameter override** limitation), so validation always targets the current working directory regardless of any user-specified path. Validation is performed by testing for the file's existence.

- **If found:** Execution continues.
- **If not found:** The tool displays a warning message instructing the user to download ADeleg from [https://github.com/mtth-bfft/adeleg/releases](https://github.com/mtth-bfft/adeleg/releases) and place it in the same folder, then **halts execution**. (In the current implementation, the halt is performed using a `break` statement outside of any loop or switch, which will cause a runtime error rather than a clean exit. A correct re-implementation should exit gracefully.)

### Step 6: Invoke ADeleg

The tool executes the ADeleg binary with the `--csv` flag to produce a CSV delegation report. The command follows this pattern:

- **Without a server specified:**
  ```
  ADeleg.exe --csv "ADelegReport_<ddMMyyyy>.csv"
  ```
- **With a server specified:**
  ```
  ADeleg.exe --server <server> --csv "ADelegReport_<ddMMyyyy>.csv"
  ```

Where `<ddMMyyyy>` is the current date formatted as two-digit day, two-digit month, and four-digit year with no separators (e.g., `17032026` for 17 March 2026).

Any errors during ADeleg execution are silently caught and suppressed.

### Step 7: Parse the ADeleg Report

The tool reads the generated CSV file (`ADelegReport_<ddMMyyyy>.csv`) and parses it into structured records. Each record contains at minimum the following fields (as column headers in the CSV):

| Field | Description |
|---|---|
| `Trustee` | The security principal (user, group, or computer) granted the delegation. |
| `Trustee Type` | The type of the trustee (e.g., user, group). |
| `Resource` | The Active Directory object to which the delegation applies. |
| `Category` | The type of access control entry — typically `Allow` or `Deny`. |
| `Details` | A human-readable description of the specific permissions granted. |

### Step 8: Identify Insecure Trustee Delegations

The tool iterates over every record in the parsed report and flags entries where **all** of the following conditions are true:

1. The `Trustee` field matches the unsafe trustees list (via pattern matching).
2. The `Category` field matches `Allow` (via pattern matching).
3. The `Details` field matches the unsafe delegation types list (via pattern matching).

Each matching record is captured as a finding with the following output fields: `Trustee`, `TrusteeType`, `Resource`, `Category`, `Delegations` (mapped from the input `Details` field).

### Step 9: Identify Insecure Resource Delegations

The tool iterates over every record in the parsed report and flags entries where **all** of the following conditions are true:

1. The `Trustee` field matches the unsafe trustees list (via pattern matching).
2. The `Resource` field matches the Tier 0 resources list (via pattern matching).
3. The `Category` field matches `Allow` (via pattern matching).
4. The `Details` field matches the unsafe delegation types list (via pattern matching).

Each matching record is captured as a finding with the same output fields as Step 8.

### Step 10: Generate Output Reports

For each detection category:

- **If findings exist:** The tool exports the results to a dedicated CSV file and displays an alert message to the user.
- **If no findings exist:** The tool displays a success message indicating a clean result.

A closing message is displayed upon completion.

---

## 6. Output Artifacts

ADeleginator can produce up to three CSV files during a single execution:

### 6.1 Raw ADeleg Report

| Property | Details |
|---|---|
| **Filename** | `ADelegReport_<ddMMyyyy>.csv` |
| **Example** | `ADelegReport_15012025.csv` |
| **Source** | Generated directly by ADeleg. |
| **Contents** | All delegation entries discovered in the domain. |
| **Schema** | Defined by ADeleg; includes at minimum: `Trustee`, `Trustee Type`, `Resource`, `Category`, `Details`. |

### 6.2 Insecure Trustee Delegation Report

| Property | Details |
|---|---|
| **Filename** | `ADeleg_InsecureTrusteeDelegationReport_<ddMMyyyy>.csv` |
| **Example** | `ADeleg_InsecureTrusteeDelegationReport_15012025.csv` |
| **Source** | Generated by ADeleginator after filtering. |
| **Contents** | Only delegation entries that match the insecure trustee detection rules (Step 8). |
| **Generated when** | At least one insecure trustee delegation is found. Not created if the result is clean. |

### 6.3 Insecure Resource Delegation Report

| Property | Details |
|---|---|
| **Filename** | `ADeleg_InsecureResourceDelegationReport_<ddMMyyyy>.csv` |
| **Example** | `ADeleg_InsecureResourceDelegationReport_15012025.csv` |
| **Source** | Generated by ADeleginator after filtering. |
| **Contents** | Only delegation entries that match the insecure resource detection rules (Step 9). |
| **Generated when** | At least one insecure resource delegation is found. Not created if the result is clean. |

### Output Report Schema

Both filtered reports (trustee and resource) share the same column schema:

| Column | Source Field | Description |
|---|---|---|
| `Trustee` | `Trustee` | The security principal granted the delegation. |
| `TrusteeType` | `Trustee Type` | The type of the trustee (note: the space is removed in the output column name). |
| `Resource` | `Resource` | The AD object to which the delegation applies. |
| `Category` | `Category` | The access type (`Allow`). |
| `Delegations` | `Details` | The specific permissions granted (renamed from `Details` in the raw report). |

> **Note:** The date component `<ddMMyyyy>` in all filenames represents the current date at the time of execution, formatted as two-digit day, two-digit month, and four-digit year with no separators.

---

## 7. Detection Logic & Matching Rules

### Matching Method

All filtering in ADeleginator is performed using **regular expression (pattern) matching**, not exact string comparison. Each list (unsafe trustees, Tier 0 resources, unsafe delegation types) is internally represented as a single pattern string with entries separated by the pipe (`|`) character, which functions as the regex alternation (OR) operator.

For example, the unsafe trustees pattern:

```
Domain Users|Authenticated Users|Everyone
```

matches any field value that **contains** any of the listed substrings. Because regex matching is used (not exact equality), a field value of `DOMAIN\Domain Users` or `Authenticated Users (S-1-5-11)` would also match if those substrings appear anywhere in the value.

### Matching Characteristics

| Characteristic | Behavior |
|---|---|
| **Case sensitivity** | Matching is **case-insensitive**. |
| **Match type** | **Substring/contains** — the pattern need only appear somewhere within the field value, not match the entire value. |
| **Alternation** | Multiple patterns are combined with `|` (pipe), which is the regex alternation operator, meaning any one alternative matching is sufficient. |
| **Special characters** | Patterns such as `add/delete delegations` contain the `/` character and `Domain Controllers (OU)` contains parentheses. In the .NET regex engine, unescaped parentheses `(` and `)` create **capture groups** rather than matching literal parentheses. This means a pattern like `Domain Controllers (OU)` is interpreted as `Domain Controllers ` followed by a capture group containing `OU` — this will match the string `Domain Controllers OU` (without parentheses) but will **not** match the literal string `Domain Controllers (OU)` (with parentheses), because the capture group tries to match `O` at the position where `(` appears. In the current pattern list, the `Domain Controllers (OU)` alternative is effectively redundant because the separate `Domain Controllers` alternative already matches any string containing "Domain Controllers" (including `Domain Controllers (OU)`). However, `Users (container)` has no shorter alternative — there is no standalone `Users` entry — so this pattern will fail to match a resource literally named `Users (container)`, creating a **false-negative gap**. A correct re-implementation targeting .NET should escape regex metacharacters in patterns (e.g., `Domain Controllers \(OU\)` and `Users \(container\)`) to ensure literal parentheses are matched reliably. Implementations targeting other platforms should apply the equivalent escaping for their regex engine. |

### Insecure Trustee Delegation Rules

A record is flagged as an insecure trustee delegation when **all** of the following conditions evaluate to true:

```
    Trustee  MATCHES  <Unsafe Trustees Pattern>
AND Category MATCHES  "Allow"
AND Details  MATCHES  <Unsafe Delegation Types Pattern>
```

### Insecure Resource Delegation Rules

A record is flagged as an insecure resource delegation when **all** of the following conditions evaluate to true:

```
    Trustee  MATCHES  <Unsafe Trustees Pattern>
AND Resource MATCHES  <Tier 0 Resources Pattern>
AND Category MATCHES  "Allow"
AND Details  MATCHES  <Unsafe Delegation Types Pattern>
```

### Key Distinction Between the Two Detection Types

- **Trustee detection** does not consider the `Resource` field — it flags any dangerous permission granted to an unsafe trustee, regardless of what object the permission applies to.
- **Resource detection** adds an additional constraint: the `Resource` must also be a Tier 0 object, meaning only delegations affecting the most critical AD objects are flagged.

---

## 8. Console Output & User Feedback

ADeleginator provides structured console output with color-coded severity indicators throughout execution. The following table documents the messages and their associated severity levels.

### Startup Banner

Upon launch, the tool displays an ASCII art banner featuring the tool name, author credit (`Spencer Alessi @techspence`), version number (`v0.1`), and decorative artwork. This banner is purely informational.

### Runtime Messages

| Phase | Message | Severity | Color |
|---|---|---|---|
| **Dependency validation** | `ADeleg not found in the current directory. Download and place ADeleg.exe in the same folder as this script, then run ADeleginator again.` | Warning | Yellow |
| **Dependency validation** | `You can download ADeleg from here: https://github.com/mtth-bfft/adeleg/releases` | Warning | Yellow |
| **Report generation** | `[i] Running ADeleg and creating ADelegReport_<ddMMyyyy>.csv` | Informational | Default |
| **Analysis** | `[i] Checking for insecure trustee/resource delegations...` | Informational | Default |
| **Trustee results (findings)** | `[!] Insecure trustee delegations found. Exporting report: ADeleg_InsecureTrusteeDelegationReport_<ddMMyyyy>.csv` | Alert | Red |
| **Trustee results (clean)** | `[+] No insecure trustee delegations found. Eureka!` | Success | Green |
| **Resource results (findings)** | `[!] Insecure resource delegations found. Exporting report: ADeleg_InsecureResourceDelegationReport_<ddMMyyyy>.csv` | Alert | Red |
| **Resource results (clean)** | `[+] No insecure resource delegations found. Eureka!` | Success | Green |
| **Completion** | `Thank you for using ADeleginator. Godspeed! :O)` | Informational | Default |

> **Note:** The two dependency-validation messages are emitted via `Write-Warning`. PowerShell automatically prepends a `WARNING:` prefix to the output (e.g., `WARNING: ADeleg not found in the current directory...`), so the actual console text will include this prefix even though it is not part of the message string itself.

### Message Prefix Conventions

| Prefix | Meaning |
|---|---|
| `[i]` | Informational — status update or progress indicator. |
| `[+]` | Success — a clean result with no findings. |
| `[!]` | Alert — findings detected that require attention. |

---

## 9. Limitations & Assumptions

### Known Limitations

| Limitation | Details |
|---|---|
| **Hardcoded Tier 0 resources list** | The list of Tier 0 (critical) AD objects is hardcoded and cannot be customized by the user without modifying the tool's source. Organizations with non-standard administrative groups or custom privileged objects will need to manually adjust the list. |
| **Hardcoded unsafe delegation types** | The set of delegation patterns considered insecure is hardcoded. Emerging or organization-specific dangerous permission types are not detected unless the source is modified. |
| **Hardcoded baseline unsafe trustees** | The three baseline unsafe trustees (`Domain Users`, `Authenticated Users`, `Everyone`) are hardcoded. Additional broad groups specific to an environment must be added manually. |
| **Regex pattern matching nuances** | Because filtering uses regex substring matching rather than exact string comparison, there is a possibility of false positives. For example, the pattern `delete` will also match `delete child objects` and any other string containing the word "delete". Similarly, `Administrator` will match `Administrators`. |
| **Unescaped regex metacharacters** | Some patterns contain regex metacharacters (e.g., parentheses in `Domain Controllers (OU)` and `Users (container)`). In .NET's regex engine, unescaped parentheses create capture groups rather than matching literal characters. The `Domain Controllers (OU)` alternative does not cause a practical gap because the separate `Domain Controllers` alternative (without parentheses) already covers it. However, `Users (container)` has **no shorter alternative** in the pattern list, so it will fail to match a resource literally named `Users (container)` — this is a real false-negative risk. A re-implementation targeting .NET should escape these characters (e.g., `\(` and `\)`) to ensure literal parentheses are matched; implementations targeting other platforms should apply equivalent escaping for their regex engine. |
| **Single output format** | The tool only produces CSV output. There is no built-in support for JSON, HTML, or other report formats. |
| **Silent error suppression during ADeleg execution** | If ADeleg fails to execute or encounters an error, the error output from ADeleg is silently suppressed — the user will not see the root cause. However, the failure will surface later when the tool attempts to import the missing or incomplete CSV report (e.g., as a file-not-found or parse error), so the user will eventually see an error, but without the underlying ADeleg failure context. |
| **No validation of ADeleg CSV schema** | The tool does not validate that the CSV produced by ADeleg contains the expected column headers. If ADeleg's output format changes, the tool may fail or produce incorrect results without a clear error message. |
| **PathToADeleg parameter override** | In the current implementation (v0.1), the `PathToADeleg` parameter is accepted but then unconditionally overwritten with the default value (`.\ADeleg.exe`), effectively making the parameter non-functional. This is a known defect in the current version. |
| **Group membership evaluation** | The current user's group names are checked against the Tier 0 resources pattern using an array filter. The filter returns only the non-matching (non-Tier-0) groups. If **at least one** non-Tier-0 group exists, the condition evaluates to true and the tool appends **all** of the user's groups (including any Tier 0 groups) to the unsafe trustees list. Only if **every** group the user belongs to is a Tier 0 resource will none be appended. A correct re-implementation should append only the non-Tier-0 groups individually. |
| **Group array space-join** | When the current user's groups are appended to the unsafe trustees regex string, the array is concatenated using `"|" + $CurrentUserGroups`. Because `$CurrentUserGroups` is an array, PowerShell coerces it to a space-separated string (e.g., `|GroupA GroupB GroupC`). The entire space-joined sequence becomes a single regex alternative, so none of the individual group names will match unless the trustee field contains the entire verbatim string. A correct re-implementation should join group names with `|` (e.g., `GroupA|GroupB|GroupC`). |

### Assumptions

| Assumption | Details |
|---|---|
| **Interactive console execution** | The tool is designed to be run interactively in a console/terminal session by a human operator. It relies on color-coded console output for feedback. |
| **Domain-joined Windows machine** | The tool assumes it is running on a Windows system joined to the Active Directory domain under assessment, with ADSI/LDAP connectivity to a domain controller. |
| **Standard domain user context** | The tool assumes the executing user has at least standard domain user read permissions to query AD objects and their own `memberOf` attribute. |
| **ADeleg CSV format stability** | The tool assumes ADeleg produces a CSV with specific column headers (`Trustee`, `Trustee Type`, `Resource`, `Category`, `Details`). Changes to ADeleg's output format would break the tool. |
| **Current working directory** | Output files are written to the current working directory. The user is expected to run the tool from an appropriate writable location. |

---

## 10. Glossary

| Term | Definition |
|---|---|
| **ACE (Access Control Entry)** | A single entry in an access control list that grants or denies a specific permission to a specific security principal (trustee) on a specific object (resource). |
| **ACL (Access Control List)** | An ordered collection of ACEs that defines the permissions on an Active Directory object. Each AD object has a Discretionary ACL (DACL) controlling access permissions. |
| **Active Directory (AD)** | Microsoft's directory service for Windows domain networks, providing authentication, authorization, and a hierarchical database of objects such as users, groups, computers, and organizational units. |
| **AdminSDHolder** | A special Active Directory container object whose ACL is used as a template. The Security Descriptor Propagator (SDProp) process periodically applies AdminSDHolder's ACL to all protected (Tier 0) accounts and groups, overriding any manual ACL changes. Insecure ACEs on AdminSDHolder propagate to all protected accounts. |
| **ADSI (Active Directory Service Interfaces)** | A set of COM interfaces used to access directory services, including Active Directory, from Windows applications. ADeleginator uses ADSI to query the current user's group memberships. |
| **ADeleg** | An open-source tool by [@mtth-bfft](https://github.com/mtth-bfft) that enumerates delegation entries (ACEs) in an Active Directory domain and exports them in structured formats (CSV, JSON). ADeleginator wraps ADeleg to provide automated risk filtering. |
| **CN (Common Name)** | An LDAP attribute representing the human-readable name of an object. In a Distinguished Name like `CN=Domain Admins,CN=Users,DC=example,DC=com`, the CN is `Domain Admins`. |
| **Delegation** | In the context of Active Directory, a delegation refers to the assignment of specific permissions on AD objects to security principals, allowing them to perform administrative tasks without full domain administrator privileges. |
| **Distinguished Name (DN)** | The full LDAP path to an object in Active Directory, uniquely identifying it within the directory tree (e.g., `CN=JohnDoe,OU=Users,DC=example,DC=com`). |
| **Domain Controller (DC)** | A server that responds to authentication requests and enforces security policies within a Windows Active Directory domain. ADeleg queries domain controllers to enumerate delegation entries. |
| **krbtgt** | The Key Distribution Center (KDC) service account in Active Directory, used to encrypt and sign all Kerberos tickets. Compromise of the `krbtgt` account enables an attacker to forge arbitrary Kerberos tickets (Golden Ticket attack), granting unrestricted access to the domain. |
| **LDAP (Lightweight Directory Access Protocol)** | An application protocol for accessing and modifying directory services, including Active Directory. LDAP queries are used to search for objects and retrieve their attributes. |
| **memberOf** | An Active Directory attribute on user and group objects that lists the Distinguished Names of groups to which the object belongs. |
| **sAMAccountName** | The pre-Windows 2000 logon name for a user or group in Active Directory (e.g., `jdoe`). Used as the search filter when resolving the current user's group memberships. |
| **Tier 0** | The highest tier in the Microsoft tiered administration model for Active Directory. Tier 0 assets are those whose compromise would grant full control over the directory — including domain controllers, domain admin accounts, the `krbtgt` account, and other critical objects. |
| **Trustee** | The security principal (user, group, computer, or other entity) to whom permissions are granted or denied in an Access Control Entry. In the context of ADeleginator, "unsafe trustees" are broadly-scoped groups or accounts whose delegation entries pose a security risk. |
