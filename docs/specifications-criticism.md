# Specification Criticism — `specifications-reference.md`

This document provides functional and technical criticism of the specification defined in `docs/specifications-reference.md`. The criticism is written from the perspective of producing a revised specification that will be used to write a net-new, from-scratch tool in **.NET Framework 2.0** (for intentional backward compatibility), running exclusively from the **console** with output to **CSV or similar text files** (no graphical user interface).

---

## Table of Contents

1. [Platform and Technology Coupling](#1-platform-and-technology-coupling)
2. [LDAP Access Layer](#2-ldap-access-layer)
3. [.NET Framework 2.0 Constraints and Implications](#3-net-framework-20-constraints-and-implications)
4. [Security Descriptor Parsing](#4-security-descriptor-parsing)
5. [SID Resolution Strategy](#5-sid-resolution-strategy)
6. [Filtering Logic Concerns](#6-filtering-logic-concerns)
7. [CSV Output and Formatting](#7-csv-output-and-formatting)
8. [Delegation and Template System](#8-delegation-and-template-system)
9. [Error Handling and Fault Tolerance](#9-error-handling-and-fault-tolerance)
10. [Performance and Scalability](#10-performance-and-scalability)
11. [Missing or Underspecified Behaviors](#11-missing-or-underspecified-behaviors)
12. [Correctness and Edge Case Concerns](#12-correctness-and-edge-case-concerns)
13. [Usability and Operational Concerns](#13-usability-and-operational-concerns)
14. [Security Considerations](#14-security-considerations)
15. [Assumptions That Should Be Re-evaluated](#15-assumptions-that-should-be-re-evaluated)

---

## 1. Platform and Technology Coupling

### 1.1. Rust-Specific Implementation Details Embedded in the Spec

The specification repeatedly references Rust-specific constructs (e.g., `RefCell<HashMap>`, `Iterator` trait, `LdapSearch` struct, `LdapEntry`, crate names like `authz` and `winldap`). A revised spec should describe behaviors and data flows in language-agnostic terms rather than prescribing implementation structures. Struct field names like `resolved_sid_to_dn`, enum variants like `PrincipalType`, and the `ace_equivalent()` function are implementation details that should be described as abstract behaviors (e.g., "a SID resolution cache," "a principal type classification," "an ACE comparison function").

### 1.2. Windows LDAP C API Specifics

The spec lists specific C API functions (`ldap_initW`, `ldap_connect`, `ldap_bind_sW`, `ldap_search_ext_sW`, `ldap_create_page_controlW`, `ldap_parse_page_controlW`) from `wldap32.dll`. While .NET Framework 2.0 can P/Invoke these, it would be far more natural (and less error-prone) to use `System.DirectoryServices` (`DirectoryEntry`, `DirectorySearcher`) or `System.DirectoryServices.Protocols` (`LdapConnection`, `SearchRequest`). The revised spec should define required behaviors (e.g., "perform a paged subtree search," "bind with Negotiate authentication") without mandating a specific API surface.

### 1.3. Embedded Compile-Time Resources

The spec refers to `builtin_delegations.json` being "embedded at compile time." In .NET Framework 2.0, the equivalent mechanism would be an embedded resource or an external file distributed alongside the executable. The revised spec should describe the logical requirement (a set of built-in delegation definitions shipped with the tool) without prescribing the delivery mechanism.

### 1.4. Dynamic Library Loading

The spec mentions dynamically loading `LookupAccountSidLocalW` from `sechost.dll` via `GetProcAddress`. In .NET Framework 2.0, `System.Security.Principal.SecurityIdentifier.Translate()` or P/Invoke with `LookupAccountSid` would be more natural. The revised spec should describe the SID-to-name resolution requirement without mandating a specific OS API call mechanism.

### 1.5. .NET Framework Native AD Objects Could Eliminate Granular LDAP Control

The spec describes Active Directory access exclusively through low-level LDAP operations: explicit connection handles, bind calls, paged search controls, referral option flags, SD flags controls, port numbers, and timeout values. If the .NET Framework rewrite uses `System.DirectoryServices` (`DirectoryEntry`, `DirectorySearcher`) or `System.DirectoryServices.ActiveDirectory` (`Domain`, `Forest`, `ActiveDirectorySchema`), many of these LDAP-level concerns are abstracted away entirely by the framework:

- **DC discovery and connection**: `Domain.GetCurrentDomain()` and `Forest.GetCurrentForest()` locate domain controllers automatically, eliminating the need for `--server` and `--port` CLI options in most cases.
- **Paging**: `DirectorySearcher.PageSize` handles paged searches transparently — there is no need to manually create page controls or parse cookies.
- **Referrals**: `DirectorySearcher.ReferralChasing` provides a simple enum-based configuration rather than raw `ldap_set_option` calls.
- **Authentication**: `DirectoryEntry` constructors accept credentials and automatically use Negotiate/SSPI when none are provided, removing the need for `SEC_WINNT_AUTH_IDENTITY_W` structures.
- **Security descriptors**: `DirectoryEntry.ObjectSecurity` returns an `ActiveDirectorySecurity` object with managed ACE access via `GetAccessRules()`, eliminating raw binary parsing.
- **SD flags control**: `DirectorySearcher.SecurityMasks` provides a managed interface for specifying which SD components to retrieve (Owner, DACL, SACL, Group).
- **Timeouts**: `DirectorySearcher.ClientTimeout` and `DirectorySearcher.ServerTimeLimit` replace raw `LDAP_TIMEVAL` structs.

The revised spec should seriously consider specifying behaviors at this higher abstraction level rather than at the LDAP protocol level. This would make the spec simpler, more naturally aligned with .NET Framework, and would avoid overspecifying implementation mechanics that the framework already handles. The remaining LDAP-level sections of this criticism (Section 2) may become partially or wholly moot if this approach is adopted.

---

## 2. LDAP Access Layer

> **Note:** As discussed in Section 1.5, many of these LDAP-level concerns may be rendered moot if the revised spec adopts .NET Framework native AD objects (`System.DirectoryServices`) instead of specifying raw LDAP operations. The criticisms below remain relevant if the spec retains LDAP-level granularity, or as fallback considerations for edge cases that .NET Framework abstractions may not cover.

### 2.1. Connection Timeout Semantics Are Unclear

The spec states a 2-second `LDAP_TIMEVAL` for `ldap_connect`, but then immediately adds a caveat that the "overall connection attempt may exceed 2 seconds due to underlying DNS/mDNS/NBNS resolution layers." This is confusing. The revised spec should define the desired timeout behavior in terms of the overall user-visible behavior: what is the maximum acceptable time before the tool reports a connection failure? Should DNS resolution timeout be separately configurable?

### 2.2. Referral Disabling Rationale is Good but Incomplete

The spec correctly disables referrals to prevent hanging when running outside the domain, but does not discuss the implications: disabling referrals means the tool will not automatically follow cross-domain references within the same forest. If a naming context references objects in another domain, those objects will not be resolved — the LDAP client will receive referral responses that go unfollowed, which depending on the API layer may surface as errors or simply as missing results. The revised spec should explicitly state whether cross-domain references within a forest should be followed (and if so, how to handle authentication for them), or whether unfollowed referrals are acceptable and how they should be reported.

### 2.3. Page Size of 999 Should Be Justified or Configurable

The page size of 999 is stated as a fixed constant without justification. The default AD MaxPageSize policy is 1000. Using 999 presumably stays under this limit, but the spec does not explain this. The revised spec should either justify this choice or make it configurable. Some environments have custom MaxPageSize policies, and a fixed value of 999 may not be optimal everywhere.

### 2.4. No Support for LDAPS or StartTLS

The spec does not mention encrypted LDAP connections (LDAPS on port 636 or StartTLS). While Negotiate/SPNEGO provides signing and sealing by default, in environments that require channel binding or TLS-only policies, this could be a limitation. The revised spec should explicitly state whether encrypted transport is supported and, if so, how (port selection, certificate validation, etc.).

### 2.5. No Specification for Connection Endpoints or Alternative Ports

The spec does not document how the LDAP connection endpoint is determined — it does not specify a default port, CLI options for overriding the port, or support for LDAPS (port 636) or Global Catalog (ports 3268/3269). The existing implementation supports `--port` (defaulting to 389), but this is not captured in the spec. The revised spec should clarify what connection endpoints are supported and what protocol differences alternative ports imply (e.g., Global Catalog returns partial attribute sets). However, see Section 1.5 — if the revised spec uses .NET Framework native AD objects, port selection and protocol handling may be abstracted away entirely.

---

## 3. .NET Framework 2.0 Constraints and Implications

### 3.1. No LINQ

.NET Framework 2.0 predates LINQ (introduced in .NET 3.5). Any spec behaviors described in terms of filtering, projection, or aggregation over collections must be implementable with explicit `for`/`foreach` loops and manual collection manipulation. This is not a spec deficiency per se, but the revised spec should avoid describing behaviors in a way that implicitly assumes functional-style collection processing (e.g., "filter the DACL ACEs through `is_ace_interesting()`" is fine since it describes a filter predicate, but more complex pipeline descriptions should be broken into discrete steps).

### 3.2. Limited Generic Collections

.NET Framework 2.0 has `Dictionary<TKey, TValue>`, `List<T>`, and `Queue<T>`, but lacks `HashSet<T>` (introduced in .NET 3.5), `ConcurrentDictionary` (introduced in .NET 4.0), and other modern collections. The spec's use of `HashMap` and set-based operations should be described in terms of behavior, not data structure. For example, the SID resolution cache could be described as "a key-value mapping from SID to resolved name" rather than mandating a specific collection type.

### 3.3. No Async/Await

.NET Framework 2.0 has no `async`/`await` support. All operations will be synchronous, which is actually consistent with the current spec (it describes single-threaded, synchronous processing). However, if a future revision considers parallelization (which the current spec lists as a limitation), the .NET Framework 2.0 constraint makes this significantly harder, requiring manual threading with `System.Threading.Thread` or `ThreadPool`.

### 3.4. String Handling

.NET Framework 2.0 has `StringBuilder` but lacks `string.IsNullOrWhiteSpace()` (introduced in .NET 4.0) and other modern string utilities. The spec should not rely on specific string manipulation APIs, but rather describe the string-processing requirements clearly enough that they can be implemented with basic string operations.

### 3.5. Security Descriptor API Availability

.NET Framework 2.0 includes `System.Security.AccessControl` and `System.DirectoryServices`, which provide managed access to security descriptors. However, the class `ActiveDirectorySecurity` and its `GetAccessRules()` method are available in .NET Framework 2.0, making managed SD parsing possible without P/Invoke. The revised spec should describe the parsing requirements in terms of what information is needed (owner, DACL, individual ACEs with their types, flags, access masks, and object GUIDs) without mandating raw binary parsing via Windows API calls.

### 3.6. JSON Parsing

.NET Framework 2.0 does not include a built-in JSON parser. `System.Text.Json` arrived in .NET Core 3.0. `System.Web.Script.Serialization.JavaScriptSerializer` is only available when referencing `System.Web.Extensions`, which was part of ASP.NET AJAX Extensions and may not be present in all .NET Framework 2.0 installations.

The revised spec should address this as a design decision. Options include: specifying a JSON format simple enough for a hand-written parser, using XML instead (natively supported in .NET Framework 2.0 via `System.Xml`), or explicitly requiring a third-party JSON library (e.g., Newtonsoft.Json, whose early versions supported .NET Framework 2.0).

---

## 4. Security Descriptor Parsing

### 4.1. Binary Parsing vs. Managed API

The spec describes parsing security descriptors from raw binary blobs using Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorControl`, `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, etc.) and parsing ACEs byte-by-byte with `GetAce`. In .NET Framework 2.0, `System.DirectoryServices` returns security descriptors as `ActiveDirectorySecurity` objects (a subclass of `ObjectSecurity`) which provide managed access to ACEs through `GetAccessRules()` and `GetAuditRules()`. Using these managed APIs would be safer and more idiomatic. The revised spec should describe the information to extract without mandating low-level binary parsing.

### 4.2. SDDL Parsing for Schema Defaults

The spec mentions parsing SDDL strings from schema `defaultSecurityDescriptor` attributes using `ConvertStringSecurityDescriptorToSecurityDescriptorW`. In .NET Framework 2.0, the `RawSecurityDescriptor` class (in `System.Security.AccessControl`) can parse SDDL strings via its constructor `RawSecurityDescriptor(string)`. The revised spec should describe the requirement (parse SDDL strings into structured security descriptors) without mandating a specific API.

### 4.3. Callback ACE Handling is Underspecified

The spec acknowledges that callback ACE conditional expressions are not evaluated, but the spec does not clearly state what should happen with these ACEs in the output. Are they reported with a warning that the condition was not evaluated? Are they treated identically to non-callback ACEs? This ambiguity should be resolved in the revised spec.

### 4.4. ACE Type Coverage

The spec lists 13 ACE types that are handled, but does not mention `ACCESS_ALLOWED_COMPOUND_ACE_TYPE` (type 4), `SYSTEM_ALARM_ACE_TYPE` (type 3), `SYSTEM_ALARM_OBJECT_ACE_TYPE` (type 8), or `SYSTEM_ALARM_CALLBACK_ACE_TYPE`/`SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE`. While these are rarely encountered, the spec should explicitly state how unknown or unsupported ACE types are handled — are they silently skipped, logged as warnings, or treated as errors?

---

## 5. SID Resolution Strategy

### 5.1. Resolution Order and Cache Semantics Are Overly Complex

Section 7 of the spec describes a multi-step SID resolution strategy with nuanced cache population rules that differ based on whether a SID is domain-specific or not. The cache is populated from three different paths (main scan, local resolution, LDAP lookup) with different overwrite semantics for each. This complexity is a source of bugs and is difficult to test. The revised spec should simplify this by defining a clear, unambiguous resolution priority:

1. Cache lookup
2. Well-known SID table (a static mapping of common SIDs to names)
3. LDAP lookup via SID-based DN
4. Local API lookup (e.g., `LookupAccountSid`)
5. Raw SID string as fallback

The cache should have simple "first write wins" or "last write wins" semantics, not the current mixed approach.

### 5.2. `LookupAccountSidLocalW` May Not Be Available in All Contexts

The spec relies on `LookupAccountSidLocalW` for resolving well-known SIDs. In .NET Framework 2.0, the equivalent is `SecurityIdentifier.Translate(typeof(NTAccount))`. However, this may fail in cross-forest or workgroup scenarios. The revised spec should define the expected behavior when local SID resolution is unavailable (e.g., when running the tool on a non-domain-joined machine or in a cross-forest context).

### 5.3. Cache Field Name is Misleading

The spec itself notes that `resolved_sid_to_dn` stores either a DN or a `DOMAIN\Username` string, which makes the name misleading. The revised spec should define a clear "resolved SID display name" concept that can be either a DN or a `DOMAIN\Username` format, and name it accordingly.

### 5.4. Principal Type Resolution Has Gaps

The spec maps `objectClass` values and `SID_NAME_USE` values to four categories: `User`, `Group`, `Computer`, and `External`. This mapping has gaps:

- `managedServiceAccount` and `groupManagedServiceAccount` (`msDS-GroupManagedServiceAccount`) are not mentioned. These inherit from `computer` or `user` depending on the implementation, but the spec should clarify.
- `foreignSecurityPrincipal` objects will map to `External` even when they represent known groups from trusted domains, which may be confusing.
- `inetOrgPerson` inherits from `user` and would correctly map to `User` only if the `objectClass` ordering is reliable (most-specific-last). The spec should explicitly state this assumption.

---

## 6. Filtering Logic Concerns

### 6.1. The `OBJECT_INHERIT_ACE` Claim is Technically Incorrect

The spec states: "there is no 'object' in Active Directory, only containers." While this is broadly true for the majority of AD objects, leaf objects do exist in AD (e.g., individual DNS records in AD-integrated DNS zones, certain system objects). The `OBJECT_INHERIT_ACE` flag is not entirely meaningless in AD. The revised spec should acknowledge this nuance and document the decision to ignore this flag as an intentional simplification, rather than stating it as a fact.

### 6.2. Schema Default ACE Matching May Produce False Negatives

The spec states that ACEs matching schema defaults are excluded. However, an administrator may intentionally set an explicit ACE that happens to match a schema default (e.g., to ensure a specific permission persists even if the schema default changes). Excluding these ACEs means the tool will not report them, which could hide intentional configurations. The revised spec should discuss this trade-off and consider whether a flag (similar to `--show-builtin`) should expose these matches.

### 6.3. Ignored Trustee List is Hardcoded and Inflexible

The list of ignored trustee SIDs (SELF, Local System, BUILTIN\Administrators, etc.) is hardcoded. In some environments, administrators may want to see ACEs for these principals (e.g., to audit Account Operators' permissions, which are a known attack vector). The revised spec should consider making this list configurable, or at minimum provide a `--show-all-trustees` flag.

### 6.4. Account Operators and Print Operators Should Not Be Suppressed by Default

The spec suppresses ACEs for Account Operators (`S-1-5-32-548`), Server Operators (`S-1-5-32-549`), Print Operators (`S-1-5-32-550`), and Backup Operators (`S-1-5-32-551`) by default. These groups are well-known attack vectors in Active Directory. Security auditors often specifically want to see what these groups can do. Suppressing them by default could give a false sense of security. The revised spec should either remove these from the default suppression list or make suppression opt-in.

### 6.5. Read-Only Access Rights Masking Could Hide Write+Read Combined ACEs

The spec masks out read-only rights (`READ_CONTROL`, `ACTRL_DS_LIST`, `DS_LIST_OBJECT`, `DS_READ_PROP`) before comparing access masks. While this correctly focuses on write/modify permissions, it means the output may not accurately reflect the full scope of an ACE. If an ACE grants both `DS_WRITE_PROP` and `DS_READ_PROP`, the output will show only `DS_WRITE_PROP`. The revised spec should clarify whether the output should reflect the masked or unmasked access rights, and whether a "raw" mode should show the full mask.

### 6.6. "Delete Protection" Deny ACE Suppression is Overly Broad

The spec suppresses deny ACEs for `Everyone` that deny `DELETE`, `DS_DELETE_CHILD`, and/or `DS_DELETE_TREE`. However, this suppression does not verify that the ACE only denies these rights — it checks if these rights are present but there could also be other denied rights in the same ACE. The revised spec should clarify whether the suppression applies only to ACEs that deny exclusively these rights, or also to ACEs that deny these rights among others.

### 6.7. AdminSDHolder Matching Does Not Account for Stale adminCount

The spec excludes AdminSDHolder-matching ACEs for objects with `adminCount != 0`. However, `adminCount` is notoriously stale in AD — it is set when an object is added to a protected group but not always cleared when the object is removed. This means formerly-protected objects that still have `adminCount=1` but are no longer in a protected group will have their ACEs incorrectly filtered. The revised spec should acknowledge this limitation and consider whether additional validation (e.g., checking actual group membership) is warranted.

---

## 7. CSV Output and Formatting

### 7.1. Non-Deterministic Output Order is a Significant Limitation

The spec explicitly states that CSV output order depends on `HashMap` iteration order and is non-deterministic. For a tool intended for auditing and compliance, this makes diff-based change tracking between runs impossible. The revised spec should mandate a deterministic output order. A natural sort order would be: primary sort by Resource (DN), secondary sort by Category, tertiary sort by Trustee. This is critical for operational use.

### 7.2. CSV Schema is Too Narrow

The 5-column CSV schema (Resource, Trustee, Trustee type, Category, Details) packs too much information into the free-text "Details" column. This makes it difficult to programmatically process the output. The revised spec should consider additional structured columns:

- **Access mask** (numeric or symbolic) — for programmatic filtering
- **Object type GUID** — for correlation with schema
- **Inherited object type GUID** — for understanding scope
- **Allow/Deny** — currently embedded in the Category column
- **Delegation name** — currently embedded in the Details column
- **Raw SID** — useful for programmatic correlation even when a resolved name is available

### 7.3. No Header Row is Specified

The spec does not explicitly state whether the CSV includes a header row. RFC 4180 allows but does not require a header. The revised spec should mandate a header row for usability.

### 7.4. .NET Framework 2.0 CSV Writing

.NET Framework 2.0 does not have a built-in CSV library. The spec references the Rust `csv` crate for RFC 4180 compliance. The revised spec should either require RFC 4180 compliance (which can be achieved with a simple manual implementation in .NET Framework 2.0 — proper quoting of fields containing commas, double-quotes, and newlines) or specify a simpler escaping convention. Given that DNs can contain commas, proper CSV quoting is essential.

### 7.5. UTF-8 Encoding With or Without BOM

The spec states UTF-8 encoding but does not mention a Byte Order Mark (BOM). Many Windows tools (including Excel, which is a common consumer of CSV files) handle UTF-8 CSV files better when a BOM is present. The revised spec should explicitly state whether a BOM should be included, given that the target audience likely uses Windows tools to consume the output.

### 7.6. Multiple CSV Output Files Should Be Considered

The current spec produces a single CSV file containing all finding types (owners, warnings, ACEs, delegations). For large environments, this could produce very large files. The revised spec should consider whether the tool should support outputting multiple CSV files (e.g., one per category, one per naming context) or at minimum support filtering output by category.

### 7.7. The `--csv -` (Stdout) Option Should Coexist with Console Logging

The spec mentions that `--csv -` writes CSV to stdout. However, the tool also writes diagnostic messages (like the unreadable SD warning count) to stderr. The revised spec should clearly define the separation between stdout (data output) and stderr (diagnostic/progress messages) to ensure they can be cleanly separated when using pipe redirection.

---

## 8. Delegation and Template System

### 8.1. JSON Format is Problematic for .NET Framework 2.0

As noted in Section 3.6, .NET Framework 2.0 lacks native JSON support. The current delegation and template format uses JSON. The revised spec should either:

- Adopt XML format (natively supported in .NET Framework 2.0 via `System.Xml`)
- Explicitly require a specific JSON library and version
- Define a simpler text-based format (e.g., INI-style, CSV-based)

### 8.2. Template System is Underspecified

The `templates.json` file defines delegation templates with `applies_to` filters and `rights` arrays, but the spec does not fully describe:

- How `applies_to.any_instance_of` is evaluated — does the object's most-specific class need to match, or any class in the chain?
- What happens when a template references a class name that does not exist in the schema
- Whether template names must be unique and what happens on collision
- How template versioning works — what if a built-in template is updated in a new version of the tool?

### 8.3. Delegation Location Wildcards Are Limited

The spec describes wildcard patterns for delegation locations (`DC=*`, `CN=Configuration,DC=*`, etc.), but these are hardcoded patterns, not true wildcards. The revised spec should either formalize the supported patterns as a closed set or introduce a proper pattern-matching syntax (e.g., allowing arbitrary DN component wildcards).

### 8.4. Delegation Matching is One-Directional

The spec describes matching orphan ACEs against expected delegation ACEs, but does not describe what happens when an ACE matches a delegation but with additional rights. For example, if a delegation expects `WRITE_PROP` for attribute X, but the actual ACE grants `WRITE_PROP | DELETE` for attribute X, is this a match? A partial match? The revised spec should clarify the matching semantics for superset/subset access masks.

### 8.5. `access_mask` in Delegation/Template Definitions Uses Magic Numbers

The spec describes delegation and template definitions that use raw numeric `access_mask` values (the spec itself uses values like `48`, `8`, and `256` for `validAccesses` in LDAP filters, and the delegation JSON format uses numeric `access_mask` fields). Raw numeric access masks are opaque and error-prone for human authors. The revised spec should either define symbolic constants for these values (mirroring the human-readable names in Section 8's access mask mapping table) or require the template/delegation format to use symbolic names that the tool resolves at load time.

---

## 9. Error Handling and Fault Tolerance

### 9.1. Exit Code 1 for All Errors is Insufficient

The spec describes a single exit code (1) for all error conditions. For a console tool, differentiated exit codes would be far more useful for scripting and automation:

- 0: Success (no issues found or findings exported to CSV)
- 1: General/unexpected error
- 2: Connection/authentication failure
- 3: Input file parsing error (templates, delegations)
- 4: Output file error (cannot write CSV)

### 9.2. Error Counter Message is Misleading

The spec acknowledges that the `warning_unreadable_count` message says "security descriptors could not be read" but actually counts all per-location processing errors (including missing `objectClass` and unparseable SDDL). The revised spec should fix this messaging inconsistency.

### 9.3. Panic on Empty `objectClass` is Unacceptable

The spec states that an object with a present but empty `objectClass` value list causes a panic (via `.pop().expect(...)`). While this may be "impossible" in a valid AD, network errors, proxying LDAP servers, or AD corruption could cause this condition. The revised spec should require graceful handling (log an error, skip the object, continue scanning).

### 9.4. Search-Level Error Aborts Entire Run

The spec states that a search-level LDAP error during `get_explicit_aces()` "aborts scanning for that entire naming context (and currently the entire run)." This is too aggressive. The revised spec should define retry behavior for transient errors and allow the tool to continue with remaining naming contexts if one fails. At minimum, the tool should report which naming contexts were successfully scanned and which failed.

### 9.5. No Progress Reporting for Long Scans

The spec does not define any progress reporting mechanism. In large forests with millions of objects, scanning can take a very long time. The revised spec should define a progress reporting mechanism (e.g., periodic messages to stderr showing objects processed, current naming context, elapsed time, estimated completion).

---

## 10. Performance and Scalability

### 10.1. Full Subtree Scan of Every Object is Expensive

The spec states that every object in every naming context is queried with `(objectClass=*)`. In large enterprises with millions of objects, this produces enormous result sets. The revised spec should consider:

- Whether an option to scope the scan to specific OUs or DNs would be valuable
- Whether scanning only specific object classes (e.g., containers, OUs, domains, and objects with explicit ACEs) could reduce the workload without sacrificing completeness
- Whether the tool should report scan statistics (objects processed, time elapsed, ACEs analyzed)

### 10.2. Memory Consumption is Not Bounded

While the spec mentions pruning records with no findings, it does not define a memory budget or describe behavior when memory is exhausted. In .NET Framework 2.0, the default process memory limit is lower than in modern frameworks. The revised spec should consider streaming output (writing CSV records as they are produced) rather than accumulating all results in memory.

### 10.3. SID Resolution Cache Could Grow Unbounded

The SID resolution cache stores entries for every unique SID encountered. In a large forest, this could be hundreds of thousands of entries. The revised spec should consider whether cache eviction or size limits are needed.

### 10.4. No Support for Incremental or Delta Scans

The spec describes a full scan every time the tool runs. For large environments, this is very expensive. The revised spec should consider whether a delta/incremental mode (using `uSNChanged` or `whenChanged` attributes, or comparing against a previous run's output) would be valuable. Even if not implemented in v1, the spec should be designed to accommodate this in the future.

---

## 11. Missing or Underspecified Behaviors

### 11.1. No Specification for Console Text Output

The spec focuses exclusively on CSV export. Since the new tool will have no GUI, the console text output becomes the primary interactive interface. The spec should fully define:

- The text output format (currently only briefly described as "sorted by location" in section 10)
- Color coding or visual indicators (if any) for different finding types
- Verbosity levels and how they affect console output
- Whether the `--index resources` vs. `--index trustees` view modes should be preserved

### 11.2. No Specification for the `--show-raw` Behavior in Console Output

The spec describes `--show-raw` behavior for CSV output (raw constant names and hex values) but does not clearly define how raw mode affects console text output. The revised spec should define both outputs.

### 11.3. LDAP Server/Domain Controller Discovery is Not Specified

The spec does not document how the tool determines which domain controller to connect to. The existing implementation supports a `--server` CLI option and has automatic DC discovery logic, but neither behavior is captured in the spec. The revised spec should define:

- How the tool discovers a domain controller when no explicit server is specified (e.g., via .NET Framework's `System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain()`, DNS SRV records, or `DsGetDcName`)
- What happens when discovery fails
- Whether the tool should support connecting to a specific site's DC
- Whether explicit server specification should even be needed if .NET Framework native AD objects handle DC location automatically (see Section 1.5)

### 11.4. No Specification for Encoding of DN Strings

Distinguished Names in Active Directory can contain special characters (commas, plus signs, semicolons, angle brackets, equals signs, hash marks, backslashes) that are escaped differently in LDAP DNs vs. CSV fields. The spec does not describe how these characters are handled in the output. This is especially important for the CSV format, where a DN like `CN=Smith\, John,OU=Users,DC=example,DC=com` must be properly quoted.

### 11.5. No Specification for Multi-Valued Attribute Handling

The spec mentions multi-valued attributes (e.g., `objectClass`, `namingContexts`) but does not specify a general rule for how multi-valued attributes are handled. Are values joined by a delimiter? Is only the first or last value used? This varies by attribute in the current spec (e.g., `objectClass` uses the last value as the most-specific class), but a general rule would improve consistency.

### 11.6. Missing Specification for What Constitutes a "Known Domain NC"

The spec references "known domain NC" in several places (e.g., AdminSDHolder lookup, domain SID association) but does not clearly define what makes a naming context a "known domain NC" vs. an application partition or other NC. The revised spec should clearly define this (presumably: NCs that appear in the `CN=Partitions,{configurationNC}` crossRef objects with `nETBIOSName` and `nCName` attributes).

### 11.7. No Versioning or Format Stability Guarantee

The spec does not define a version number or provide any stability guarantees for the CSV format, delegation JSON format, or template JSON format. The revised spec should define format versions and describe backward compatibility expectations.

---

## 12. Correctness and Edge Case Concerns

### 12.1. ACE Canonicality Check May Produce False Positives

The spec defines a non-canonical ACL as one where "a deny ACE follows an allow ACE among explicit ACEs." However, this check does not account for the nuance that in Windows ACLs, the canonical order is: explicit deny, explicit allow, inherited deny, inherited allow — but only within the same inheritance level. Two explicit ACEs may have different inheritance scopes (e.g., one applies to this object, one inherits to children), and their relative ordering may be correct even if deny follows allow across different scopes. The revised spec should define the canonicality check more precisely.

### 12.2. Creator Owner Replacement Logic Needs Clarification

The spec states that when computing inherited ACEs from schema defaults, `Creator Owner` SID (`S-1-3-0`) ACEs are replaced by the object's actual owner SID, and "both the replaced and original ACEs are produced as defaults." This means that if an explicit ACE matches either the `Creator Owner` version or the owner-replaced version, it will be filtered out. But what if the object's owner has changed since creation? The ACE with the original creator's SID would no longer match the owner-replaced version. The revised spec should clarify the expected behavior in this case.

### 12.3. Domain SID Detection for Non-Domain NCs is a Guess

For non-domain naming contexts (schema, configuration, application partitions), the spec uses the root domain SID as a fallback for "deleted trustee" detection. This means SIDs from child domains that appear in the schema/configuration partition will not be correctly identified as deleted if they belong to a non-root domain. The revised spec should consider checking all known domain SIDs, not just the root domain.

### 12.4. `adminCount` Attribute is Checked as String "0"

The spec states that `adminCount` is checked via `adminCount != "0"`, defaulting to `"0"` if missing. Since `adminCount` is an INTEGER attribute in the AD schema, LDAP returns it as a string representation of a number. A simple string comparison against `"0"` is fragile if the attribute value is missing, corrupt, or returned in an unexpected format. The revised spec should define numeric parsing of `adminCount` and treat any nonzero integer as indicating a protected object, with graceful handling for non-numeric or absent values.

### 12.5. Potential for Missed ACEs on Objects with Multiple Classes

The spec computes default security descriptors based on the object's most-specific class (last value in `objectClass`). However, AD uses the union of inherited ACEs from all structural classes in the hierarchy. If a class has a `defaultSecurityDescriptor` that introduces ACEs not present in the most-specific class's default, those ACEs might not be correctly filtered. The revised spec should clarify whether the tool considers only the most-specific class's defaults or the full class hierarchy.

---

## 13. Usability and Operational Concerns

### 13.1. No Dry-Run or Validation Mode

The tool performs read-only operations, so a dry-run mode might seem unnecessary. However, a mode that validates configuration (template files, delegation files, connectivity) without performing the full scan would be useful for troubleshooting deployment issues.

### 13.2. No Logging to a File

The spec only describes stdout (CSV/text output) and stderr (diagnostic messages). For operational use, the ability to log diagnostic messages to a file (independent of the CSV output) would be valuable. The revised spec should consider a `--log` option.

### 13.3. No Summary Statistics

After a scan, the tool should produce a summary of what it found: total objects scanned, total ACEs analyzed, total findings by category, scan duration, etc. The spec does mention a count of unreadable SDs printed to stderr, but a comprehensive summary would be more useful.

### 13.4. No Support for Excluding Specific OUs or DNs

The spec scans everything in every naming context. For large environments, administrators may want to exclude specific subtrees (e.g., `OU=Workstations` with thousands of computer objects that have identical delegations). The revised spec should consider `--exclude-dn` or similar filtering options.

### 13.5. Credential Handling UX

The spec mentions `--password *` for interactive password entry and `--password <value>` for command-line password. For .NET Framework 2.0, `Console.ReadKey(true)` can implement secure password entry. The revised spec should also consider reading credentials from environment variables or a configuration file (with appropriate security warnings) as alternatives to command-line arguments.

---

## 14. Security Considerations

### 14.1. Cleartext Password on Command Line

The spec correctly warns about `--password` leaking credentials via process listings. The revised spec should consider deprecating the cleartext `--password` option entirely and supporting only interactive entry (`--password *`) and SSPI/Kerberos (no password needed). If cleartext must be supported for automation, environment variable input (`ADELEG_PASSWORD`) would be less visible than a command-line argument.

### 14.2. No Certificate Validation for LDAPS

If LDAPS support is added (see Section 2.4), the spec should define certificate validation behavior. In .NET Framework 2.0, the `ServicePointManager.ServerCertificateValidationCallback` can be used for custom validation, but the default behavior and any override options should be specified.

### 14.3. No Audit Trail of Tool Execution

The tool makes LDAP queries that may be logged by the domain controller, but the tool itself does not produce an audit trail of its own execution. For compliance purposes, the revised spec should consider logging the tool's execution parameters, start/end times, and scan scope to the output or a separate log file.

### 14.4. Output File Permissions

The spec does not address the permissions on the output CSV file. In a security-sensitive tool, the output file should be created with restrictive permissions (e.g., readable only by the current user) since it may contain sensitive information about the AD delegation structure.

---

## 15. Assumptions That Should Be Re-evaluated

### 15.1. "Single Forest Scope" Assumption

The spec assumes all naming contexts belong to the same forest. This is reasonable for the initial scope, but the revised spec should define behavior when the tool encounters cross-forest references (e.g., foreign security principals from trusted forests). Currently, these appear as `External` type with raw SIDs — should the tool attempt to resolve them via the trust relationship?

### 15.2. "Standard Schema" Assumption

The spec assumes a standard AD schema. In practice, many organizations extend the schema with custom classes and attributes. The revised spec should explicitly state how custom schema extensions are handled (they should be fully supported since the schema is loaded dynamically, but the spec should confirm this).

### 15.3. "All AD Entries Are Containers" Assumption

As noted in Section 6.1, this is not strictly true. The revised spec should document this as an intentional simplification and list known exceptions (e.g., DNS records, leaf objects in AD LDS).

### 15.4. Removal of GUI Removes Context

The existing tool has a GUI that provides interactive exploration of results. With the GUI removed, the console output and CSV become the only interfaces. The revised spec should consider whether additional output modes (e.g., HTML report, interactive console mode with filtering/searching) are needed to compensate for the loss of the GUI's interactive capabilities.

### 15.5. .NET Framework 2.0 Backward Compatibility Goal Should Be Justified

The choice of .NET Framework 2.0 deserves a clear justification in the revised spec. .NET Framework 2.0 is end-of-life and lacks modern security patches. While backward compatibility with older Windows versions (Windows Server 2003/2008?) may be the motivation, the revised spec should explicitly state:

- Which minimum Windows versions are targeted
- Whether .NET Framework 2.0 is chosen because it's pre-installed on those versions
- What trade-offs are accepted by choosing .NET Framework 2.0 (no modern TLS defaults, no LINQ, limited async, etc.)
- Whether .NET 4.0 or .NET Standard 2.0 would be acceptable alternatives that provide better APIs while still supporting reasonably old Windows versions
