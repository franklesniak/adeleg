# Specification Criticism — `specifications-reference.md`

This document provides functional and technical criticism of the specification defined in `docs/specifications-reference.md`. The criticism is written from the perspective of producing a revised specification that will be used to write a net-new, from-scratch tool in **.NET Framework 2.0** (for intentional backward compatibility), running exclusively from the **console** with output to **CSV or similar text files** (no graphical user interface).

---

## Table of Contents

1. [Platform and Technology Coupling](#1-platform-and-technology-coupling)
2. [Residual LDAP Access Layer Concerns](#2-residual-ldap-access-layer-concerns)
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

### 1.5. .NET Framework 2.0 Native AD Objects as Functional Replacements for the Spec's LDAP Operations

The reference specification describes Active Directory access exclusively through low-level LDAP operations: explicit connection handles, bind calls, paged search controls, referral option flags, SD flags controls, port numbers, and timeout values. .NET Framework 2.0 provides managed AD APIs that functionally replace nearly all of these operations. The revised spec should be written at this higher abstraction level, specifying behaviors in terms of the .NET Framework objects that will actually be used, rather than in terms of the raw LDAP protocol operations that the Rust implementation happens to use.

The following subsections map each major area of the reference specification to its .NET Framework 2.0 equivalent, identifying where the current spec's LDAP-level detail becomes unnecessary.

#### 1.5.1. Domain Controller Discovery and Connection (Replaces Spec §2 Connection Logic)

The spec's `ldap_initW(serverName, port)` and `ldap_connect` calls are entirely replaced:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Initialize connection to a specific server/port | `new DirectoryEntry("LDAP://serverName")` — connection is established lazily on first property access |
| Auto-discover a DC for the current domain | `Domain.GetCurrentDomain()` returns a `Domain` object with an auto-selected DC; `Domain.FindDomainController()` for explicit DC selection |
| Auto-discover forest-level topology | `Forest.GetCurrentForest()` returns the forest with all domains, sites, and global catalogs |
| Specify a port number | Encoded in the LDAP path: `"LDAP://serverName:636"` for LDAPS, or `"GC://serverName"` for Global Catalog |
| Connection timeout | `DirectorySearcher.ClientTimeout` and `DirectoryEntry.Options.Timeout` (`DirectoryEntryConfiguration`) |

**Impact on the revised spec:** The `--server` and `--port` CLI options may be unnecessary for most use cases. The spec should define the tool's DC selection behavior in terms of `Domain.GetCurrentDomain()` / `Forest.GetCurrentForest()`, with an optional override for explicit server targeting. The 2-second `LDAP_TIMEVAL` concern (Spec §2) and DNS/mDNS/NBNS timeout caveat disappear — .NET Framework handles the underlying resolution internally.

#### 1.5.2. Authentication (Replaces Spec §2 Bind Logic and §16 Credential Handling)

The spec's `ldap_bind_sW` with `SEC_WINNT_AUTH_IDENTITY_W` structures is entirely replaced:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Bind with current Windows SSO (Negotiate/SSPI) | `new DirectoryEntry(path)` — no credentials needed; uses the process identity automatically |
| Bind with explicit credentials | `new DirectoryEntry(path, username, password, AuthenticationTypes.Secure)` |
| Interactive password entry (`--password *`) | Read password via `Console.ReadKey(true)`, pass to `DirectoryEntry` constructor |

**Impact on the revised spec:** The `SEC_WINNT_AUTH_IDENTITY_W` structure, `Negotiate` flag, and dynamic `sechost.dll` loading details are all moot. The spec should describe authentication requirements as: "Use the current Windows security context by default; support explicit username/password credentials via `DirectoryEntry` constructors."

#### 1.5.3. RootDSE Bootstrap (Replaces Spec §1 RootDSE Section)

The spec's base-scoped LDAP search on an empty DN is replaced:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Read `namingContexts` | `new DirectoryEntry("LDAP://RootDSE").Properties["namingContexts"]` |
| Read `schemaNamingContext` | `new DirectoryEntry("LDAP://RootDSE").Properties["schemaNamingContext"]` or `ActiveDirectorySchema.GetCurrentSchema().Name` |
| Read `configurationNamingContext` | `new DirectoryEntry("LDAP://RootDSE").Properties["configurationNamingContext"]` |
| Read `rootDomainNamingContext` | `new DirectoryEntry("LDAP://RootDSE").Properties["rootDomainNamingContext"]` |
| Read `supportedControl` | `new DirectoryEntry("LDAP://RootDSE").Properties["supportedControl"]` (but this becomes less important when the framework handles controls automatically) |

**Impact on the revised spec:** The RootDSE bootstrap is straightforward in either approach. However, `.NET Framework 2.0` provides higher-level alternatives for some values (e.g., `ActiveDirectorySchema.GetCurrentSchema()` instead of reading the raw DN). The `supportedControl` check for `LDAP_SERVER_SD_FLAGS_OID` becomes unnecessary because `DirectorySearcher.SecurityMasks` handles this transparently.

#### 1.5.4. Paged Search (Replaces Spec §3 Paging Section)

The spec's manual page control creation (`ldap_create_page_controlW`, `ldap_parse_page_controlW`, cookie management) is entirely replaced:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Create paged search with page size 999 | `DirectorySearcher.PageSize = 1000` (or any value ≤ AD's MaxPageSize) — paging is handled transparently |
| Parse paging cookies and continue | Automatic — `DirectorySearcher.FindAll()` handles continuation internally |
| Detect end of paged results | Automatic — the `SearchResultCollection` enumerator terminates when done |

**Impact on the revised spec:** The entire paging section of the spec (§3) is unnecessary. The revised spec need only state: "Set `DirectorySearcher.PageSize` to a value at or below the domain's MaxPageSize policy (default 1000) to enable transparent paging."

#### 1.5.5. Referral Handling (Replaces Spec §2 Referral Section)

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Disable referral chasing via `ldap_set_option(LDAP_OPT_REFERRALS, 0)` | `DirectorySearcher.ReferralChasing = ReferralChasingOption.None` |

**Impact on the revised spec:** Same behavior, one line of managed code instead of a P/Invoke `ldap_set_option` call.

#### 1.5.6. Schema Enumeration — Classes and Attributes (Replaces Spec §1/§2 Schema Queries)

The spec performs LDAP subtree searches on the schema NC to enumerate `classSchema` and `attributeSchema` objects. .NET Framework 2.0 provides a dedicated managed API:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Enumerate all schema classes with GUIDs and SDDL defaults | `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` returns `ReadOnlyActiveDirectorySchemaClassCollection`; each `ActiveDirectorySchemaClass` has `.SchemaGuid` and `.DefaultObjectSecurityDescriptor` (SDDL string) |
| Enumerate all schema attributes with GUIDs | `ActiveDirectorySchema.GetCurrentSchema().FindAllProperties()` returns `ReadOnlyActiveDirectorySchemaPropertyCollection`; each `ActiveDirectorySchemaProperty` has `.SchemaGuid` |
| Get `lDAPDisplayName` for a class or attribute | `ActiveDirectorySchemaClass.Name` / `ActiveDirectorySchemaProperty.Name` (this is the `lDAPDisplayName`) |

**Impact on the revised spec:** The schema query filters (`(objectClass=classSchema)`, `(objectClass=attributeSchema)`) and the attribute lists (`schemaIDGUID`, `lDAPDisplayName`, `defaultSecurityDescriptor`) become implementation details — the revised spec should describe the information needed (class GUIDs, attribute GUIDs, default SDDL strings) and note that `ActiveDirectorySchema` provides this natively. This is simpler, faster, and less error-prone than manual LDAP queries.

#### 1.5.7. Extended Rights, Property Sets, and Validated Writes (Partially Replaced)

The spec queries the Configuration NC for `controlAccessRight` objects with different `validAccesses` values. .NET Framework 2.0's `ActiveDirectorySchema` does **not** directly expose these:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Enumerate property sets (`validAccesses=48`) | **No direct .NET equivalent** — use `DirectorySearcher` on the Configuration NC with the same LDAP filter |
| Enumerate validated writes (`validAccesses=8`) | **No direct .NET equivalent** — use `DirectorySearcher` on the same NC |
| Enumerate control access rights (`validAccesses=256`) | **No direct .NET equivalent** — use `DirectorySearcher` on the same NC |

**Impact on the revised spec:** This is one area where `DirectorySearcher` with LDAP filters is still needed. The spec should retain these query definitions but express them in terms of `DirectorySearcher` filter/properties syntax rather than raw LDAP API calls. The `rightsGuid` and `displayName` attributes are still the relevant output.

#### 1.5.8. Domain Enumeration — SIDs and NetBIOS Names (Partially Replaced)

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Enumerate domains from `CN=Partitions,{configNC}` for `nCName`/`nETBIOSName` | `Forest.GetCurrentForest().Domains` returns a `DomainCollection`; each `Domain` has `.Name` (DNS name). However, **NetBIOS name is not directly exposed** — use `DirectorySearcher` on `CN=Partitions,{configNC}` or read `Domain.GetDirectoryEntry().Properties["nETBIOSName"]` via the crossRef object |
| Retrieve each domain's SID | `Domain.GetDirectoryEntry().Properties["objectSid"]` returns the domain SID as a byte array; parse with `new SecurityIdentifier(bytes, 0)` |

**Impact on the revised spec:** Domain enumeration is partially abstracted by `Forest.Domains`, but NetBIOS names and domain SIDs still require targeted queries. The revised spec should describe the higher-level approach first (use `Forest.Domains`), then specify the supplemental queries needed for NetBIOS names and SIDs.

#### 1.5.9. Security Descriptor Retrieval and SD Flags Control (Replaces Spec §3 SD Flags Section)

The spec's `LDAP_SERVER_SD_FLAGS_OID` control is fully replaced:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Send `LDAP_SERVER_SD_FLAGS_OID` requesting Owner + DACL | `DirectorySearcher.SecurityMasks = SecurityMasks.Owner \| SecurityMasks.Dacl` |
| Retrieve only DACL for AdminSDHolder | `DirectorySearcher.SecurityMasks = SecurityMasks.Dacl` |
| Parse raw SD binary from `nTSecurityDescriptor` | `SearchResult.GetDirectoryEntry().ObjectSecurity` returns `ActiveDirectorySecurity`, **or** read `nTSecurityDescriptor` as `byte[]` and parse with `new RawSecurityDescriptor(bytes, 0)` |

**Impact on the revised spec:** The SD flags OID, the control creation code, and the binary parsing details are all unnecessary. The revised spec should state: "Configure `DirectorySearcher.SecurityMasks` to request only the needed SD components, then access the SD via `ActiveDirectorySecurity` or `RawSecurityDescriptor`."

#### 1.5.10. ACE Extraction and Inherited ACE Filtering (Replaces Spec §4 and §5)

The spec describes manual byte-level ACE parsing and an explicit `is_inherited()` flag check. .NET Framework 2.0 replaces both:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Parse ACE types byte-by-byte via `GetAce` | `ActiveDirectorySecurity.GetAccessRules()` returns `AuthorizationRuleCollection` of `ActiveDirectoryAccessRule` objects |
| Check `INHERITED_ACE` flag manually | `GetAccessRules(includeExplicit: true, includeInherited: false, ...)` — pass `false` for `includeInherited` to get only explicit ACEs directly |
| Extract ACE type (Allow/Deny) | `ActiveDirectoryAccessRule.AccessControlType` (enum: `Allow`, `Deny`) |
| Extract access mask | `ActiveDirectoryAccessRule.ActiveDirectoryRights` (flags enum: `CreateChild`, `DeleteChild`, `WriteProperty`, `ExtendedRight`, `Delete`, `WriteDacl`, `WriteOwner`, etc.) |
| Extract `object_type` GUID | `ActiveDirectoryAccessRule.ObjectType` (returns `Guid`) |
| Extract `inherited_object_type` GUID | `ActiveDirectoryAccessRule.InheritedObjectType` (returns `Guid`) |
| Extract inheritance flags | `ActiveDirectoryAccessRule.InheritanceFlags` (enum: `ContainerInherit`, `ObjectInherit`) and `.PropagationFlags` (`InheritOnly`, `NoPropagateInherit`) |
| Extract trustee SID | `ActiveDirectoryAccessRule.IdentityReference` (returns `IdentityReference`, castable to `SecurityIdentifier`) |
| Extract ACE header flags | `ActiveDirectoryAccessRule.InheritanceFlags` and `.PropagationFlags` cover the relevant flag bits; `.IsInherited` for the `INHERITED_ACE` flag |

**Impact on the revised spec:** The entire ACE parsing section (§4) and the inherited/explicit detection section (§5) can be replaced with: "Call `ActiveDirectorySecurity.GetAccessRules(true, false, typeof(SecurityIdentifier))` to retrieve only explicit ACEs as `ActiveDirectoryAccessRule` objects. Each rule exposes the access type, rights, object GUIDs, inheritance flags, and trustee SID as typed properties." The 13 ACE types enumerated in the spec are handled transparently — .NET Framework parses them and exposes them through the same `ActiveDirectoryAccessRule` class. Callback ACE types require further investigation: `GetAccessRules()` returns callback ACEs as `ActiveDirectoryAccessRule` objects, but does not expose the conditional expression data embedded in the ACE. The revised spec should document this limitation and define whether callback ACEs are reported as-is (without condition evaluation, matching the current Rust tool's behavior) or flagged with a warning.

#### 1.5.11. SDDL Parsing for Schema Defaults (Replaces Spec §4.2)

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Parse SDDL via `ConvertStringSecurityDescriptorToSecurityDescriptorW` then binary parse | `new RawSecurityDescriptor(sddlString)` — the constructor accepts SDDL directly; `.DiscretionaryAcl` provides ACE access |

**Impact on the revised spec:** One constructor call replaces the two-step (SDDL → binary → parsed) approach. The revised spec should state: "Parse schema `defaultSecurityDescriptor` SDDL strings using `RawSecurityDescriptor(string)` and enumerate the resulting `DiscretionaryAcl` for default ACEs."

#### 1.5.12. SID Resolution (Replaces Spec §7)

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| `LookupAccountSidLocalW` via dynamic `GetProcAddress` from `sechost.dll` | `SecurityIdentifier.Translate(typeof(NTAccount))` — returns an `NTAccount` with `Value` in `DOMAIN\Username` format; throws `IdentityNotMappedException` on failure |
| LDAP SID-based lookup via `<SID=S-1-5-...>` synthetic DN | `new DirectoryEntry("LDAP://<SID=" + sid.Value + ">")` then `.Properties["distinguishedName"]` and `.Properties["objectClass"]` |
| Cache resolved SIDs | `Dictionary<SecurityIdentifier, string>` (or a custom cache class) — semantics are application-level, not API-level |

**Impact on the revised spec:** The `GetProcAddress`/`sechost.dll` dynamic loading and `SID_NAME_USE` enum mapping are unnecessary. The revised spec should define SID resolution as: "Attempt `SecurityIdentifier.Translate(typeof(NTAccount))` for local resolution; fall back to LDAP `<SID=...>` lookup via `DirectoryEntry`; cache results in a `Dictionary<string, string>` keyed by SID string."

#### 1.5.13. Owner Retrieval (Replaces Part of Spec §4)

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| `GetSecurityDescriptorOwner` on raw binary SD | `ActiveDirectorySecurity.GetOwner(typeof(SecurityIdentifier))` returns the owner as a `SecurityIdentifier` directly |

#### 1.5.14. AdminSDHolder DACL Retrieval

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| LDAP base search at `CN=AdminSDHolder,CN=System,<domainDN>` for `nTSecurityDescriptor` (DACL only) | `new DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System," + domainDN)` then `.ObjectSecurity.GetAccessRules(true, false, typeof(SecurityIdentifier))` |

#### 1.5.15. Main Scan — Subtree Search of All Objects (Approach Remains Similar)

The spec's `(objectClass=*)` subtree search is the core scanning operation. While `DirectorySearcher` replaces the raw LDAP calls, the logical operation remains the same:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Subtree search with `(objectClass=*)` | `DirectorySearcher.Filter = "(objectClass=*)"`, `.SearchScope = SearchScope.Subtree` |
| Request specific attributes | `DirectorySearcher.PropertiesToLoad.AddRange(new[] { "nTSecurityDescriptor", "objectClass", "objectSID", "adminCount", "msDS-KrbTgtLinkBl", "serverReference" })` |
| Process results one at a time | `DirectorySearcher.FindAll()` returns `SearchResultCollection`; iterate with `foreach` |

**Impact on the revised spec:** The query logic is the same, but expressed through `DirectorySearcher` properties instead of raw LDAP API calls. The key difference is that `DirectorySearcher.PageSize` handles paging transparently, and `SecurityMasks` replaces the manual SD flags control. The revised spec should describe this scan in terms of `DirectorySearcher` configuration.

#### 1.5.16. Access Mask Interpretation (Replaces Spec §8 Raw Bitmask Mapping)

The spec describes mapping raw 32-bit access mask values (hex constants like `0x20`, `0x100`, `0x80000`) to human-readable descriptions. .NET Framework 2.0 replaces raw bitmask manipulation with a typed flags enum:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Check `access_mask & 0x20` for `WRITE_PROP` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteProperty)` |
| Check `access_mask & 0x100` for `CONTROL_ACCESS` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight)` |
| Check `access_mask & 0x1` for `CREATE_CHILD` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.CreateChild)` |
| Check `access_mask & 0x2` for `DELETE_CHILD` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.DeleteChild)` |
| Check `access_mask & 0x80000` for `WRITE_OWNER` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner)` |
| Check `access_mask & 0x40000` for `WRITE_DAC` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl)` |
| Check `access_mask & 0x10000` for `DELETE` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.Delete)` |
| Check `access_mask & 0x40` for `DELETE_TREE` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.DeleteTree)` |
| Check `access_mask & 0x8` for `DS_SELF` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.Self)` |
| Check `access_mask & 0x1000000` for `ACCESS_SYSTEM_SECURITY` | `ActiveDirectoryAccessRule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.AccessSystemSecurity)` |
| Mask out read-only rights via `access_mask & ~IGNORED_RIGHTS` | Check `ActiveDirectoryRights.ReadProperty`, `ActiveDirectoryRights.ListChildren`, `ActiveDirectoryRights.ReadControl`, `ActiveDirectoryRights.ListObject` individually |
| Combine multiple rights as raw OR'd bitmask | `ActiveDirectoryRights` is a `[Flags]` enum — use `HasFlag()`, bitwise AND/OR, and `ToString()` for symbolic names |

**Impact on the revised spec:** The access mask mapping table in the spec (§8) should be rewritten in terms of `ActiveDirectoryRights` enum values instead of hex constants. The "ignored (read-only) access rights" set should be defined using enum values: `ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListObject`. The `--show-raw` mode can use `((int)rule.ActiveDirectoryRights).ToString("X8")` to display hex values and `rule.ActiveDirectoryRights.ToString()` for symbolic names — eliminating the need for a manual bitmask-to-name mapping table.

#### 1.5.17. ACL Canonicality Check (Replaces Part of Spec §12)

The spec manually checks whether deny ACEs follow allow ACEs among explicit ACEs and whether explicit ACEs follow inherited ACEs. .NET Framework 2.0 provides a built-in check:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Manually iterate ACEs checking deny-after-allow and explicit-after-inherited ordering | `RawSecurityDescriptor` → `CommonSecurityDescriptor` → `.DiscretionaryAcl.IsCanonical` (returns `bool`) |

**Impact on the revised spec:** The canonicality check logic described in the spec can be replaced with a single property access on `CommonAcl.IsCanonical`. However, this only answers "is it canonical?" — it does not identify which specific ACE is out of order. If the revised spec requires reporting the specific offending ACE (as the current spec does), the manual iteration is still needed as a supplement. The revised spec should state: "Use `CommonAcl.IsCanonical` as the primary canonicality check; if it returns `false`, iterate the ACEs to identify the specific ordering violation for the warning message."

#### 1.5.18. DACL Inheritance Protection Detection (Replaces Part of Spec §6)

The spec manually checks the `SE_DACL_PROTECTED` flag from the SD control field. .NET Framework 2.0 exposes this directly:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Check `SE_DACL_PROTECTED` flag via `GetSecurityDescriptorControl` | `ActiveDirectorySecurity.AreAccessRulesProtected` (returns `bool` — `true` if DACL inheritance is blocked) |

**Impact on the revised spec:** The DACL protection check is a single property access. The spec should replace the raw flag check with: "Check `ActiveDirectorySecurity.AreAccessRulesProtected` to determine if DACL inheritance is blocked."

#### 1.5.19. Domain SID Prefix Matching for Deleted Trustee Detection (Replaces Part of Spec §12)

The spec computes domain SID prefixes manually via `shares_prefix_with(domain_sid.with_rid(0))` to determine if an unresolvable SID belongs to the current domain. .NET Framework 2.0 provides this natively:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Strip RID and compare SID prefixes manually | `SecurityIdentifier.AccountDomainSid` — returns the domain portion of a SID (strips the RID), or `null` for well-known SIDs that have no domain component |
| Check if SID belongs to a specific domain | `sid.AccountDomainSid != null && sid.AccountDomainSid.Equals(domainSid)` — direct comparison of domain SIDs |

**Impact on the revised spec:** The deleted trustee detection logic should be expressed as: "For each unresolvable trustee SID, check `SecurityIdentifier.AccountDomainSid`. If it matches the naming context's associated domain SID (or the root domain SID for non-domain NCs), flag the ACE as a deleted trustee." This is cleaner and less error-prone than manual SID byte manipulation.

#### 1.5.20. Foreign Security Principal Resolution (Replaces Part of Spec §12)

The spec describes special handling for `CN=ForeignSecurityPrincipals` objects, preferring `LookupAccountSidLocalW` over the container DN. .NET Framework 2.0 handles this transparently:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Detect FSP container objects and prefer local SID resolution | `SecurityIdentifier.Translate(typeof(NTAccount))` — resolves trusted-domain and well-known SIDs automatically, regardless of where they appear in the directory. Returns `DOMAIN\Username` format. Throws `IdentityNotMappedException` for truly unresolvable SIDs |
| Fall back to raw SID for cross-forest principals | Catch `IdentityNotMappedException` and use `SecurityIdentifier.Value` (the SDDL string form, e.g., `S-1-5-21-...`) as the fallback display name |

**Impact on the revised spec:** The FSP-specific handling in the spec becomes unnecessary — `SecurityIdentifier.Translate()` already does the right thing for cross-domain, cross-forest, and well-known SIDs. The revised spec should state: "Resolve all trustee SIDs using `SecurityIdentifier.Translate(typeof(NTAccount))`. If translation throws `IdentityNotMappedException`, fall back to `SecurityIdentifier.Value` as the display name."

#### 1.5.21. Delegation and Template Data Format (Replaces Spec §11 JSON Format)

The spec uses JSON for delegation and template definitions (`builtin_delegations.json`, `templates.json`). .NET Framework 2.0 lacks native JSON support but has full XML support:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Parse JSON delegation files | `System.Xml.XmlDocument.Load(path)` — load XML delegation files with `SelectNodes()` for XPath queries |
| Embed built-in delegations as a compiled resource | Embed as an XML resource (`Assembly.GetManifestResourceStream()`) and parse with `XmlDocument` |
| Parse template files | `System.Xml.Serialization.XmlSerializer` — deserialize template definitions directly into typed objects |
| JSON schema validation | XML Schema (XSD) validation via `XmlReaderSettings.Schemas` — provides formal schema validation that JSON lacks |

**Impact on the revised spec:** The revised spec should define the delegation and template format as XML rather than JSON. XML provides several advantages in .NET Framework 2.0: native parsing (`XmlDocument`, `XmlReader`), native serialization (`XmlSerializer`), formal schema validation (XSD), and XPath query support. The revised spec should define the XML schema for delegation and template files, including element names, attribute types, and validation rules. The `access_mask` values in delegation definitions should use symbolic `ActiveDirectoryRights` enum names (e.g., `WriteProperty`, `ExtendedRight`) rather than raw numeric values, resolved at load time via `Enum.Parse(typeof(ActiveDirectoryRights), name)`.

#### 1.5.22. CSV Output Writing (Replaces Spec §10 CSV Generation)

The spec references the Rust `csv` crate for RFC 4180-compliant output. .NET Framework 2.0 has no built-in CSV library, but the operation is simple:

| Spec Behavior | .NET Framework 2.0 Replacement |
|---|---|
| Write RFC 4180 CSV via `csv` crate | `StreamWriter` with manual RFC 4180 quoting — fields containing commas, double-quotes, or newlines are enclosed in double-quotes, with embedded double-quotes escaped as `""` |
| Write to file or stdout | `new StreamWriter(path, false, Encoding.UTF8)` for file output; `Console.Out` for stdout |
| UTF-8 encoding | `Encoding.UTF8` — or `new UTF8Encoding(true)` to include a BOM for Excel compatibility |

**Impact on the revised spec:** The revised spec should define CSV output in terms of `StreamWriter` with explicit RFC 4180 quoting rules. Since .NET Framework 2.0 has no CSV library, the spec should define the exact quoting behavior required (which is trivial to implement: ~20 lines of code). The spec should also mandate a UTF-8 BOM when writing to a file (for Excel compatibility) and no BOM when writing to stdout (for piping).

#### 1.5.23. Progress Reporting (New Behavior — Not in Current Spec)

The current spec has no progress reporting. For a console tool scanning large forests, this is a significant usability gap. .NET Framework 2.0 supports this natively:

| Behavior | .NET Framework 2.0 Implementation |
|---|---|
| Report current naming context being scanned | `Console.Error.Write("\r[Scanning {ncDN}] {count} objects processed...")` — write to stderr with carriage return for in-place updates |
| Report elapsed time | `System.Diagnostics.Stopwatch.Elapsed` — high-resolution timer available in .NET Framework 2.0 |
| Report scan summary | `Console.Error.WriteLine("[Done] {total} objects, {findings} findings, {elapsed}")` |

**Impact on the revised spec:** The revised spec should define a progress reporting protocol using stderr. This keeps stdout clean for CSV/text data output while providing operational visibility. The `Stopwatch` class provides precise timing without P/Invoke.

#### 1.5.24. Summary of Replacement Coverage

| Spec Area | Fully Replaced by .NET Framework 2.0? | Notes |
|---|---|---|
| DC discovery and connection | ✅ Yes | `Domain.GetCurrentDomain()`, `DirectoryEntry` |
| Authentication and binding | ✅ Yes | `DirectoryEntry` constructor with credentials |
| Paged search controls | ✅ Yes | `DirectorySearcher.PageSize` |
| Referral handling | ✅ Yes | `DirectorySearcher.ReferralChasing` |
| SD flags control | ✅ Yes | `DirectorySearcher.SecurityMasks` |
| Security descriptor parsing | ✅ Yes | `ActiveDirectorySecurity`, `RawSecurityDescriptor` |
| ACE extraction and type handling | ✅ Yes | `GetAccessRules()` returns typed `ActiveDirectoryAccessRule` objects |
| Inherited vs. explicit ACE filtering | ✅ Yes | `GetAccessRules(includeExplicit, includeInherited, ...)` parameter |
| SDDL parsing | ✅ Yes | `RawSecurityDescriptor(string)` constructor |
| SID resolution (local) | ✅ Yes | `SecurityIdentifier.Translate(typeof(NTAccount))` |
| SID resolution (LDAP) | ✅ Yes | `DirectoryEntry("LDAP://<SID=...>")` |
| Owner retrieval | ✅ Yes | `ActiveDirectorySecurity.GetOwner()` |
| Schema class/attribute enumeration | ✅ Yes | `ActiveDirectorySchema.FindAllClasses()` / `FindAllProperties()` |
| RootDSE bootstrap | ✅ Yes | `DirectoryEntry("LDAP://RootDSE")` |
| Connection timeouts | ✅ Yes | `DirectorySearcher.ClientTimeout`, `DirectoryEntry.Options` |
| Access mask interpretation | ✅ Yes | `ActiveDirectoryRights` flags enum with `HasFlag()`, `ToString()` |
| ACL canonicality check | ✅ Yes | `CommonAcl.IsCanonical` for detection; manual iteration for specific ACE identification |
| DACL inheritance protection | ✅ Yes | `ActiveDirectorySecurity.AreAccessRulesProtected` |
| Domain SID prefix matching | ✅ Yes | `SecurityIdentifier.AccountDomainSid` for domain-portion extraction and comparison |
| Foreign security principal resolution | ✅ Yes | `SecurityIdentifier.Translate(typeof(NTAccount))` handles FSPs transparently |
| Delegation/template data format | ✅ Yes | `System.Xml.XmlDocument`, `XmlSerializer`, XSD validation — replaces JSON entirely |
| CSV output writing | ✅ Yes | `StreamWriter` with manual RFC 4180 quoting — simple, no external library needed |
| Progress reporting | ✅ Yes (new) | `Console.Error`, `Stopwatch` — not in current spec but should be in revised spec |
| Extended rights / property sets / validated writes | ⚠️ Partial | Still need `DirectorySearcher` on Configuration NC — no managed schema API for these |
| Domain NetBIOS names | ⚠️ Partial | `Forest.Domains` provides DNS names; NetBIOS requires supplemental query |
| Callback ACE conditional expressions | ❌ Not addressed | `GetAccessRules()` does not expose callback conditionals — same limitation as current spec |

**Conclusion for the revised spec:** 22 of 25 major operation areas are fully replaced by .NET Framework 2.0 managed APIs, with an additional area (progress reporting) that is new functionality enabled by .NET console APIs. The revised spec should be written in terms of these managed APIs, not in terms of raw LDAP operations or Windows API calls. The spec's entire Section 2 (Directory Query Mechanics), Section 3 (Paging), Section 4 (SD Parsing), Section 7 (SID Resolution), and Section 8 (Access Mask Mapping) should be replaced by .NET Framework 2.0-native descriptions. The remaining concerns in Section 2 of this criticism document are retained only for the two partially-replaced areas (extended rights and domain NetBIOS names) and the one unaddressed area (callback ACE conditionals).

---

## 2. Residual LDAP Access Layer Concerns

> **Context:** Section 1.5 demonstrates that 22 of 25 major operation areas in the reference spec are fully replaced by .NET Framework 2.0 managed APIs. The criticisms below address the **two partially-replaced areas** (extended rights enumeration and domain NetBIOS names) and edge cases where the .NET Framework abstractions may need supplementation. If the revised spec is written at the .NET Framework abstraction level as recommended, most of these points become implementation notes rather than spec-level concerns.

### 2.1. Connection Timeout Semantics Are Unclear (Largely Moot with .NET Framework)

The spec states a 2-second `LDAP_TIMEVAL` for `ldap_connect`, but then immediately adds a caveat that the "overall connection attempt may exceed 2 seconds due to underlying DNS/mDNS/NBNS resolution layers." With .NET Framework 2.0, `DirectorySearcher.ClientTimeout` and `DirectoryEntry.Options.Timeout` replace this — the framework handles DNS resolution internally. The revised spec should simply define the maximum acceptable wall-clock time before the tool reports a connection failure, expressed as a `ClientTimeout` value rather than a raw `LDAP_TIMEVAL`.

### 2.2. Referral Disabling Rationale is Good but Expression Should Use .NET API

The spec correctly disables referrals to prevent hanging when running outside the domain, but expresses this through `ldap_set_option(LDAP_OPT_REFERRALS, 0)`. In .NET Framework 2.0, the equivalent is `DirectorySearcher.ReferralChasing = ReferralChasingOption.None` — a single property assignment. The underlying concern remains valid: disabling referrals means the tool will not automatically follow cross-domain references within the same forest. If a naming context references objects in another domain, those objects will not be resolved — the LDAP client will receive referral responses that go unfollowed, which depending on the API layer may surface as errors or simply as missing results. The revised spec should state the referral policy in terms of `ReferralChasingOption` and explicitly define whether cross-domain references within a forest should be followed or whether unfollowed referrals are acceptable and how they should be reported.

### 2.3. Page Size Should Be Justified or Configurable (Simplified by .NET)

The page size of 999 is stated as a fixed constant without justification. With .NET Framework 2.0, paging is handled by setting `DirectorySearcher.PageSize` — no manual cookie management is needed. The default AD MaxPageSize policy is 1000, and any value ≤ 1000 will work. The revised spec should simply state the `PageSize` value to use (e.g., 1000), justify the choice relative to the AD policy default, and note that environments with custom MaxPageSize policies may require a different value.

### 2.4. No Support for LDAPS or StartTLS

The spec does not mention encrypted LDAP connections (LDAPS on port 636 or StartTLS). While Negotiate/SPNEGO provides signing and sealing by default, in environments that require channel binding or TLS-only policies, this could be a limitation. The revised spec should explicitly state whether encrypted transport is supported and, if so, how (port selection, certificate validation, etc.).

### 2.5. Connection Endpoints Are Largely Moot with .NET Framework

The spec does not document how the LDAP connection endpoint is determined — it does not specify a default port, CLI options for overriding the port, or support for LDAPS (port 636) or Global Catalog (ports 3268/3269). With .NET Framework 2.0, `Domain.GetCurrentDomain()` and `Forest.GetCurrentForest()` handle DC discovery automatically. LDAPS is supported via path syntax (`"LDAP://server:636"`), and Global Catalog access uses the `GC://` provider (`"GC://server"`). The revised spec should define connection behavior in terms of these .NET Framework constructs rather than raw port numbers, and should specify whether Global Catalog queries (which return partial attribute sets) are useful for any of the tool's operations.

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

### 3.5. Security Descriptor APIs Are Available and Should Be the Default Approach

.NET Framework 2.0 includes `System.Security.AccessControl` and `System.DirectoryServices`, which provide full managed access to security descriptors. `ActiveDirectorySecurity` (from `DirectoryEntry.ObjectSecurity`) and `RawSecurityDescriptor` (from `System.Security.AccessControl`) are both available, making managed SD parsing the natural approach. As detailed in Sections 1.5.9 through 1.5.13, the revised spec should describe SD processing exclusively through these managed APIs: `ActiveDirectorySecurity.GetAccessRules()` for ACE enumeration, `ActiveDirectorySecurity.GetOwner()` for owner retrieval, and `RawSecurityDescriptor(string)` for SDDL parsing. The Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorOwner`, `GetAce`, etc.) described in the reference spec should not appear in the revised spec.

### 3.6. JSON Parsing

.NET Framework 2.0 does not include a built-in JSON parser. `System.Text.Json` arrived in .NET Core 3.0. `System.Web.Script.Serialization.JavaScriptSerializer` is only available when referencing `System.Web.Extensions`, which was part of ASP.NET AJAX Extensions and may not be present in all .NET Framework 2.0 installations.

The revised spec should address this as a design decision. Options include: specifying a JSON format simple enough for a hand-written parser, using XML instead (natively supported in .NET Framework 2.0 via `System.Xml`), or explicitly requiring a third-party JSON library (e.g., Newtonsoft.Json, whose early versions supported .NET Framework 2.0).

---

## 4. Security Descriptor Parsing

### 4.1. The Revised Spec Should Define SD Processing Exclusively Through Managed APIs

The spec describes parsing security descriptors from raw binary blobs using Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorControl`, `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, etc.) and parsing ACEs byte-by-byte with `GetAce`. As detailed in Section 1.5.10, .NET Framework 2.0 provides `ActiveDirectorySecurity.GetAccessRules(true, false, typeof(SecurityIdentifier))` which returns typed `ActiveDirectoryAccessRule` objects with all relevant properties (access type, rights, object GUIDs, inheritance flags, trustee SID) already parsed. The revised spec should describe ACE processing exclusively in terms of `ActiveDirectoryAccessRule` properties:

- **Access type**: `rule.AccessControlType` (enum: `Allow` or `Deny`)
- **Rights**: `rule.ActiveDirectoryRights` (flags enum — see Section 1.5.16)
- **Object type GUID**: `rule.ObjectType` (returns `Guid`)
- **Inherited object type GUID**: `rule.InheritedObjectType` (returns `Guid`)
- **Trustee SID**: `(SecurityIdentifier)rule.IdentityReference`
- **Inheritance scope**: `rule.InheritanceFlags` and `rule.PropagationFlags`

For `SearchResult`-based access (where `ActiveDirectorySecurity` may not be directly available), `new RawSecurityDescriptor(bytes, 0)` provides a parsed SD with `.DiscretionaryAcl` access, and individual ACEs can be examined through `CommonAce` and `ObjectAce` types in `System.Security.AccessControl`.

### 4.2. SDDL Parsing Should Use `RawSecurityDescriptor(string)`

The spec mentions parsing SDDL strings from schema `defaultSecurityDescriptor` attributes using `ConvertStringSecurityDescriptorToSecurityDescriptorW`. As detailed in Section 1.5.11, .NET Framework 2.0 provides `RawSecurityDescriptor(string)` which accepts SDDL directly. The resulting `.DiscretionaryAcl` provides ACE enumeration through `CommonAce` and `ObjectAce` types. The revised spec should describe this requirement as: "Parse `defaultSecurityDescriptor` SDDL strings using `RawSecurityDescriptor(string)` and enumerate the resulting `DiscretionaryAcl`."

### 4.3. Callback ACE Handling is Underspecified and Unchanged by .NET

The spec acknowledges that callback ACE conditional expressions are not evaluated, but the spec does not clearly state what should happen with these ACEs in the output. Are they reported with a warning that the condition was not evaluated? Are they treated identically to non-callback ACEs? This ambiguity should be resolved in the revised spec. Note that .NET Framework 2.0's `GetAccessRules()` returns callback ACEs as `ActiveDirectoryAccessRule` objects but does not expose the conditional expression data — the same limitation exists in both the current Rust tool and the .NET Framework 2.0 rewrite (see Section 1.5.10).

### 4.4. ACE Type Coverage is Handled Transparently by .NET

The spec lists 13 ACE types that are handled, but does not mention `ACCESS_ALLOWED_COMPOUND_ACE_TYPE` (type 4), `SYSTEM_ALARM_ACE_TYPE` (type 3), `SYSTEM_ALARM_OBJECT_ACE_TYPE` (type 8), or `SYSTEM_ALARM_CALLBACK_ACE_TYPE`/`SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE`. With .NET Framework 2.0's `GetAccessRules()` and `GetAuditRules()`, the framework parses all supported ACE types and exposes them through the same `ActiveDirectoryAccessRule` / `ActiveDirectoryAuditRule` classes — the tool does not need to enumerate ACE types manually. The revised spec should state that ACE type coverage is determined by the framework's `GetAccessRules()` implementation, and should define behavior only for ACE types that the framework does not expose (which would be returned as `CustomAce` objects in the raw `RawSecurityDescriptor.DiscretionaryAcl` collection).

---

## 5. SID Resolution Strategy

### 5.1. Resolution Should Use .NET Native APIs with a Simple Cache

Section 7 of the spec describes a multi-step SID resolution strategy with nuanced cache population rules that differ based on whether a SID is domain-specific or not. The cache is populated from three different paths (main scan, local resolution, LDAP lookup) with different overwrite semantics for each. This complexity is a source of bugs and is difficult to test.

With .NET Framework 2.0, the resolution mechanism is simpler. The revised spec should define a clear, unambiguous resolution priority using native .NET APIs:

1. Cache lookup (`Dictionary<string, string>` keyed by SID string)
2. `SecurityIdentifier.Translate(typeof(NTAccount))` — resolves well-known and domain SIDs to `DOMAIN\Username` format without requiring P/Invoke or dynamic `GetProcAddress` calls
3. LDAP lookup via `new DirectoryEntry("LDAP://<SID=" + sid.Value + ">")` — retrieves the DN and `objectClass` for type determination
4. Raw SID string as fallback

The cache should have simple "first write wins" semantics (once resolved, a SID's mapping is stable for the duration of the run). The main scan's `objectSid` values can pre-populate the cache with SID → DN mappings for domain-specific SIDs, but `Translate()` results should not be overwritten by DN-based lookups (or vice versa) — whichever resolution succeeds first should be retained.

### 5.2. `SecurityIdentifier.Translate()` Replaces `LookupAccountSidLocalW`

The spec relies on dynamically loading `LookupAccountSidLocalW` from `sechost.dll` via `GetProcAddress`. In .NET Framework 2.0, `SecurityIdentifier.Translate(typeof(NTAccount))` provides the same functionality without P/Invoke. This method throws `IdentityNotMappedException` on failure, which is cleaner than checking Win32 error codes. The revised spec should define SID-to-name resolution exclusively through `SecurityIdentifier.Translate()` and document the expected behavior when translation fails (e.g., cross-forest SIDs, workgroup scenarios, non-domain-joined machines).

### 5.3. Cache Should Store a Typed Resolution Result

The spec itself notes that `resolved_sid_to_dn` stores either a DN or a `DOMAIN\Username` string, which makes the name misleading. In the .NET Framework 2.0 rewrite, the cache should store a typed resolution result (e.g., a simple class with `DisplayName` and `ResolutionSource` properties) rather than an untyped string. This makes it clear whether a cached value came from `SecurityIdentifier.Translate()` (producing `DOMAIN\Username`) or from a `DirectoryEntry` LDAP lookup (producing a DN).

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

### 6.5. Read-Only Access Rights Masking Should Use `ActiveDirectoryRights` Enum

The spec masks out read-only rights (`READ_CONTROL`, `ACTRL_DS_LIST`, `DS_LIST_OBJECT`, `DS_READ_PROP`) before comparing access masks using raw bitmask operations. With .NET Framework 2.0, the same logic should use the `ActiveDirectoryRights` flags enum (see Section 1.5.16): define the ignored set as `ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListObject`, then check `(rule.ActiveDirectoryRights & ~ignoredRights) == 0` to detect read-only ACEs. While this correctly focuses on write/modify permissions, it means the output may not accurately reflect the full scope of an ACE. If an ACE grants both `WriteProperty` and `ReadProperty`, the output will show only `WriteProperty`. The revised spec should clarify whether the output should reflect the masked or unmasked access rights, and whether a "raw" mode should show the full mask.

### 6.6. "Delete Protection" Deny ACE Suppression is Overly Broad

The spec suppresses deny ACEs for `Everyone` that deny `DELETE`, `DS_DELETE_CHILD`, and/or `DS_DELETE_TREE`. However, this suppression does not verify that the ACE only denies these rights — it checks if these rights are present but there could also be other denied rights in the same ACE. The revised spec should clarify whether the suppression applies only to ACEs that deny exclusively these rights, or also to ACEs that deny these rights among others.

### 6.7. AdminSDHolder Matching Does Not Account for Stale adminCount — Consider `ActiveDirectorySecurity.AreAccessRulesProtected`

The spec excludes AdminSDHolder-matching ACEs for objects with `adminCount != 0`. However, `adminCount` is notoriously stale in AD — it is set when an object is added to a protected group but not always cleared when the object is removed. This means formerly-protected objects that still have `adminCount=1` but are no longer in a protected group will have their ACEs incorrectly filtered. The revised spec should acknowledge this limitation and consider whether additional validation (e.g., checking actual group membership) is warranted.

Additionally, the DACL inheritance protection check for AdminSDHolder-managed objects should use `ActiveDirectorySecurity.AreAccessRulesProtected` (see Section 1.5.18) rather than manually checking the `SE_DACL_PROTECTED` flag.

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

### 8.1. Delegation/Template Format Should Use XML, Not JSON

As noted in Section 3.6 and detailed in Section 1.5.21, .NET Framework 2.0 lacks native JSON support but has comprehensive XML support. The revised spec should adopt XML as the delegation and template format. This provides several concrete advantages:

- **Native parsing**: `XmlDocument.Load(path)` for DOM-based access, or `XmlReader` for streaming
- **Type-safe deserialization**: `XmlSerializer` can deserialize XML directly into typed C# objects (`Delegation`, `Template` classes)
- **Formal schema validation**: XML Schema (XSD) files can formally define the structure of delegation/template files, with validation via `XmlReaderSettings.Schemas` — this is stronger than JSON Schema and requires no external library
- **XPath querying**: `XmlDocument.SelectNodes("//delegation[@trustee='...']")` for flexible querying
- **Embedded resources**: Built-in delegation definitions can be embedded as XML resources via `Assembly.GetManifestResourceStream()` and parsed with `XmlDocument.Load(stream)`

The revised spec should define the XML schema for delegation and template files.

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

### 8.5. `access_mask` in Delegation/Template Definitions Should Use `ActiveDirectoryRights` Enum Names

The spec describes delegation and template definitions that use raw numeric `access_mask` values (the spec itself uses values like `48`, `8`, and `256` for `validAccesses` in LDAP filters, and the delegation JSON format uses numeric `access_mask` fields). Raw numeric access masks are opaque and error-prone for human authors. As detailed in Section 1.5.16, .NET Framework 2.0's `ActiveDirectoryRights` enum provides symbolic names for all AD-specific access rights. The revised spec should require the delegation/template format (whether XML or otherwise) to use `ActiveDirectoryRights` enum names (e.g., `WriteProperty`, `ExtendedRight`, `CreateChild`, `DeleteChild`, `WriteDacl`, `WriteOwner`, `Delete`, `DeleteTree`, `Self`, `AccessSystemSecurity`) rather than raw numeric values. These can be resolved at load time via `(ActiveDirectoryRights)Enum.Parse(typeof(ActiveDirectoryRights), name)`.

---

## 9. Error Handling and Fault Tolerance

### 9.1. Exit Code 1 for All Errors is Insufficient — Use .NET `Environment.ExitCode`

The spec describes a single exit code (1) for all error conditions. For a console tool, differentiated exit codes would be far more useful for scripting and automation. .NET Framework 2.0 sets exit codes via `Environment.ExitCode` or the return value from `Main()`:

- 0: Success (no issues found or findings exported to CSV)
- 1: General/unexpected error
- 2: Connection/authentication failure (`DirectoryServicesCOMException` or `ActiveDirectoryObjectNotFoundException`)
- 3: Input file parsing error (templates, delegations — `XmlException` or `InvalidOperationException` from `XmlSerializer`)
- 4: Output file error (cannot write CSV — `IOException`, `UnauthorizedAccessException`)

### 9.2. Error Counter Message is Misleading

The spec acknowledges that the `warning_unreadable_count` message says "security descriptors could not be read" but actually counts all per-location processing errors (including missing `objectClass` and unparseable SDDL). The revised spec should fix this messaging inconsistency.

### 9.3. Panic on Empty `objectClass` is Unacceptable — Use Exception Handling

The spec states that an object with a present but empty `objectClass` value list causes a panic (via `.pop().expect(...)`). While this may be "impossible" in a valid AD, network errors, proxying LDAP servers, or AD corruption could cause this condition. In .NET Framework 2.0, the equivalent of a "panic" is an unhandled exception crashing the process. The revised spec should require `try/catch` handling around per-object processing — if `SearchResult.Properties["objectClass"].Count == 0`, log an error to stderr and skip the object, continuing the scan.

### 9.4. Search-Level Error Should Not Abort Entire Run — Catch `DirectoryServicesCOMException`

The spec states that a search-level LDAP error during `get_explicit_aces()` "aborts scanning for that entire naming context (and currently the entire run)." This is too aggressive. In .NET Framework 2.0, search errors surface as `DirectoryServicesCOMException` with specific `ErrorCode` values (matching LDAP error codes). The revised spec should define:

- **Transient errors** (e.g., `LDAP_BUSY`, `LDAP_UNAVAILABLE`): Retry with exponential backoff (via `System.Threading.Thread.Sleep()`)
- **Non-transient errors** (e.g., `LDAP_INSUFFICIENT_RIGHTS`, `LDAP_NO_SUCH_OBJECT`): Log the error, skip the naming context, continue with remaining NCs
- **Summary reporting**: At the end of the scan, report which naming contexts were successfully scanned and which failed, using `Console.Error.WriteLine()`

### 9.5. Progress Reporting Should Use `Console.Error` and `Stopwatch`

The spec does not define any progress reporting mechanism. In large forests with millions of objects, scanning can take a very long time. As detailed in Section 1.5.23, .NET Framework 2.0 supports progress reporting via `Console.Error.Write()` (to avoid mixing with CSV data on stdout) and `System.Diagnostics.Stopwatch` for precise elapsed-time tracking. The revised spec should define a progress reporting protocol, e.g.:

- `Console.Error.Write("\r[{ncDN}] {count} objects processed...")` — in-place progress updates via carriage return
- `Console.Error.WriteLine("[Done] {total} objects, {findings} findings, {elapsed}")` — final summary

---

## 10. Performance and Scalability

### 10.1. Full Subtree Scan of Every Object is Expensive

The spec states that every object in every naming context is queried with `(objectClass=*)`. In large enterprises with millions of objects, this produces enormous result sets. The revised spec should consider:

- Whether an option to scope the scan to specific OUs or DNs would be valuable
- Whether scanning only specific object classes (e.g., containers, OUs, domains, and objects with explicit ACEs) could reduce the workload without sacrificing completeness
- Whether the tool should report scan statistics (objects processed, time elapsed, ACEs analyzed)

### 10.2. Memory Consumption is Not Bounded — Use Streaming with `StreamWriter`

While the spec mentions pruning records with no findings, it does not define a memory budget or describe behavior when memory is exhausted. In .NET Framework 2.0, the default process memory limit is lower than in modern frameworks. The revised spec should consider streaming output (writing CSV records as they are produced via `StreamWriter` — see Section 1.5.22) rather than accumulating all results in memory. `DirectorySearcher.FindAll()` returns a `SearchResultCollection` that can be iterated one result at a time, enabling a streaming approach. **Important .NET-specific note:** `SearchResultCollection` implements `IDisposable` — the revised spec should mandate calling `.Dispose()` (or using a `using` statement) to release unmanaged LDAP result handles, preventing memory leaks during long scans.

### 10.3. SID Resolution Cache Could Grow Unbounded — Use `Dictionary<string, string>` with Size Monitoring

The SID resolution cache stores entries for every unique SID encountered. In a large forest, this could be hundreds of thousands of entries. In .NET Framework 2.0, the cache would be a `Dictionary<string, string>` keyed by the `SecurityIdentifier.Value` string. The revised spec should consider whether cache eviction or size limits are needed, and should define the cache behavior when memory pressure is detected (e.g., via `GC.GetTotalMemory()`).

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

### 11.3. LDAP Server/Domain Controller Discovery Should Use .NET Framework Native APIs

The spec does not document how the tool determines which domain controller to connect to. The existing Rust implementation supports a `--server` CLI option and has automatic DC discovery logic, but neither behavior is captured in the spec.

With .NET Framework 2.0, DC discovery is a solved problem. The revised spec should define the default behavior as:

- Use `Domain.GetCurrentDomain()` to discover the current domain and auto-select a DC — no CLI option needed for the common case
- Use `Forest.GetCurrentForest()` for forest-level topology discovery
- Support an optional `--server` override for targeting a specific DC (expressed as `new DirectoryEntry("LDAP://specificServer/...")`)
- Define failure behavior when `Domain.GetCurrentDomain()` throws `ActiveDirectoryObjectNotFoundException` (e.g., non-domain-joined machine)

This approach eliminates the need for raw `DsGetDcName` P/Invoke calls or DNS SRV record parsing.

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

### 12.1. ACL Canonicality Check Should Use `CommonAcl.IsCanonical` as Primary Detection

The spec defines a non-canonical ACL as one where "a deny ACE follows an allow ACE among explicit ACEs." However, this check does not account for the nuance that in Windows ACLs, the canonical order is: explicit deny, explicit allow, inherited deny, inherited allow — but only within the same inheritance level. Two explicit ACEs may have different inheritance scopes (e.g., one applies to this object, one inherits to children), and their relative ordering may be correct even if deny follows allow across different scopes.

As detailed in Section 1.5.17, .NET Framework 2.0 provides `CommonAcl.IsCanonical` (via `RawSecurityDescriptor` → `CommonSecurityDescriptor` → `.DiscretionaryAcl.IsCanonical`) which implements the Windows ACL canonicality rules correctly, accounting for inheritance scope levels. The revised spec should use this as the primary detection mechanism, supplemented by manual iteration only when a non-canonical ACL needs to identify the specific offending ACE for the warning message.

### 12.2. Creator Owner Replacement Logic Needs Clarification

The spec states that when computing inherited ACEs from schema defaults, `Creator Owner` SID (`S-1-3-0`) ACEs are replaced by the object's actual owner SID, and "both the replaced and original ACEs are produced as defaults." This means that if an explicit ACE matches either the `Creator Owner` version or the owner-replaced version, it will be filtered out. But what if the object's owner has changed since creation? The ACE with the original creator's SID would no longer match the owner-replaced version. The revised spec should clarify the expected behavior in this case.

### 12.3. Domain SID Detection Should Use `SecurityIdentifier.AccountDomainSid`

For non-domain naming contexts (schema, configuration, application partitions), the spec uses the root domain SID as a fallback for "deleted trustee" detection using manual SID byte manipulation. As detailed in Section 1.5.19, .NET Framework 2.0 provides `SecurityIdentifier.AccountDomainSid` which returns the domain portion of a SID (strips the RID), or `null` for well-known SIDs with no domain component. The revised spec should define deleted trustee detection as: "For each unresolvable trustee SID, extract `sid.AccountDomainSid`. If it matches any known domain SID (not just the root domain), flag the ACE as a deleted trustee." This approach is both simpler and more correct — it checks all known domain SIDs, not just the root domain, which means SIDs from child domains in the schema/configuration partition will be correctly identified as deleted.

### 12.4. `adminCount` Attribute Should Be Parsed as Integer via `SearchResult.Properties`

The spec states that `adminCount` is checked via `adminCount != "0"`, defaulting to `"0"` if missing. Since `adminCount` is an INTEGER attribute in the AD schema, .NET Framework 2.0's `SearchResult.Properties["adminCount"]` returns it as an `int` (boxed in `object`), not as a string. The revised spec should define numeric handling: `int adminCount = result.Properties.Contains("adminCount") ? (int)result.Properties["adminCount"][0] : 0;` and treat any nonzero integer as indicating a protected object. This eliminates the fragile string comparison entirely.

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

### 13.5. Credential Handling Should Use `DirectoryEntry` Constructor and `Console.ReadKey(true)`

The spec mentions `--password *` for interactive password entry and `--password <value>` for command-line password. In .NET Framework 2.0, credentials are passed directly to the `DirectoryEntry` constructor (see Section 1.5.2): `new DirectoryEntry(path, username, password, AuthenticationTypes.Secure)`. Interactive password entry uses `Console.ReadKey(true)` in a loop to read characters without echo, building a `string` or `System.Security.SecureString`. The revised spec should also consider reading credentials from environment variables (via `Environment.GetEnvironmentVariable("ADELEG_PASSWORD")`) or a configuration file (with appropriate security warnings) as alternatives to command-line arguments.

---

## 14. Security Considerations

### 14.1. Cleartext Password on Command Line

The spec correctly warns about `--password` leaking credentials via process listings. The revised spec should consider deprecating the cleartext `--password` option entirely and supporting only interactive entry (`--password *`) and SSPI/Kerberos (no password needed). If cleartext must be supported for automation, environment variable input (`ADELEG_PASSWORD`) would be less visible than a command-line argument.

### 14.2. No Certificate Validation for LDAPS — Use `ServicePointManager` or `AuthenticationTypes.SecureSocketsLayer`

If LDAPS support is added (see Section 2.4), the spec should define certificate validation behavior. In .NET Framework 2.0, LDAPS connections can be established by specifying `AuthenticationTypes.SecureSocketsLayer` in the `DirectoryEntry` constructor or by using port 636 in the LDAP path (e.g., `"LDAP://server:636"`). Custom certificate validation can be implemented via `ServicePointManager.ServerCertificateValidationCallback`. The revised spec should define the default behavior (validate the server certificate against the local CA trust store) and any override options (e.g., `--ignore-cert-errors` for testing environments).

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
