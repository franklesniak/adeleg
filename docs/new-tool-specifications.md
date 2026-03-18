# Active Directory Delegation Analysis Tool — Technical Specification

> **Provenance:** This specification is derived from the original ADeleg tool's behavioral specification (`specifications-reference.md`) and revised per the criticism document (`specifications-criticism.md`, Sections 1–12). All operations are described in terms of .NET Framework 2.0 managed APIs. This is a standalone document — no other specification documents are required to understand the tool's behavior for the areas covered herein.

---

## Table of Contents

1. [Active Directory Scope and Query Locations](#1-active-directory-scope-and-query-locations)
2. [Directory Query Mechanics](#2-directory-query-mechanics)
3. [Paging, Performance, and Query Configuration](#3-paging-performance-and-query-configuration)
4. [Security Descriptor Retrieval and ACE Processing](#4-security-descriptor-retrieval-and-ace-processing)
5. [Detection of Inherited vs. Explicit Permissions](#5-detection-of-inherited-vs-explicit-permissions)
6. [Filtering of Default or Built-in Permissions](#6-filtering-of-default-or-built-in-permissions)
7. [Security Identifier (SID) Resolution](#7-security-identifier-sid-resolution)
8. [Permission and Rights Interpretation](#8-permission-and-rights-interpretation)
9. [Data Processing and Transformation Pipeline](#9-data-processing-and-transformation-pipeline)
10. [CSV Export Structure](#10-csv-export-structure)
11. [Delegation and Template System](#11-delegation-and-template-system)
12. [Handling of Special or Edge Cases](#12-handling-of-special-or-edge-cases)
13. [Performance and Scalability Considerations](#13-performance-and-scalability-considerations)
14. [Error Handling and Fault Tolerance](#14-error-handling-and-fault-tolerance)
15. [Assumptions and Limitations](#15-assumptions-and-limitations)

---

## 1. Active Directory Scope and Query Locations

### Naming Contexts Queried

The tool queries the following Active Directory partitions, discovered dynamically at runtime from the RootDSE:

| Partition | RootDSE Attribute | Purpose |
|---|---|---|
| Schema | `schemaNamingContext` | Retrieve class definitions, attribute definitions, default security descriptors |
| Configuration | `configurationNamingContext` | Retrieve extended rights, control access rights, validated writes, property sets |
| All naming contexts | `namingContexts` | Scan every object in each naming context (including schema, configuration, domain, and application partitions) for explicit (non-inherited) ACEs |
| Root domain | `rootDomainNamingContext` | Used as a fallback domain reference |

### RootDSE Bootstrap

On startup, the tool reads the RootDSE to retrieve essential directory metadata:

```csharp
DirectoryEntry rootDSE = new DirectoryEntry("LDAP://RootDSE");
```

The following attributes are read from the RootDSE:

- `namingContexts` — the list of all naming contexts hosted by the server
- `schemaNamingContext` — the DN of the Schema partition
- `configurationNamingContext` — the DN of the Configuration partition
- `rootDomainNamingContext` — the DN of the forest root domain

When targeting a specific server, the path format is `"LDAP://serverName/RootDSE"`.

The `supportedControl` attribute is not required, as .NET Framework 2.0's `DirectorySearcher.SecurityMasks` handles SD flags control transparently.

### Known Domain NC Definition

A naming context is classified as a "known domain NC" if it appears as the `nCName` attribute of a `crossRef` object in `CN=Partitions,<configurationNamingContext>` that also has a `nETBIOSName` attribute. This distinguishes domain naming contexts from application partitions and other non-domain NCs.

### Recursive Traversal

- **Schema partition**: Enumerated via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` and `FindAllProperties()` for class GUIDs, attribute GUIDs, and default security descriptors.
- **Configuration partition**: Queried with `DirectorySearcher` using `SearchScope.Subtree` to enumerate `controlAccessRight` objects for property sets, validated writes, and control access rights.
- **Each naming context** (including schema, configuration, domain, and application partitions): Queried with `DirectorySearcher` using `Filter = "(objectClass=*)"` and `SearchScope = SearchScope.Subtree`, which returns every object in the partition recursively.
- **AdminSDHolder**: Accessed via `new DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,<domainDN>")` when the naming context is a known domain NC; otherwise `new DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,<rootDomainNamingContext>")`.
- **Individual SID lookups**: Performed via `new DirectoryEntry("LDAP://<SID=S-1-5-...>")`.

---

## 2. Directory Query Mechanics

### Domain Controller Discovery and Connection

The tool uses .NET Framework 2.0 managed APIs for DC discovery:

| Behavior | Implementation |
|---|---|
| Auto-discover a DC for the current domain | `Domain.GetCurrentDomain()` returns a `Domain` object with an auto-selected DC |
| Auto-discover forest-level topology | `Forest.GetCurrentForest()` returns the forest with all domains and sites |
| Connect to a specific server | `new DirectoryEntry("LDAP://serverName")` — connection is established lazily on first property access |
| Specify a port number | Encoded in the LDAP path: `"LDAP://serverName:636"` for LDAPS |
| Failure on non-domain-joined machine | `Domain.GetCurrentDomain()` throws `ActiveDirectoryObjectNotFoundException`; the tool must catch this and report a clear error message |

The tool should default to using `Domain.GetCurrentDomain()` for DC discovery. An optional `--server` CLI argument allows targeting a specific DC via `new DirectoryEntry("LDAP://specificServer/...")`.

### Authentication

| Behavior | Implementation |
|---|---|
| Use current Windows SSO (Negotiate/SSPI) | `new DirectoryEntry(path)` — uses the process identity automatically |
| Explicit credentials | `new DirectoryEntry(path, username, password, AuthenticationTypes.Secure)` |
| Interactive password entry (`--password *`) | Read password via `Console.ReadKey(true)` in a loop, pass to `DirectoryEntry` constructor |

### LDAP Filters Used

| Query Target | Filter | Attributes Requested |
|---|---|---|
| Property sets | `(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Validated writes | `(&(objectClass=controlAccessRight)(validAccesses=8)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Control access rights | `(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| All naming contexts (main scan) | `(objectClass=*)` | `nTSecurityDescriptor`, `objectClass`, `objectSID`, `adminCount`, `msDS-KrbTgtLinkBl`, `serverReference` |
| AdminSDHolder | `(objectClass=*)` | `nTSecurityDescriptor` |
| Domain enumeration (partitions) | `(&(nCName=*)(nETBIOSName=*))` | `nCName`, `nETBIOSName` |
| Domain enumeration (SID) | `(objectSid=*)` | `objectSid` |

Schema classes and attributes are enumerated via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` and `FindAllProperties()` respectively, rather than via direct LDAP queries. Each `ActiveDirectorySchemaClass` provides `.SchemaGuid`, `.Name` (the `lDAPDisplayName`), and `.DefaultObjectSecurityDescriptor` (SDDL string). Each `ActiveDirectorySchemaProperty` provides `.SchemaGuid` and `.Name`.

Extended rights, property sets, and validated writes are not directly exposed by `ActiveDirectorySchema` and must be queried via `DirectorySearcher` on the Configuration NC using the LDAP filters listed above.

### Referral Handling

LDAP referrals are disabled:

```csharp
searcher.ReferralChasing = ReferralChasingOption.None;
```

**Rationale:** Disabling referrals prevents hanging when running the tool from outside the domain or when DNS cannot resolve referral targets.

**Cross-domain implication:** With referrals disabled, the tool will not automatically follow cross-domain references within the same forest. Objects referenced from other domains will not be resolved via referral chasing. Unfollowed referrals may surface as missing results or errors depending on the specific operation. This is an acceptable trade-off for connection reliability.

### LDAPS and Encrypted Transport

The tool uses `AuthenticationTypes.Secure` by default, which provides SASL/Kerberos signing and encryption without requiring LDAPS. For environments that require TLS-based transport:

- LDAPS is supported via path syntax: `"LDAP://server:636"` with `AuthenticationTypes.SecureSocketsLayer`
- Certificate validation is handled automatically by the Windows trusted CA certificate store
- No custom certificate validation code or P/Invoke is needed

### Connection Endpoints

DC discovery is handled by `Domain.GetCurrentDomain()` and `Forest.GetCurrentForest()`. The `--server` CLI option allows explicit server targeting. Global Catalog access uses the `GC://` provider (`"GC://server"`), though the tool's operations primarily use the standard LDAP provider.

---

## 3. Paging, Performance, and Query Configuration

### Paged Search

All LDAP searches use paged results via `DirectorySearcher.PageSize`:

```csharp
searcher.PageSize = 1000;
```

Setting `PageSize` to a nonzero value enables transparent paging — `DirectorySearcher.FindAll()` handles page control creation, cookie management, and continuation automatically. The value 1000 is the default AD `MaxPageSize` policy limit. Environments with custom `MaxPageSize` policies may require a different value.

### Security Descriptor Retrieval Control

The `DirectorySearcher.SecurityMasks` property controls which parts of the security descriptor are retrieved:

- **Main scan**: `SecurityMasks.Owner | SecurityMasks.Dacl` — retrieves only the owner and DACL
- **AdminSDHolder**: `SecurityMasks.Dacl` — retrieves only the DACL

This replaces the manual `LDAP_SERVER_SD_FLAGS_OID` control and reduces data transfer by excluding the SACL and primary group.

### Timeouts

- `DirectorySearcher.ClientTimeout` — maximum time the client waits for search results
- `DirectorySearcher.ServerTimeLimit` — maximum time the server spends processing a query

The tool should set reasonable timeout values and report a clear error message if a timeout occurs.

### Attribute Selection

Only the specific attributes needed are requested via `DirectorySearcher.PropertiesToLoad`:

```csharp
searcher.PropertiesToLoad.AddRange(new string[] {
    "nTSecurityDescriptor", "objectClass", "objectSID",
    "adminCount", "msDS-KrbTgtLinkBl", "serverReference"
});
```

This reduces network traffic compared to retrieving all attributes.

---

## 4. Security Descriptor Retrieval and ACE Processing

### Security Descriptor Access

Security descriptors are accessed through .NET Framework 2.0 managed APIs exclusively. No raw Windows API calls (`IsValidSecurityDescriptor`, `GetSecurityDescriptorOwner`, `GetAce`, etc.) are used.

For objects retrieved via `DirectorySearcher`:

- **Primary approach**: Access `SearchResult.GetDirectoryEntry().ObjectSecurity` to obtain an `ActiveDirectorySecurity` object.
- **Alternative**: Read `nTSecurityDescriptor` as `byte[]` from `SearchResult.Properties["nTSecurityDescriptor"]` and parse with `new RawSecurityDescriptor(bytes, 0)`.

### ACE Extraction

ACEs are retrieved via:

```csharp
ActiveDirectorySecurity security = entry.ObjectSecurity;
AuthorizationRuleCollection rules = security.GetAccessRules(
    true,   // includeExplicit
    false,  // includeInherited
    typeof(SecurityIdentifier)
);
```

Passing `false` for `includeInherited` retrieves only explicit ACEs directly, replacing the manual `INHERITED_ACE` flag check.

Each `ActiveDirectoryAccessRule` exposes:

| Property | Description |
|---|---|
| `AccessControlType` | `Allow` or `Deny` |
| `ActiveDirectoryRights` | Flags enum of access rights granted/denied |
| `ObjectType` | GUID identifying the specific property, property set, extended right, or child class |
| `InheritedObjectType` | GUID identifying which child object type the ACE applies to |
| `IdentityReference` | Trustee SID (castable to `SecurityIdentifier`) |
| `InheritanceFlags` | `ContainerInherit`, `ObjectInherit` |
| `PropagationFlags` | `InheritOnly`, `NoPropagateInherit` |
| `IsInherited` | Whether the ACE is inherited (always `false` when retrieved with `includeInherited = false`) |

### SDDL Parsing for Schema Defaults

Schema `defaultSecurityDescriptor` SDDL strings are parsed using:

```csharp
RawSecurityDescriptor sd = new RawSecurityDescriptor(sddlString);
```

The `RawSecurityDescriptor(string)` constructor accepts SDDL directly. The resulting `.DiscretionaryAcl` provides ACE enumeration through `CommonAce` and `ObjectAce` types in `System.Security.AccessControl`.

### Owner Retrieval

The object owner is retrieved via:

```csharp
SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
```

### Callback ACE Handling

**Documented limitation:** Callback ACE types (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`, `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`, etc.) are returned by `GetAccessRules()` as `ActiveDirectoryAccessRule` objects, but the conditional expression data embedded in the ACE is not exposed by the .NET Framework. Callback ACEs are reported as-is, treated identically to their non-callback counterparts, without evaluation of their conditional expressions. The reported permissions may not reflect the effective conditional access. This matches the behavior of the original tool.

### ACE Type Coverage

ACE type coverage is determined by the .NET Framework's `GetAccessRules()` implementation, which parses all supported ACE types and exposes them through `ActiveDirectoryAccessRule`. The tool does not need to enumerate ACE types manually. ACE types that the framework does not expose would appear as `CustomAce` objects in the raw `RawSecurityDescriptor.DiscretionaryAcl` collection; these are not processed by the tool.

### Objects Inspected

Every object in every naming context is inspected. The tool does not filter by object class during the LDAP query — it retrieves all objects via `(objectClass=*)` and processes each one's security descriptor.

---

## 5. Detection of Inherited vs. Explicit Permissions

### Inherited ACE Filtering

Only explicitly assigned (non-inherited) ACEs are included in the output. This is achieved by passing `includeInherited = false` to `GetAccessRules()`:

```csharp
security.GetAccessRules(true, false, typeof(SecurityIdentifier));
```

This eliminates the need for manual `INHERITED_ACE` flag checking. The tool's goal is to report delegations that were explicitly configured, not those that flow down from parent containers through inheritance.

---

## 6. Filtering of Default or Built-in Permissions

### Schema Default Security Descriptors

Each AD class can have a `defaultSecurityDescriptor` attribute in SDDL form, accessed via `ActiveDirectorySchemaClass.DefaultObjectSecurityDescriptor`. The tool parses these for every class and computes the ACEs that would be derived by inheritance from the schema defaults for each object's class. An ACE that matches a schema default is excluded from the output.

The ACE comparison function compares two ACEs while ignoring:

- **Read-only access rights**: `ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListObject`
- **Object inherit flag**: `InheritanceFlags.ObjectInherit`. The `OBJECT_INHERIT_ACE` flag causes an ACE to be inherited by non-container (leaf) child objects, while `ContainerInherit` causes inheritance to container child objects. Since the vast majority of Active Directory entries are containers rather than leaf objects, the `ObjectInherit` flag has no practical effect for most AD objects. The tool masks out this flag before comparing ACEs.

**Caveat:** Leaf objects do exist in AD (e.g., individual DNS records in AD-integrated DNS zones, certain system objects). Ignoring `OBJECT_INHERIT_ACE` is an intentional simplification that may produce incorrect results for these objects. This is documented as a known limitation.

**False-negative risk:** An administrator may intentionally set an explicit ACE that happens to match a schema default. Excluding these ACEs means the tool will not report them. This trade-off is documented as a known limitation. A future enhancement could provide a flag to expose these matches, similar to `--show-builtin`.

### Default SD Computation for Multiple Classes

The tool computes default security descriptors based on the object's most-specific class (the last value in the multi-valued `objectClass` attribute). Active Directory uses the union of inherited ACEs from all structural classes in the hierarchy. If a parent class has a `defaultSecurityDescriptor` that introduces ACEs not present in the most-specific class's default, those ACEs may not be correctly filtered. This is documented as a known limitation.

### Creator Owner Handling in Schema Defaults

When computing inherited ACEs from schema defaults, if the parent ACE's trustee is the `Creator Owner` SID (`S-1-3-0`), it is replaced by the actual owner SID of the child object (mirroring AD behavior). Both the replaced and original ACEs are produced as defaults, so an explicit ACE matching either version is filtered.

**Note:** If the object's owner has changed since creation, the ACE with the original creator's SID would no longer match the owner-replaced version. The tool uses the current owner SID for this comparison.

### Ignored Trustee SIDs

ACEs for the following well-known SIDs are suppressed by default, since these principals already have inherent full control:

| SID | Identity |
|---|---|
| `S-1-5-10` | SELF |
| `S-1-5-18` | Local System |
| `S-1-5-20` | Network Service |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-9` | Enterprise Domain Controllers |
| `<domain SID>-512` | Domain Admins (per domain) |
| `<domain SID>-516` | Domain Controllers (per domain) |
| `<domain SID>-518` | Schema Admins (per domain) |
| `<domain SID>-519` | Enterprise Admins (per domain) |

**Note:** Account Operators (`S-1-5-32-548`), Server Operators (`S-1-5-32-549`), Print Operators (`S-1-5-32-550`), and Backup Operators (`S-1-5-32-551`) are **reported by default** and are NOT in the suppressed list. These groups are well-known attack vectors in Active Directory, and suppressing their ACEs by default could give a false sense of security. Security auditors specifically need visibility into what these groups can do.

### Configurable Ignored Trustee List

The `--show-ignored-trustees` CLI option causes the tool to report ACEs for all trustees, including those in the default suppressed list. This allows auditors to see the full picture when needed.

### Read-Only Access Rights

ACEs whose access mask, after masking out read-only rights, results in zero are discarded. The ignored (read-only) access rights are defined using the `ActiveDirectoryRights` enum:

```csharp
ActiveDirectoryRights ignoredRights =
    ActiveDirectoryRights.ReadProperty |
    ActiveDirectoryRights.ListChildren |
    ActiveDirectoryRights.ReadControl |
    ActiveDirectoryRights.ListObject;

if ((rule.ActiveDirectoryRights & ~ignoredRights) == 0)
{
    // ACE grants only read-only rights; discard
}
```

The output reflects the full (unmasked) access rights of an ACE. The masking is used only for the "is this ACE interesting?" decision. In `--show-raw` mode, the complete access mask is displayed.

### Delete Protection ACEs

Deny ACEs for `Everyone` (`S-1-1-0`) are suppressed only when the ACE **exclusively** denies delete-related rights (`Delete`, `DeleteChild`, and/or `DeleteTree`). If the ACE also denies other rights beyond these, it is NOT suppressed. This tightened check prevents hiding deny ACEs that restrict more than just deletion.

```csharp
ActiveDirectoryRights deleteRights =
    ActiveDirectoryRights.Delete |
    ActiveDirectoryRights.DeleteChild |
    ActiveDirectoryRights.DeleteTree;

// Suppress only if the ACE denies exclusively delete rights
if (rule.AccessControlType == AccessControlType.Deny
    && trusteeSid.Equals(everyoneSid)
    && (rule.ActiveDirectoryRights & ~deleteRights) == 0)
{
    // Suppress this standard delete-protection entry
}
```

### Change Password Deny ACEs

Deny ACEs for `Everyone` that deny the `Change Password` control access right are suppressed, as these are set by tools like `dsa.msc` for the "Cannot change password" option.

### AdminSDHolder ACEs

For objects with a nonzero `adminCount` attribute, ACEs that appear in the AdminSDHolder DACL are suppressed. This is because the SDProp process copies the AdminSDHolder's DACL onto protected objects.

The `adminCount` attribute is parsed as an integer, not a string:

```csharp
int adminCount = result.Properties.Contains("adminCount")
    ? (int)result.Properties["adminCount"][0]
    : 0;
```

Any nonzero integer value indicates a protected object.

**Stale adminCount caveat:** The `adminCount` attribute is notoriously stale in AD — it is set when an object is added to a protected group but not always cleared when removed. Formerly-protected objects may have `adminCount=1` but are no longer managed by SDProp, causing their ACEs to be incorrectly filtered. As a supplemental check, the tool also examines `ActiveDirectorySecurity.AreAccessRulesProtected` — objects that are truly SDProp-managed will have DACL inheritance blocked. If `adminCount != 0` but `AreAccessRulesProtected` is `false`, the tool should log a warning to stderr noting the inconsistency, as this may indicate a stale `adminCount`.

### Ignored Control Access Rights

ACEs granting only `ExtendedRight` for specific control access rights that do not grant meaningful control over a resource are suppressed:

- `Apply Group Policy` — applying a GPO does not mean controlling it
- `Allow a DC to create a clone of itself` — if an attacker can impersonate a DC, cloning is not the primary concern

### Ignored DACL Protected Flags

DACL inheritance blocking (detected via `ActiveDirectorySecurity.AreAccessRulesProtected`) is not reported as a warning for:

- Objects of class `groupPolicyContainer` (GPOs block inheritance by design)
- Objects with `adminCount != 0` (expected to block inheritance via SDProp)
- Specific well-known containers: `CN=AdminSDHolder,CN=System`, `CN=VolumeTable,CN=FileLinks,CN=System`, `CN=Keys`, `CN=WMIPolicy,CN=System`, `CN=SOM,CN=WMIPolicy,CN=System`

### Built-in Delegation Definitions

A set of built-in delegation definitions is shipped with the tool, either as an embedded XML resource (loaded via `Assembly.GetManifestResourceStream()`) or as an external XML file distributed alongside the executable. These define expected ACEs for well-known delegations (e.g., DnsAdmins on DNS zones, Group Policy Creator Owners on WMI policies). By default, matched built-in delegations are excluded from CSV output unless `--show-builtin` is specified.

### RODC-Specific Filtering

The tool suppresses several ACE patterns specific to Read-Only Domain Controllers (RODCs):

- Change Password / Reset Password control access by an RODC on its secondary KrbTgt account
- `CreateChild` on `nTDSDSA` objects by the RODC referenced from the server object, and `Delete` on `nTDSDSA` objects only when the ACE has the `InheritOnly` propagation flag set
- `WriteProperty` for `schedule` and `fromServer` attributes on `nTDSConnection` objects by the owning RODC
- Validated write for `dnsHostName` on `server` objects by the referenced RODC

---

## 7. Security Identifier (SID) Resolution

### Resolution Strategy

SID resolution uses a clear 4-step priority:

1. **Cache lookup**: Check a SID resolution cache (a key-value mapping from SID string to resolved result) for a previously resolved display name and principal type.
2. **Local resolution via `SecurityIdentifier.Translate()`**: Call `SecurityIdentifier.Translate(typeof(NTAccount))`. If successful, the `NTAccount.Value` property returns the name in `DOMAIN\Username` format. This replaces the previous `LookupAccountSidLocalW` approach entirely — no P/Invoke or dynamic library loading is needed.
3. **LDAP SID-based lookup**: Perform a lookup via `new DirectoryEntry("LDAP://<SID=" + sid.Value + ">")` and retrieve `distinguishedName` and `objectClass` attributes. If successful, the DN is used as the display name and `objectClass` determines the principal type.
4. **Raw SID string fallback**: If all resolution methods fail, the raw SID string (e.g., `S-1-5-21-...`) is used as the display name, with type `External`.

### Cache Semantics

The SID resolution cache uses **"first write wins"** semantics: once a SID's mapping is stored, it is not overwritten for the duration of the run. This ensures stable, predictable resolution results.

The cache stores a typed resolution result with:
- **Display name**: Either a `DOMAIN\Username` string (from `Translate()`) or a DN (from LDAP lookup) or a raw SID string (fallback)
- **Principal type**: The resolved principal type classification
- **Resolution source**: Which resolution path populated the entry (for diagnostic purposes)

### Cache Population

The cache is populated from multiple sources during operation:

- **During the main scan**: When an object has an `objectSid` attribute, for domain-specific SIDs (starting with `S-1-5-21-...`), the mapping from SID → DN is inserted directly. For non-domain-specific SIDs (e.g., well-known SIDs found in `CN=ForeignSecurityPrincipals`), `Translate()` is attempted first; only if it throws `IdentityNotMappedException` is the SID → DN mapping inserted as a fallback. Existing cache entries are never overwritten.
- **During `Translate()` resolution**: A successful translation stores the SID → `DOMAIN\Username` mapping.
- **During LDAP SID lookup**: A successful lookup stores the SID → DN mapping.

### Principal Type Resolution

Each resolved SID is mapped to one of four principal type classifications. The mapping depends on the resolution path:

**From LDAP (objectClass-based):** The most specific class (last value of the multi-valued `objectClass` attribute) is compared via case-insensitive exact match:

| Most Specific Class | Principal Type | Notes |
|---|---|---|
| `computer` | `Computer` | Includes machine accounts |
| `user` | `User` | Includes `inetOrgPerson` (which inherits from `user` and appears as most-specific class `inetOrgPerson` — see below) |
| `group` | `Group` | |
| `msDS-GroupManagedServiceAccount` | `User` | gMSA accounts (inherits from `computer` in AD but logically represents a service identity) |
| `msDS-ManagedServiceAccount` | `User` | sMSA accounts |
| `inetOrgPerson` | `User` | Inherits from `user`; the `objectClass` ordering (most-specific-last) ensures this is the last value |
| `foreignSecurityPrincipal` | `External` | Represents a principal from a trusted domain |
| Any other class | `External` | |

**From `SecurityIdentifier.Translate()` resolution:** The `Translate()` method returns an `NTAccount` but does not directly provide a `SID_NAME_USE` equivalent. The principal type is set to `External` by default for `Translate()`-resolved SIDs, unless the SID is subsequently resolved via LDAP (which provides the `objectClass`).

**Unresolved SIDs:** If resolution fails entirely (cache miss, `Translate()` throws `IdentityNotMappedException`, and LDAP lookup fails), the raw SID string is used as the trustee name with type `External`.

### Foreign Security Principals

`SecurityIdentifier.Translate(typeof(NTAccount))` automatically resolves trusted-domain and well-known SIDs, regardless of where they appear in the directory. Foreign security principal objects in `CN=ForeignSecurityPrincipals` do not require special handling — `Translate()` does the right thing for cross-domain and cross-forest SIDs. Truly unresolvable SIDs (e.g., from unreachable forests) fall back to the raw SID string.

### Deleted Trustee Detection

During post-processing, for each naming context, ACEs whose trustee SID cannot be resolved are evaluated for deleted trustee classification:

```csharp
SecurityIdentifier trusteeSid = /* unresolvable trustee */;
SecurityIdentifier domainSid = trusteeSid.AccountDomainSid;

if (domainSid != null && IsKnownDomainSid(domainSid))
{
    // Flag as deleted trustee
}
```

`SecurityIdentifier.AccountDomainSid` returns the domain portion of a SID (strips the RID), or `null` for well-known SIDs with no domain component. If the domain portion matches **any** known domain SID (not just the root domain), the ACE is flagged as a deleted trustee. Unresolvable SIDs from unknown domains or forests remain as orphan ACEs with raw SID trustee strings.

---

## 8. Permission and Rights Interpretation

### Access Mask Mapping

The tool maps `ActiveDirectoryRights` enum values to human-readable descriptions. When in resolved-name mode (the default), the following mappings apply:

| `ActiveDirectoryRights` Value | Human-Readable Description |
|---|---|
| `WriteProperty` | "Write attribute {name}" (attribute GUID match), "Write attributes of category {name}" (property set GUID match), or "Write all properties" (no match/no GUID) |
| `ExtendedRight` | "{Control access name}" or "Perform all application-specific operations" |
| `CreateChild` | "Create child {class} objects" or "Create child objects of any type" |
| `DeleteChild` | "Delete child {class} objects" or "Delete child objects of any type" |
| `WriteOwner` | "Change the owner" |
| `WriteDacl` | "Add/delete delegations" |
| `Delete` | "Delete" |
| `DeleteTree` | "Delete along with all children" |
| `Self` | "{Validated write name}" or "Perform all validated writes" |
| `AccessSystemSecurity` | "Add/delete auditing rules" |

Rights checks use bitwise operations compatible with .NET Framework 2.0:

```csharp
if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) != 0)
{
    // WriteProperty is set
}
```

**Note:** `Enum.HasFlag()` is NOT used, as it was introduced in .NET Framework 4.0.

### Object Type GUID Resolution

In **resolved-name mode** (the default), the `ObjectType` GUID resolution is **conditional on which access right is set**:

| Access Right | GUID Resolution Order |
|---|---|
| `WriteProperty` | attribute GUID → property set GUID → (fallback: "Write all properties") |
| `ExtendedRight` | control access right GUID → (fallback: "Perform all application-specific operations") |
| `CreateChild` | class GUID → (fallback: "Create child objects of any type") |
| `DeleteChild` | class GUID → (fallback: "Delete child objects of any type") |
| `Self` | validated write GUID → (fallback: "Perform all validated writes") |

In **raw mode** (`--show-raw`), the GUID is resolved sequentially across all schema categories:
1. Class GUID → class name
2. Attribute GUID → attribute name
3. Control access right GUID → control access name
4. Property set GUID → property set name
5. Validated write GUID → validated write name

Raw mode displays hex values via `((int)rule.ActiveDirectoryRights).ToString("X8")` and symbolic names via `rule.ActiveDirectoryRights.ToString()`.

### Inherited Object Type Resolution and Inheritance Scope

When in resolved-name mode and `ContainerInherit` is set in `InheritanceFlags`, the `InheritedObjectType` GUID is resolved against class GUIDs to determine which child object type the ACE applies to:

- "on all {class_name} child objects" if `InheritedObjectType` resolves to a class
- "on all child objects" otherwise
- "and the container itself" is appended if `InheritOnly` is NOT set in `PropagationFlags`

When `ContainerInherit` is not set, no inheritance scope text is included.

---

## 9. Data Processing and Transformation Pipeline

### Step 1: Connection and Bootstrap

- Establish connection via `DirectoryEntry` (automatically discovers a DC via `Domain.GetCurrentDomain()`, or connects to a specific server via `--server`)
- Read RootDSE for naming contexts and schema/configuration DNs
- Enumerate domains from `CN=Partitions,<configurationNC>` via `DirectorySearcher` to get domain NetBIOS names. Domain SIDs are retrieved via `Domain.GetDirectoryEntry().Properties["objectSid"]` parsed with `new SecurityIdentifier(bytes, 0)`.
- Report progress: `Console.Error.WriteLine("[*] Connected to {serverName}")` 

### Step 2: Schema Loading

- Enumerate all schema classes via `ActiveDirectorySchema.GetCurrentSchema().FindAllClasses()` for class GUIDs (`SchemaGuid`) and `DefaultObjectSecurityDescriptor` SDDL strings
- Enumerate all schema attributes via `ActiveDirectorySchema.GetCurrentSchema().FindAllProperties()` for attribute GUIDs (`SchemaGuid`)
- Query `controlAccessRight` objects via `DirectorySearcher` on the Configuration NC for property sets (`validAccesses=48`), validated writes (`validAccesses=8`), and control access rights (`validAccesses=256`)
- Report progress: `Console.Error.WriteLine("[*] Schema loaded: {classCount} classes, {attrCount} attributes, {rightCount} extended rights")`

### Step 3: Delegation and Template Loading

- Load built-in delegations from the embedded XML resource (via `Assembly.GetManifestResourceStream()` and `XmlDocument.Load(stream)`)
- Optionally load user-provided templates (`--templates`) and delegations (`--delegations`) from external XML files, validated against XSD schema
- For each delegation, derive expected ACEs by resolving trustees and locations, and index them by SID → Location

### Step 4: Schema ACE Analysis

- For each `ActiveDirectorySchemaClass` with a `DefaultObjectSecurityDescriptor`:
  - Parse the SDDL string via `new RawSecurityDescriptor(sddlString)` for each domain
  - Filter the DACL ACEs through the interest check logic
  - Store remaining ACEs as orphan ACEs in the result set

### Step 5: Explicit ACE Analysis

- For each naming context, perform a subtree search via `DirectorySearcher` with `Filter = "(objectClass=*)"`, `SearchScope = SearchScope.Subtree`, `PageSize = 1000`, `SecurityMasks = SecurityMasks.Owner | SecurityMasks.Dacl`
- **Important:** `SearchResultCollection` returned by `FindAll()` implements `IDisposable`. It MUST be disposed (via `using` statement or explicit `.Dispose()`) to release unmanaged LDAP result handles and prevent memory leaks during long scans.
- For each object:
  - Parse the security descriptor via `ActiveDirectorySecurity`
  - Compute expected default ACEs from the schema class's `DefaultObjectSecurityDescriptor`
  - Filter each DACL ACE through the interest check, which excludes: inherited ACEs, read-only ACEs, schema default ACEs, AdminSDHolder ACEs, ignored trustee ACEs, and special-case ACEs
  - Record: owner, DACL protection status (via `AreAccessRulesProtected`), ACL canonicality, and orphan ACEs
- Report progress periodically: `Console.Error.Write(String.Format("\r[{0}] {1} objects processed...", ncDN, count))`

### Step 6: Post-Processing

1. **Memory optimization**: Remove records with no findings (no orphan ACEs, no owner issues, no warnings), but retain parent container records needed for CREATE_CHILD analysis.
2. **Deleted trustee detection**: For each naming context, determine the associated domain SID (from the known domain NC list) or the root domain SID for non-domain naming contexts. For each unresolvable orphan ACE trustee, check `SecurityIdentifier.AccountDomainSid` — if it matches any known domain SID, move the ACE to the deleted trustee list.
3. **KDS root key handling**: Suppress DACL protection warnings for KDS root key objects in the Configuration partition.
4. **Owner analysis via CREATE_CHILD**: For each object with a non-ignored owner, walk up the container hierarchy checking if the owner has `CreateChild` permissions — if so, suppress the owner finding (the owner created the object). Group membership for this check uses the `tokenGroups` constructed attribute via `DirectoryEntry.RefreshCache(new string[] { "tokenGroups" })`, which resolves transitive/nested group memberships.
5. **Parent object ACE suppression**: Remove ACEs whose trustees are parent objects (e.g., computers controlling their own BitLocker recovery objects).

### Step 7: Delegation Matching

1. For each expected delegation (built-in + user-defined), create or update a result entry, initially marking all expected ACEs as "missing".
2. For each location, match orphan ACEs against expected delegation ACEs using the ACE comparison function:
   - If a match is found, the ACE moves from orphan ACEs to found ACEs for that delegation
   - The corresponding expected ACE is removed from the missing list
   - One ACE can match multiple delegations
3. For built-in delegations, clear all missing ACEs (do not flag missing built-in ACEs).

### Step 8: CSV Generation

- Iterate over all results, sorted deterministically (see Section 10)
- For each entry, write CSV records for: errors/warnings, owner, DACL protection, non-canonical ACL, deleted trustees, orphan ACEs, and matched delegations
- Report final summary: `Console.Error.WriteLine(String.Format("[Done] {0} objects, {1} findings, elapsed: {2}", total, findings, stopwatch.Elapsed))`

---

## 10. CSV Export Structure

### Triggering CSV Export

CSV export is triggered by the `--csv <path>` command-line argument. If the path is `-`, output goes to stdout. Otherwise, a file is created (or truncated if it exists).

### CSV Header Row

The CSV output includes a mandatory header row as the first line:

```
Resource,Trustee,Trustee type,Category,Details
```

### CSV Schema

The CSV output has **5 columns**:

| Column | Name | Description |
|---|---|---|
| 1 | **Resource** | The location where the delegation or finding applies. Either a DN (e.g., `OU=Users,DC=example,DC=com`) or a schema reference (e.g., `Schema: default security descriptor of class 'user'`) |
| 2 | **Trustee** | The resolved name of the security principal (DN or `DOMAIN\Username`), or the raw SID string if unresolvable, or `Global` for location-level warnings |
| 3 | **Trustee type** | One of: `User`, `Group`, `Computer`, `External` |
| 4 | **Category** | Classification of the finding (see below) |
| 5 | **Details** | Human-readable description of the permission or finding |

### Category Values

| Category | Meaning |
|---|---|
| `Owner` | The trustee owns the object, granting implicit full control |
| `Warning` | A structural issue (unreadable SD, blocked DACL inheritance, non-canonical ACL) or a deleted trustee finding |
| `Allow ACE` | An explicit allow ACE not explained by any known delegation |
| `Deny ACE` | An explicit deny ACE not explained by any known delegation |
| `Built-in` | A delegation matching a built-in definition (only shown with `--show-builtin`) |
| `Delegation` | A delegation matching a user-defined definition |
| `Expected allow ACE found` | An individual allow ACE that was expected and found in place |
| `Expected deny ACE found` | An individual deny ACE that was expected and found in place |
| `Expected allow ACE missing` | An individual allow ACE that was expected but not found |
| `Expected deny ACE missing` | An individual deny ACE that was expected but not found |

### Deterministic Row Ordering

CSV rows are sorted deterministically using the following order:

1. **Primary sort**: Resource column (DN), alphabetically
2. **Secondary sort**: Category column, by priority order: `Warning` → `Owner` → `Deny ACE` → `Allow ACE` → `Built-in` → `Delegation` → `Expected deny ACE found` → `Expected allow ACE found` → `Expected deny ACE missing` → `Expected allow ACE missing`
3. **Tertiary sort**: Trustee column, alphabetically

This deterministic ordering enables diff-based change tracking between runs.

### Record Generation Logic

For each location/result pair in the scan results:

1. **Per-location processing errors** (if `--show-warning-unreadable`): One `Warning` record with the error message. This covers any error entry in the results, including unreadable security descriptors, missing/unreadable `objectClass` attributes, and unparseable schema `defaultSecurityDescriptor` SDDL strings.
2. **Owner**: One `Owner` record if the object's owner is not in the ignored trustee set and was not filtered by CREATE_CHILD analysis.
3. **DACL protection**: One `Warning` record if `AreAccessRulesProtected` is `true` and the object is not in an excluded category.
4. **Non-canonical ACL**: One `Warning` record if the ACL is not in canonical order. The offending ACE is described.
5. **Deleted trustees**: One `Warning` record per ACE whose trustee no longer exists.
6. **Orphan ACEs**: One `Allow ACE` or `Deny ACE` record per unmatched ACE, with access rights described.
7. **Delegations**: For each matched delegation (built-in only if `--show-builtin`):
   - One `Built-in` or `Delegation` record with the delegation description
   - One `Expected allow/deny ACE found` record per matched ACE, prefixed with "In delegation: "
   - One `Expected allow/deny ACE missing` record per unmatched expected ACE, prefixed with "In delegation: "

### Formatting and Encoding

- **Encoding**: UTF-8 without BOM. Use `new UTF8Encoding(false)` explicitly.
- **File output**: `new StreamWriter(path, false, new UTF8Encoding(false))`
- **Stdout output**: Wrap `Console.OpenStandardOutput()` in a `StreamWriter`:

```csharp
StreamWriter writer = new StreamWriter(
    Console.OpenStandardOutput(),
    new UTF8Encoding(false)
);
```

**Do NOT use `Console.Out` directly** for CSV output, as `Console.OutputEncoding` defaults to the system's OEM code page on Windows.

- **RFC 4180 quoting rules**: Fields containing commas, double-quotes, or newlines are enclosed in double-quotes. Embedded double-quotes are escaped as `""`. The line terminator is CRLF. This is implemented manually (~20 lines of code), as .NET Framework 2.0 has no built-in CSV library.

### DN String Encoding

Distinguished Names in Active Directory can contain special characters (commas, plus signs, semicolons, angle brackets, equals signs, hash marks, backslashes). These characters appear as-is in the DN string within the CSV field. The RFC 4180 quoting rules handle the CSV-level escaping (DNs containing commas will be enclosed in double-quotes).

### Stdout and Stderr Separation

When `--csv -` is used, CSV data goes to stdout. All diagnostic and progress messages go to stderr via `Console.Error`. This ensures clean separation when using pipe redirection.

---

## 11. Delegation and Template System

### Delegation and Template Format

Delegation and template definitions use **XML format** (not JSON), taking advantage of .NET Framework 2.0's native XML support.

### XML Parsing

- **DOM-based access**: `XmlDocument.Load(path)` with `SelectNodes()` for XPath queries
- **Deserialization**: `XmlSerializer` can deserialize XML directly into typed C# objects
- **Embedded resources**: Built-in definitions loaded via `Assembly.GetManifestResourceStream()` and parsed with `XmlDocument.Load(stream)`

### XSD Schema Validation

All delegation and template XML files are validated against an XSD schema at load time:

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.Schemas.Add(null, xsdPath);
settings.ValidationType = ValidationType.Schema;
```

This provides formal structural validation without third-party libraries.

### Access Mask Representation

Delegation definitions use symbolic `ActiveDirectoryRights` enum names (e.g., `WriteProperty`, `ExtendedRight`, `CreateChild`) rather than raw numeric values. These are resolved at load time:

```csharp
ActiveDirectoryRights rights = (ActiveDirectoryRights)Enum.Parse(
    typeof(ActiveDirectoryRights), rightsName
);
```

### XML Schema Elements

The delegation XML schema defines:

- **`<delegation>`**: A delegation definition with attributes for `name`, `builtin` (boolean), `trustee` (SID or samAccountName), and child elements for locations and expected ACEs
- **`<location>`**: A location pattern (DN or wildcard) where the delegation applies
- **`<ace>`**: An expected ACE with attributes for `type` (Allow/Deny), `rights` (symbolic `ActiveDirectoryRights` names), `objectType` (GUID), `inheritedObjectType` (GUID)
- **`<template>`**: A template definition with `name`, `appliesTo` filters, and `rights` arrays

### Location Wildcards

Delegation definitions support the following wildcard patterns for locations, which are expanded at load time:

| Pattern | Expansion |
|---|---|
| `DC=*` | Each domain's DN in the forest |
| `CN=Configuration,DC=*` | The Configuration naming context |
| `CN=Schema,DC=*` | The Schema naming context |
| `DC=DomainDnsZones,DC=*` | Expanded using each domain's DN |
| `DC=ForestDnsZones,DC=*` | Expanded using the root domain NC |

These are a closed set of supported patterns, not true glob-style wildcards.

### Resource Representation

Resources in the CSV `Resource` column are represented as:

- **Distinguished Names (DNs)**: Full LDAP DNs like `CN=Users,DC=example,DC=com`
- **Schema references**: Formatted as `Schema: default security descriptor of class '{className}'`
- **`Global`**: Used for non-location-specific findings

### Multi-Valued Attribute Handling

For multi-valued attributes:

- `objectClass`: The last value (most-specific class) is used for class determination. The ordering (most-specific-last) is relied upon as a standard AD behavior.
- `namingContexts`: All values are used (each represents a naming context to scan).
- Other multi-valued attributes: The specific handling depends on the attribute's purpose and is defined per-attribute where relevant.

---

## 12. Handling of Special or Edge Cases

### Deleted Objects and Tombstones

- The tool does not explicitly query the Deleted Objects container or tombstones.
- ACEs referencing SIDs that belong to a known domain (determined via `SecurityIdentifier.AccountDomainSid` comparison against all known domain SIDs) and cannot be resolved are flagged as deleted trustees and reported with a "Warning" category.
- Unresolvable SIDs from unknown domains or forests remain as orphan ACEs with raw SID trustee strings.

### Foreign Security Principals

- Objects in `CN=ForeignSecurityPrincipals` are encountered during the subtree scan.
- `SecurityIdentifier.Translate(typeof(NTAccount))` automatically resolves well-known and trusted-domain SIDs, regardless of their container. FSP-specific handling is not needed.
- Truly foreign (cross-forest) principals that cannot be resolved locally appear with their raw SID and `External` type.

### Denied Permissions

- Deny ACEs are processed and reported in the CSV with category `Deny ACE`.
- Deny ACEs are considered during delegation matching (expected deny ACEs can be defined in delegation XML files).
- ACL canonicality checks detect deny-after-allow ordering issues.

### Non-Canonical ACLs

Non-canonical ACL detection uses `CommonAcl.IsCanonical` as the primary detection mechanism:

```csharp
RawSecurityDescriptor rawSd = new RawSecurityDescriptor(bytes, 0);
CommonSecurityDescriptor commonSd = new CommonSecurityDescriptor(
    false, false, rawSd
);
bool isCanonical = commonSd.DiscretionaryAcl.IsCanonical;
```

If `IsCanonical` returns `false`, the tool iterates the ACEs manually to identify the specific ordering violation for the warning message. A non-canonical ACL is detected when:

1. An explicit ACE follows an inherited ACE, or
2. A deny ACE follows an allow ACE among explicit ACEs

`CommonAcl.IsCanonical` correctly accounts for inheritance scope levels, where ACEs at different inheritance depths may have different canonical ordering rules.

### Callback and Audit ACE Types

- Callback ACE types are returned by `GetAccessRules()` as `ActiveDirectoryAccessRule` objects but without their conditional expression data. They are treated identically to non-callback ACEs. **This is a documented limitation** — the reported permissions may not reflect effective conditional access.
- Audit and mandatory label ACEs are parsed by the framework. `GetAccessRules()` returns only DACL access rules; audit rules would come from `GetAuditRules()`. Since the tool only processes DACLs, audit ACEs are not encountered in normal operation.

### Objects with No DACL

If an object has no DACL (null DACL, meaning unrestricted access), this represents a significant security concern. The tool should report this as a `Warning` with a message indicating that the object has no discretionary access control.

### Empty objectClass

If an object's `objectClass` attribute is present but empty (`SearchResult.Properties["objectClass"].Count == 0`), the tool logs an error to stderr and skips the object, continuing the scan. This replaces the previous behavior of crashing (panicking) on this condition.

If the `objectClass` attribute is missing entirely, the error is recorded for that object and scanning continues.

### `objectClass` Ordering Assumption

The tool assumes the multi-valued `objectClass` attribute is ordered with the most-specific class last. This is standard AD behavior. For `inetOrgPerson` objects, the `objectClass` list would be `top`, `person`, `organizationalPerson`, `user`, `inetOrgPerson` — the last value correctly identifies the most-specific class.

---

## 13. Performance and Scalability Considerations

### Query Optimization

- **Paged searches** with `PageSize = 1000` prevent the server from rejecting large result sets.
- **Attribute selection**: Only specific attributes are requested via `PropertiesToLoad`, reducing network traffic.
- **Security masks**: `DirectorySearcher.SecurityMasks` requests only the DACL and owner, reducing security descriptor data transferred.

### Memory Management

- After scanning each naming context, records with no findings are pruned (retaining only records with actual results or parent records needed for CREATE_CHILD analysis).
- `SearchResultCollection` from `DirectorySearcher.FindAll()` MUST be disposed to release unmanaged LDAP result handles. Use a `using` statement.
- Results can be processed one at a time via enumeration of `SearchResultCollection`, enabling a streaming approach that avoids loading all results into memory simultaneously.

### SID Resolution Cache Lifecycle

The SID resolution cache persists for the entire duration of the tool's execution. It is populated during the main scan and reused during CSV generation. In large forests with hundreds of thousands of unique SIDs, the cache may consume significant memory. The cache is not bounded or evicted — it grows monotonically. This is an acceptable trade-off for avoiding redundant LDAP lookups.

### Schema Cache

The entire schema (class GUIDs, attribute GUIDs, property sets, validated writes, control access rights) is loaded once at startup and reused for all naming contexts.

### Single-Threaded Processing

The tool processes naming contexts sequentially and does not parallelize queries across partitions. This is a documented constraint. .NET Framework 2.0 lacks `async/await`, making parallelization significantly harder (requiring manual threading). Single-threaded processing is simpler, more predictable, and sufficient for the tool's use case.

### Scalability

- The main scan performs one subtree search per naming context, which in large forests can return millions of objects.
- Each object's security descriptor is parsed in-memory, and its DACL ACEs are filtered immediately. Only objects with findings are retained.
- Expected delegation ACEs are indexed by SID and location for efficient lookup during the matching phase.

---

## 14. Error Handling and Fault Tolerance

### Exit Codes

The tool uses differentiated exit codes for scripting and automation:

| Exit Code | Meaning |
|---|---|
| 0 | Success (findings exported to CSV, or no findings) |
| 1 | General/unexpected error |
| 2 | Connection/authentication failure (`DirectoryServicesCOMException` or `ActiveDirectoryObjectNotFoundException`) |
| 3 | Input file parsing error (templates, delegations — `XmlException` or `InvalidOperationException` from `XmlSerializer`) |
| 4 | Output file error (cannot write CSV — `IOException`, `UnauthorizedAccessException`) |

### Graceful Degradation Per Naming Context

A search-level error during the main scan of a naming context should NOT abort the entire run. The tool catches `DirectoryServicesCOMException` per naming context:

- **Non-transient errors** (e.g., `LDAP_INSUFFICIENT_RIGHTS`, `LDAP_NO_SUCH_OBJECT`): Log the error to stderr, skip the naming context, continue with remaining NCs.
- **Summary reporting**: At the end of the scan, report which naming contexts were successfully scanned and which failed, via `Console.Error.WriteLine()`.

### Per-Object Error Handling

- Invalid security descriptors or unreadable attributes produce an error recorded per-object. Scanning continues for subsequent objects.
- If `objectClass` is present but empty, log an error and skip the object.
- If `objectClass` is missing, record the error and continue.
- All per-object processing is wrapped in `try/catch` to prevent a single object failure from aborting the naming context scan.

### Error Counter and Messaging

The error counter tracks all per-location error entries, not just unreadable security descriptors. The summary message accurately reflects this:

```
[!] {count} objects could not be fully processed, use --show-warning-unreadable to see details
```

This corrects the previous misleading message that stated "security descriptors could not be read."

### `--show-warning-unreadable` Behavior

When `--show-warning-unreadable` is specified, each per-location processing error generates a CSV record with category `Warning` and the error details. Error types covered include:

- Unreadable security descriptors (failed `nTSecurityDescriptor` reads)
- Missing or unreadable `objectClass` attributes
- Unparseable schema `defaultSecurityDescriptor` SDDL strings

Without this flag, errors are silently counted and only the summary count is printed to stderr.

### XML Parsing Errors

Template and delegation XML files that fail to parse or validate against the XSD schema produce error messages to stderr and cause the tool to exit with code 3.

### Progress Reporting

The tool reports progress to stderr throughout execution:

```csharp
Stopwatch stopwatch = Stopwatch.StartNew();
// During scan:
Console.Error.Write(String.Format("\r[{0}] {1} objects processed...", ncDN, count));
// After each NC:
Console.Error.WriteLine(String.Format("[*] {0}: {1} objects, {2} findings", ncDN, objectCount, findingCount));
// Final summary:
Console.Error.WriteLine(String.Format("[Done] {0} objects, {1} findings, elapsed: {2}", total, findings, stopwatch.Elapsed));
```

Progress messages use `Console.Error` to keep stdout clean for CSV data. `System.Diagnostics.Stopwatch` provides precise elapsed-time tracking.

---

## 15. Assumptions and Limitations

### Assumptions

1. **Single forest scope**: The tool assumes all naming contexts returned by the RootDSE belong to the same forest. Cross-forest trusts are not traversed.
2. **Standard schema**: Object type GUIDs and class names are expected to match the standard Active Directory schema. Custom schema extensions are supported as long as the schema is loaded dynamically.
3. **Canonical ACL structure**: The tool assumes ACLs follow the canonical order for correct analysis, but explicitly detects and warns about non-canonical ACLs using `CommonAcl.IsCanonical`.
4. **AdminSDHolder behavior**: Objects with `adminCount != 0` are assumed to have their DACLs managed by SDProp. Stale `adminCount` is detected by cross-referencing with `AreAccessRulesProtected`.
5. **Creator Owner semantics**: ACEs with the `Creator Owner` SID in schema defaults are replaced by the object's current owner SID at comparison time, following standard AD behavior.
6. **objectClass ordering**: The multi-valued `objectClass` attribute is assumed to be ordered with the most-specific class last.
7. **.NET Framework 2.0 target**: The tool is built for .NET Framework 2.0 for intentional backward compatibility. This means no LINQ, no `HashSet<T>`, no `async/await`, no `string.IsNullOrWhiteSpace()`, and no `Enum.HasFlag()`.

### Limitations

1. **No SACL analysis**: The tool only inspects the DACL. The SACL (used for auditing) is not analyzed.
2. **No effective permissions calculation**: The tool reports individual ACEs and delegations, not effective cumulative permissions. Deny ACEs, group memberships, and ACE ordering must be manually considered.
3. **Callback ACE conditions not evaluated**: Callback ACE types are parsed and reported, but their conditional expressions are not evaluated. Reported permissions may not reflect effective conditional access.
4. **Single-threaded processing**: Naming contexts are processed sequentially. No parallelization across partitions.
5. **Dynamic schema only**: The schema is loaded from the connected directory at runtime. Incomplete or corrupted schemas may produce raw GUID strings in output.
6. **OBJECT_INHERIT_ACE simplification**: The `ObjectInherit` flag is masked out during ACE comparison, which may produce incorrect results for AD leaf objects (e.g., DNS records).
7. **Schema default false negatives**: Explicit ACEs that happen to match schema defaults are suppressed, potentially hiding intentional configurations.
8. **Most-specific class only**: Default security descriptors are computed from only the most-specific class, not the full structural class hierarchy.
9. **Stale adminCount**: Objects with stale `adminCount=1` that are no longer SDProp-managed may have ACEs incorrectly filtered. The `AreAccessRulesProtected` cross-check mitigates but does not eliminate this.
10. **No offline/snapshot mode**: The tool requires a live LDAP connection; it does not support loading from offline dumps.
11. **Incomplete group membership for owner analysis**: The CREATE_CHILD owner analysis uses `tokenGroups` for group membership, which may not reflect all transitive group memberships across domain boundaries with selective authentication.
12. **SID resolution cache is unbounded**: In extremely large forests, the cache may consume significant memory.
