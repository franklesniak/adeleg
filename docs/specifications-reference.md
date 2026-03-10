# ADeleg CSV Export — Technical Specification

This document describes the internal behavior of the ADeleg tool with a focus on its CSV export functionality. It covers the full processing pipeline from Active Directory queries through final CSV output, enabling developers and auditors to understand and validate its behavior.

---

## 1. Active Directory Scope and Query Locations

### Naming Contexts Queried

ADeleg queries the following Active Directory partitions, discovered dynamically at runtime from the RootDSE:

| Partition | RootDSE Attribute | Purpose |
|---|---|---|
| Schema | `schemaNamingContext` | Retrieve class definitions, attribute definitions, default security descriptors |
| Configuration | `configurationNamingContext` | Retrieve extended rights, control access rights, validated writes, property sets |
| All naming contexts | `namingContexts` | Scan every object in each naming context (including schema, configuration, domain, and application partitions) for explicit (non-inherited) ACEs |
| Root domain | `rootDomainNamingContext` | Used as a fallback domain reference |

### RootDSE Bootstrap

On connection, ADeleg reads the RootDSE (a base-scoped search with no base DN) to retrieve:

- `namingContexts` — the list of all naming contexts hosted by the server
- `schemaNamingContext` — the DN of the Schema partition
- `configurationNamingContext` — the DN of the Configuration partition
- `rootDomainNamingContext` — the DN of the forest root domain
- `supportedControl` — the set of LDAP controls the server supports

These values are stored in the `LdapConnection` struct (`winldap/src/connection.rs`) and used throughout the tool.

### Recursive Traversal

- **Schema partition**: queried with `LDAP_SCOPE_SUBTREE` to enumerate all `classSchema` objects (for class GUIDs and default security descriptors) and all `attributeSchema` objects (for attribute GUIDs).
- **Configuration partition**: queried with `LDAP_SCOPE_SUBTREE` to enumerate `controlAccessRight` objects for property sets, validated writes, and control access rights.
- **Each naming context** (including schema, configuration, domain, and application partitions): queried with `LDAP_SCOPE_SUBTREE` using the filter `(objectClass=*)`, which returns every object in the partition recursively.
- **AdminSDHolder**: queried with `LDAP_SCOPE_BASE` at `CN=AdminSDHolder,CN=System,<domain DN>`.
- **Individual SID lookups**: queried with `LDAP_SCOPE_BASE` using synthetic DNs like `<SID=S-1-5-...>`.

---

## 2. Directory Query Mechanics

### APIs and Libraries

ADeleg is a Rust application that uses the Windows LDAP C API (`wldap32.dll`) via the `winldap` crate (local workspace crate). Key functions used:

| Windows API Function | Purpose |
|---|---|
| `ldap_initW` | Initialize connection handle |
| `ldap_connect` | Establish TCP connection (2-second timeout) |
| `ldap_bind_sW` | Authenticate (Negotiate/SPNEGO by default; explicit credentials supported) |
| `ldap_search_ext_sW` | Execute synchronous paged search requests |
| `ldap_create_page_controlW` | Create paging controls for large result sets |
| `ldap_parse_page_controlW` | Parse paging cookies from server responses |

The `LdapSearch` struct (`winldap/src/search.rs`) implements the `Iterator` trait, yielding `LdapEntry` results one at a time while transparently handling LDAP paging.

### LDAP Filters Used

| Query Target | Filter | Attributes Requested |
|---|---|---|
| Schema classes | `(objectClass=classSchema)` | `schemaIDGUID`, `lDAPDisplayName`, `defaultSecurityDescriptor` |
| Schema attributes | `(objectClass=attributeSchema)` | `schemaIDGUID`, `lDAPDisplayName` |
| Property sets | `(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Validated writes | `(&(objectClass=controlAccessRight)(validAccesses=8)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| Control access rights | `(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*))` | `rightsGuid`, `displayName` |
| All naming contexts (main scan) | `(objectClass=*)` | `nTSecurityDescriptor`, `objectClass`, `objectSID`, `adminCount`, `msDS-KrbTgtLinkBl`, `serverReference` |
| AdminSDHolder | `(objectClass=*)` | `nTSecurityDescriptor` |
| Domain enumeration | `(&(nCName=*)(nETBIOSName=*))` | `nCName`, `nETBIOSName` |

### LDAP Referral Handling

LDAP referrals are explicitly disabled via `ldap_set_option` with `LDAP_OPT_REFERRALS` set to `0`. This prevents DNS resolution attempts for referrals that could hang when running the tool from outside the domain.

---

## 3. Paging, Batching, and Performance Considerations for Queries

### Paged Search

All LDAP searches use paged result controls with a page size of **999** entries per page. This is implemented in `LdapSearch::next()`:

1. A page control is created via `ldap_create_page_controlW(handle, 999, ...)`.
2. After receiving a page, the paging cookie is extracted via `ldap_parse_page_controlW`.
3. If the cookie is empty, the last page has been reached.
4. Otherwise, the cookie is sent with the next request to continue.

### Security Descriptor Retrieval Control

When retrieving security descriptors, ADeleg sends the `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`) control to request only the specific parts of the security descriptor needed:

- For the main scan: `OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION`
- For AdminSDHolder: `DACL_SECURITY_INFORMATION` only

This reduces the amount of data transferred by excluding the SACL and primary group, which are not needed for delegation analysis.

---

## 4. Retrieval of Security Descriptors and ACEs

### Security Descriptor Parsing

Security descriptors are read from the `nTSecurityDescriptor` attribute as raw binary blobs. Parsing is performed in the `authz` crate:

1. **`SecurityDescriptor::from_bytes()`** (`authz/src/security_descriptor.rs`): Validates the descriptor with `IsValidSecurityDescriptor`, then extracts:
   - `revision` and `controls` (via `GetSecurityDescriptorControl`)
   - `owner` SID (via `GetSecurityDescriptorOwner`)
   - `group` SID (via `GetSecurityDescriptorGroup`)
   - `dacl` (via `GetSecurityDescriptorDacl`)
   - `sacl` (via `GetSecurityDescriptorSacl`)

2. **`SecurityDescriptor::from_str()`**: Parses SDDL string representations (used for schema `defaultSecurityDescriptor` attributes) by calling `ConvertStringSecurityDescriptorToSecurityDescriptorW`, then parsing the resulting binary form.

### ACL and ACE Extraction

The DACL is parsed by `Acl::from()` (`authz/src/acl.rs`):

1. Calls `GetAclInformation` to get the ACE count.
2. Iterates through each ACE using `GetAce`.
3. Each ACE is parsed by `Ace::from_bytes()` (`authz/src/ace.rs`), which handles the following ACE types:
   - `ACCESS_ALLOWED_ACE_TYPE`
   - `ACCESS_ALLOWED_OBJECT_ACE_TYPE`
   - `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`
   - `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`
   - `ACCESS_DENIED_ACE_TYPE`
   - `ACCESS_DENIED_OBJECT_ACE_TYPE`
   - `ACCESS_DENIED_CALLBACK_ACE_TYPE`
   - `ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE`
   - `SYSTEM_AUDIT_ACE_TYPE`
   - `SYSTEM_AUDIT_OBJECT_ACE_TYPE`
   - `SYSTEM_AUDIT_CALLBACK_ACE_TYPE`
   - `SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE`
   - `SYSTEM_MANDATORY_LABEL_ACE_TYPE`

### Object Types Inspected

Every object in every naming context is inspected. The tool does not filter by object class during the LDAP query itself — instead it retrieves all objects via `(objectClass=*)` and processes each one's security descriptor.

---

## 5. Detection of Inherited vs Explicit Permissions

### Inherited ACE Detection

An ACE is determined to be inherited by checking the `INHERITED_ACE` flag in the ACE header's `AceFlags` field:

```rust
// authz/src/ace.rs
pub fn is_inherited(&self) -> bool {
    (self.flags & (INHERITED_ACE.0 as u8)) != 0
}
```

The `INHERITED_ACE` flag (value `0x10`) is set by Active Directory on ACEs that were propagated from a parent container.

### Exclusion of Inherited Permissions

In `Engine::is_ace_interesting()` (`engine.rs`), the very first check is:

```rust
if ace.is_inherited() {
    return false; // ignore inherited ACEs
}
```

This means **only explicitly assigned (non-inherited) ACEs are included in the output**. The tool's goal is to report delegations that were explicitly configured, not those that flow down from parent containers through inheritance.

---

## 6. Filtering of Default or Built-in Permissions

### Schema Default Security Descriptors

Each AD class can have a `defaultSecurityDescriptor` attribute in SDDL form. ADeleg parses these for every class and computes the ACEs that would be derived by inheritance from the schema defaults for each object's class. An ACE that matches a schema default is excluded:

```rust
if default_aces.iter().any(|default_ace| ace_equivalent(default_ace, ace)) {
    return false;
}
```

The `ace_equivalent()` function compares two ACEs while ignoring:
- **Read-only access rights** (`IGNORED_ACCESS_RIGHTS`): `ADS_RIGHT_READ_CONTROL`, `ADS_RIGHT_ACTRL_DS_LIST`, `ADS_RIGHT_DS_LIST_OBJECT`, `ADS_RIGHT_DS_READ_PROP`
- **Object inherit flag** (`IGNORED_ACE_FLAGS`): `OBJECT_INHERIT_ACE`. The source code comment states "there is no 'object' in Active Directory, only containers"; in practice this flag is simply masked out during ACE comparison so that two ACEs differing only in this flag are treated as equivalent

### Creator Owner Handling in Schema Defaults

When computing inherited ACEs from schema defaults, if the parent ACE's trustee is the `Creator Owner` SID (`S-1-3-0`), it is replaced by the actual owner SID of the child object (mirroring AD behavior). Both the replaced and original ACEs are produced as defaults.

### Ignored Trustee SIDs

ACEs for the following well-known SIDs are suppressed, since these principals already have inherent full control:

| SID | Identity |
|---|---|
| `S-1-5-10` | SELF |
| `S-1-5-18` | Local System |
| `S-1-5-20` | Network Service |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-9` | Enterprise Domain Controllers |
| `S-1-5-32-548` | Account Operators |
| `S-1-5-32-549` | Server Operators |
| `S-1-5-32-550` | Print Operators |
| `S-1-5-32-551` | Backup Operators |
| `<domain SID>-512` | Domain Admins (per domain) |
| `<domain SID>-516` | Domain Controllers (per domain) |
| `<domain SID>-518` | Schema Admins (per domain) |
| `<domain SID>-519` | Enterprise Admins (per domain) |

### Read-Only Access Rights

ACEs whose access mask, after masking out read-only rights, results in zero are discarded:

```rust
let problematic_rights = ace.access_mask & !(IGNORED_ACCESS_RIGHTS);
if problematic_rights == 0 {
    return false;
}
```

The ignored (read-only) access rights are: `READ_CONTROL`, `ACTRL_DS_LIST`, `DS_LIST_OBJECT`, `DS_READ_PROP`.

### Delete Protection ACEs

Deny ACEs for `Everyone` (`S-1-1-0`) that only deny `DELETE`, `DS_DELETE_CHILD`, and/or `DS_DELETE_TREE` are suppressed, as these are standard delete-protection entries.

### Change Password Deny ACEs

Deny ACEs for `Everyone` that deny the `Change Password` control access right are suppressed, as these are set by tools like `dsa.msc` for the "Cannot change password" option.

### AdminSDHolder ACEs

For objects with a non-zero `adminCount` (the code checks `adminCount != "0"`, defaulting to `"0"` if the attribute is missing or unreadable), ACEs that appear in the AdminSDHolder DACL are suppressed. This is because the SDProp process copies the AdminSDHolder's DACL onto protected objects.

### Ignored Control Access Rights

ACEs granting only `DS_CONTROL_ACCESS` for specific control access rights that do not grant meaningful control over a resource are suppressed:

- `Apply Group Policy` — applying a GPO does not mean controlling it
- `Allow a DC to create a clone of itself` — if an attacker can impersonate a DC, cloning is not the primary concern

### Ignored DACL Protected Flags

DACL inheritance blocking is not reported as a warning for:
- Objects of class `groupPolicyContainer` (GPOs block inheritance by design)
- Objects with `adminCount != 0` (expected to block inheritance via SDProp)
- Specific well-known containers: `CN=AdminSDHolder,CN=System`, `CN=VolumeTable,CN=FileLinks,CN=System`, `CN=Keys`, `CN=WMIPolicy,CN=System`, `CN=SOM,CN=WMIPolicy,CN=System`

### Built-in Delegation Definitions

The file `builtin_delegations.json` (embedded at compile time) defines expected ACEs for well-known delegations (e.g., DnsAdmins on DNS zones, Group Policy Creator Owners on WMI policies). These are loaded as `Delegation` objects with `builtin: true` and are matched against discovered ACEs. By default, matched built-in delegations are excluded from CSV output unless `--show-builtin` is specified.

### RODC-Specific Filtering

The tool suppresses several ACE patterns specific to Read-Only Domain Controllers (RODCs):
- Change Password / Reset Password control access by an RODC on its secondary KrbTgt account
- CREATE_CHILD on `nTDSDSA` objects by the RODC referenced from the server object, and DELETE on `nTDSDSA` objects only when the ACE has the `inherit_only` flag set
- WRITE_PROP for `schedule` and `fromServer` attributes on `nTDSConnection` objects by the owning RODC
- Validated write for `dnsHostName` on `server` objects by the referenced RODC

---

## 7. Security Identifier (SID) Resolution

### Resolution Strategy

SID resolution is performed by `Engine::resolve_sid()` in `engine.rs` using a multi-step approach:

1. **Cache lookup**: Check `resolved_sid_to_dn` (a `RefCell<HashMap<Sid, String>>`) for a previously resolved display name. Despite its field name, this cache stores either a distinguished name (DN) **or** a locally-resolved `DOMAIN\Username` string, depending on which resolution path populated it.
2. **Local well-known SID resolution**: Call `LookupAccountSidLocalW` (loaded dynamically from `sechost.dll` via `GetProcAddress`) to resolve well-known SIDs to `DOMAIN\Username` format. If successful, the resulting `DOMAIN\Username` string is stored in `resolved_sid_to_dn`, and the `SID_NAME_USE` value returned by the API is used to determine the `PrincipalType`.
3. **LDAP SID-based lookup**: Perform a base-scoped LDAP search using the synthetic DN `<SID=S-1-5-...>` and retrieve the `objectClass` attribute to determine the principal type. If successful, the object's DN is stored in `resolved_sid_to_dn`.

### Cache Population

The SID-to-display-name cache (`resolved_sid_to_dn`) is populated from multiple sources during the tool's operation:
- **During the main scan**: When an object has an `objectSid` attribute, the mapping from SID → DN is stored.
- **During local resolution**: When `LookupAccountSidLocalW` succeeds, the mapping from SID → `DOMAIN\Username` is stored.
- **During LDAP SID lookup**: When a `<SID=...>` LDAP search succeeds, the mapping from SID → DN is stored.
- For domain-specific SIDs, the mapping is always stored during the main scan.
- For well-known SIDs (e.g., those in `CN=ForeignSecurityPrincipals`), the tool first attempts `LookupAccountSidLocalW` and only falls back to the DN if that fails.

### Principal Type Resolution

Each resolved SID is also mapped to a `PrincipalType` enum. The mapping depends on the resolution path:

- **From LDAP (objectClass-based)**: The most specific class (last value of the multi-valued `objectClass` attribute) is compared via case-insensitive exact match:
  - `Computer` — most specific class is exactly `"computer"`
  - `User` — most specific class is exactly `"user"`
  - `Group` — most specific class is exactly `"group"`
  - `External` — any other class name
- **From local resolution (`LookupAccountSidLocalW`)**: The `SID_NAME_USE` value returned by the API is mapped:
  - `SidTypeUser` → `User`
  - `SidTypeGroup` → `Group`
  - `SidTypeComputer` → `Computer`
  - All other values → `External`

### Unresolved and Orphaned SIDs

- If resolution fails entirely (no cache hit, `LookupAccountSidLocalW` fails, and LDAP lookup fails), `resolve_sid()` returns `None`. In CSV output, the raw SID string (e.g., `S-1-5-21-...`) is used as the trustee name, with type `External`.
- During post-processing, for each naming context, ACEs whose trustee SID shares a prefix with the naming context's associated domain SID (or the root domain SID for non-domain naming contexts like schema/configuration) and cannot be resolved are moved from the "orphan ACEs" list to the "deleted trustee" list. This means unresolvable SIDs from other domains remain as orphan ACEs with raw SID trustee strings.

---

## 8. Permission and Rights Interpretation

### Access Mask Mapping

The `Engine::describe_ace()` method maps individual bits in the 32-bit access mask to human-readable descriptions. When `resolve_names` is `true` (the default for CLI), the following mappings apply:

| Access Right Constant | Bit Value | Human-Readable Description |
|---|---|---|
| `ADS_RIGHT_DS_WRITE_PROP` | `0x20` | "Write attribute {name}" (attribute GUID match), "Write attributes of category {name}" (property set GUID match), or "Write all properties" (no match/no GUID) |
| `ADS_RIGHT_DS_CONTROL_ACCESS` | `0x100` | "{Control access name}" or "Perform all application-specific operations" |
| `ADS_RIGHT_DS_CREATE_CHILD` | `0x1` | "Create child {class} objects" or "Create child objects of any type" |
| `ADS_RIGHT_DS_DELETE_CHILD` | `0x2` | "Delete child {class} objects" or "Delete child objects of any type" |
| `ADS_RIGHT_WRITE_OWNER` | `0x80000` | "Change the owner" |
| `ADS_RIGHT_WRITE_DAC` | `0x40000` | "Add/delete delegations" |
| `ADS_RIGHT_DELETE` | `0x10000` | "Delete" |
| `ADS_RIGHT_DS_DELETE_TREE` | `0x40` | "Delete along with all children" |
| `ADS_RIGHT_DS_SELF` | `0x8` | "{Validated write name}" or "Perform all validated writes" |
| `ADS_RIGHT_ACCESS_SYSTEM_SECURITY` | `0x1000000` | "Add/delete auditing rules" |

### Object Type GUID Resolution

In **resolved-name mode** (the default), the `object_type` GUID is not resolved through a single global lookup order. Instead, the resolution is **conditional on which access right bit is set** in the access mask. Each access right checks only the schema categories relevant to it:

| Access Right | GUID Resolution Order |
|---|---|
| `WRITE_PROP` | attribute GUID → property set GUID → (fallback: "Write all properties") |
| `CONTROL_ACCESS` | control access right GUID → (fallback: "Perform all application-specific operations") |
| `CREATE_CHILD` | class GUID → (fallback: "Create child objects of any type") |
| `DELETE_CHILD` | class GUID → (fallback: "Delete child objects of any type") |
| `DS_SELF` | validated write GUID → (fallback: "Perform all validated writes") |

In **raw mode** (`--show-raw`), the GUID is resolved through a single sequential lookup across all schema categories in this order:
1. Class GUID → class name (from `schema.class_guids`)
2. Attribute GUID → attribute name (from `schema.attribute_guids`)
3. Control access right GUID → control access name (from `schema.control_access_names`)
4. Property set GUID → property set name (from `schema.property_set_names`)
5. Validated write GUID → validated write name (from `schema.validated_write_names`)

### Inherited Object Type Resolution

When an ACE has an `inherited_object_type` GUID, it is resolved against class GUIDs to determine which child object type the ACE applies to. This is appended as ", on all {class_name} child objects".

### Inheritance Scope Description

If `container_inherit` is true, the description includes scope information:
- "on all {class} child objects" if `inherited_object_type` resolves to a class
- "on all child objects" otherwise
- "and the container itself" is appended if `inherit_only` is false

### Raw Mode

When `--show-raw` is specified (`resolve_names` = false), access rights are shown as raw constant names and hex values (e.g., `WRITE_PROP (0x20) OBJECT_GUID=...`), including GUID lookups for classes, attributes, control accesses, property sets, and validated writes.

---

## 9. Data Processing and Transformation Pipeline

The pipeline from directory query to CSV output follows these steps:

### Step 1: Connection and Bootstrap
- Establish LDAP connection (`LdapConnection::new`)
- Read RootDSE for naming contexts and schema/configuration DNs
- Enumerate domains from `CN=Partitions,{configurationNC}` to get domain SIDs and NetBIOS names

### Step 2: Schema Loading
- Query all `classSchema` objects for class GUIDs and `defaultSecurityDescriptor` SDDL strings
- Query all `attributeSchema` objects for attribute GUIDs
- Query `controlAccessRight` objects for property sets (validAccesses=48), validated writes (validAccesses=8), and control access rights (validAccesses=256)

### Step 3: Delegation and Template Loading
- Parse built-in delegations from `builtin_delegations.json` (embedded at compile time)
- Optionally load user-provided templates (`--templates`) and delegations (`--delegations`) from JSON files
- For each delegation, derive expected ACEs by resolving trustees and locations, and index them by SID → Location

### Step 4: Schema ACE Analysis (`get_schema_aces`)
- For each `classSchema` with a `defaultSecurityDescriptor`:
  - Parse the SDDL string into a `SecurityDescriptor` for each domain
  - Filter the DACL ACEs through `is_ace_interesting()`
  - Store remaining ACEs as `orphan_aces` in an `AdelegResult`

### Step 5: Explicit ACE Analysis (`get_explicit_aces`)
- For each naming context, perform a subtree search retrieving security descriptors
- For each object:
  - Parse the security descriptor
  - Compute expected default ACEs from the schema (as if inherited from the class definition)
  - Filter each DACL ACE through `is_ace_interesting()`, which excludes: inherited ACEs, read-only ACEs, schema default ACEs, AdminSDHolder ACEs, ignored trustee ACEs, and special-case ACEs
  - Build an `AdelegResult` with owner, DACL protection status, ACL canonicality, and orphan ACEs

### Step 6: Post-Processing
1. **Memory optimization**: Remove records with no findings (no orphan ACEs, no owner issues, no warnings), but retain parent container records needed for CREATE_CHILD analysis
2. **Deleted trustee detection**: For each naming context, determine the associated domain SID (or the root domain SID for non-domain naming contexts such as schema/configuration). Check if orphan ACE trustees whose SIDs share a prefix with that domain SID (via `shares_prefix_with(domain_sid.with_rid(0))`) can be resolved; if not, move them to `deleted_trustee`
3. **KDS root key handling**: Suppress DACL protection warnings for KDS root key objects in the Configuration partition
4. **Owner analysis via CREATE_CHILD**: For each object with a non-ignored owner, walk up the container hierarchy checking if the owner has CREATE_CHILD permissions — if so, suppress the owner finding (the owner created the object)
5. **Parent object ACE suppression**: Remove ACEs whose trustees are parent objects (e.g., computers controlling their own BitLocker recovery objects)

### Step 7: Delegation Matching
1. For each expected delegation (from builtin + user-defined), create or update an `AdelegResult` entry, initially marking all expected ACEs as "missing"
2. For each location, match orphan ACEs against expected delegation ACEs using `ace_equivalent()`:
   - If a match is found, the ACE moves from `orphan_aces` to `aces_found` for that delegation
   - The corresponding entry in `aces_missing` is removed
   - One ACE can match multiple delegations
3. For built-in delegations, clear all `aces_missing` (do not flag missing built-in ACEs)

### Step 8: CSV Generation
- Iterate over all `(DelegationLocation, Result<AdelegResult, AdelegError>)` entries
- For each entry, write CSV records for: errors/warnings, owner, DACL protection, non-canonical ACL, deleted trustees, orphan ACEs, and matched delegations

---

## 10. CSV Export Structure

### Triggering CSV Export

CSV export is triggered by the `--csv <path>` command-line argument. If the path is `-`, output goes to stdout. Otherwise, a file is created (or truncated if it exists).

### CSV Schema

The CSV output has **5 columns**, written using the `csv` crate (version 1.1.6):

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
| `Warning` | A structural issue: unreadable SD, blocked DACL inheritance, or non-canonical ACL |
| `Allow ACE` | An explicit allow ACE that is not explained by any known delegation |
| `Deny ACE` | An explicit deny ACE that is not explained by any known delegation |
| `Built-in` | A delegation that matches a built-in (well-known) delegation definition (only shown with `--show-builtin`) |
| `Delegation` | A delegation that matches a user-defined delegation definition |
| `Expected allow ACE found` | An individual allow ACE that was expected and found in place |
| `Expected deny ACE found` | An individual deny ACE that was expected and found in place |
| `Expected allow ACE missing` | An individual allow ACE that was expected but not found |
| `Expected deny ACE missing` | An individual deny ACE that was expected but not found |

### Record Generation Logic

For each `(location, result)` pair in the scan results:

1. **Per-location processing errors** (if `--show-warning-unreadable`): One `Warning` record with the error message. This covers any `Err` entry in the results map, including unreadable security descriptors, missing/unreadable `objectClass` attributes, and unparseable schema `defaultSecurityDescriptor` SDDL strings.
2. **Owner**: One `Owner` record if the object's owner is not in the ignored trustee set and was not filtered by CREATE_CHILD analysis.
3. **DACL protection**: One `Warning` record if the DACL has the `SE_DACL_PROTECTED` flag set and the object is not in an excluded category.
4. **Non-canonical ACL**: One `Warning` record if the ACL is not in canonical order (deny before allow, or explicit after inherited). The offending ACE is described.
5. **Deleted trustees**: One `Warning` record per ACE whose trustee no longer exists.
6. **Orphan ACEs**: One `Allow ACE` or `Deny ACE` record per unmatched ACE, with the access rights described.
7. **Delegations**: For each matched delegation (built-in only if `--show-builtin`):
   - One `Built-in` or `Delegation` record whose Details field is the output of `describe_delegation_rights()`: either the template name (for `TemplateName`/`Template` variants) or an `"Allow/Deny {describe_ace(...)}"` string (for individual `Ace` variants)
   - One `Expected allow/deny ACE found` record per matched ACE
   - One `Expected allow/deny ACE missing` record per unmatched expected ACE

### Formatting and Encoding

- The CSV is written using the Rust `csv` crate, which produces RFC 4180-compliant output.
- Fields containing commas, quotes, or newlines are automatically quoted.
- Encoding is UTF-8.
- There is no explicit row ordering within the CSV beyond the iteration order of the internal `HashMap<DelegationLocation, ...>`, which is non-deterministic. The order of records across different runs is not guaranteed.

---

## 11. Delegation and Object Context

### Resource Representation

Resources in the CSV `Resource` column are represented as:
- **Distinguished Names (DNs)**: Full LDAP DNs like `CN=Users,DC=example,DC=com` for objects within any naming context (domain, configuration, schema, or application partitions).
- **Schema references**: Formatted as `Schema: default security descriptor of class '{className}'` for default security descriptors in the schema.
- **`Global`**: Used for non-location-specific findings.

### Location Resolution for Delegations

Delegation definitions can use wildcard patterns for locations:
- `DC=*` — expanded to each domain's DN in the forest
- `CN=Configuration,DC=*` — expanded to the Configuration naming context
- `CN=Schema,DC=*` — expanded to the Schema naming context
- `DC=DomainDnsZones,DC=*` / `DC=ForestDnsZones,DC=*` — expanded using the root domain NC

### Handling of OUs, Containers, and Domain-Level Delegations

The tool does not distinguish between OUs, containers, and other objects at the query level — all objects are scanned uniformly. The object's `objectClass` is used post-query to determine its most specific class (the last value in the multi-valued `objectClass` attribute), which influences:
- Which schema default security descriptor to compare against
- The class GUID used for CREATE_CHILD analysis
- Specific filtering rules (e.g., `groupPolicyContainer` for DACL protection)

---

## 12. Handling of Special or Edge Cases

### Deleted Objects and Tombstones

- The tool does not explicitly query the Deleted Objects container or tombstones.
- ACEs referencing SIDs that share a prefix with the current naming context's associated domain SID (or root domain SID for non-domain naming contexts) and cannot be resolved are flagged as `deleted_trustee` and reported with a "Warning" category in the CSV, noting that the trustee no longer exists and should be cleaned up. Unresolvable SIDs from other domains or forests remain as orphan ACEs with raw SID trustee strings.

### Foreign Security Principals

- Objects in `CN=ForeignSecurityPrincipals` are encountered during the subtree scan.
- Well-known SIDs found via `objectSid` are preferentially resolved through `LookupAccountSidLocalW` rather than using their DN in the ForeignSecurityPrincipals container, so they appear with user-friendly names.
- Truly foreign (cross-forest) principals that cannot be resolved locally appear with their raw SID and `External` type.

### Denied Permissions

- Deny ACEs are processed and reported in the CSV with category `Deny ACE`.
- Deny ACEs are considered during delegation matching (expected deny ACEs can be defined in delegation JSON files).
- The tool checks ACL canonicality: if a deny ACE appears after an allow ACE among explicit (non-inherited) ACEs, or if an explicit ACE appears after an inherited one, it is flagged as non-canonical.

### Non-Canonical ACLs

A non-canonical ACL is detected when:
1. An explicit ACE follows an inherited ACE, or
2. A deny ACE follows an allow ACE among explicit ACEs

(In inherited ACEs, deny ACEs from grandparents may legitimately appear after allow ACEs from parents.)

### Callback and Audit ACE Types

The `authz` crate parses callback ACE types (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`, etc.) and audit ACE types. However, the engine's `is_ace_interesting()` and `grants_access()` methods treat callback ACEs the same as their non-callback counterparts. Audit and mandatory label ACEs are parsed and `grants_access()` returns `false` for them. Note that `is_ace_interesting()` does not explicitly filter them out by ACE type; if such ACEs appeared in a DACL with non-read access rights, they would pass the `is_ace_interesting()` filter and could trigger non-canonical ACL warnings (since `grants_access()` returns `false`, the canonicality check treats them like deny ACEs). In practice, audit/mandatory label ACEs do not normally appear in DACLs.

---

## 13. Performance and Scalability Considerations

### Query Optimization

- **Paged searches** with a page size of 999 prevent the server from rejecting large result sets.
- **Attribute selection**: Only the specific attributes needed are requested in each query (e.g., `nTSecurityDescriptor`, `objectClass`, `objectSID`), reducing network traffic.
- **SD flags control**: The `LDAP_SERVER_SD_FLAGS_OID` control requests only the DACL and owner (not the SACL or group), reducing the size of security descriptor data transferred.

### Memory Management

- After scanning each naming context, records with no findings are pruned (retaining only records with actual results or parent records needed for CREATE_CHILD analysis).
- The `LdapSearch` iterator processes entries one at a time rather than loading all results into memory at once.

### Caching

- **SID resolution cache**: `resolved_sid_to_dn` and `resolved_sid_to_type` are `RefCell<HashMap>` caches that prevent redundant LDAP lookups for the same SID. These are populated during the main scan and reused during CSV generation.
- **Schema cache**: The entire schema (class GUIDs, attribute GUIDs, property sets, validated writes, control access rights) is loaded once at startup and reused for all naming contexts.
- **`LookupAccountSidLocalW`**: Used to resolve well-known SIDs without network round-trips, loaded dynamically from `sechost.dll`.

### Scalability Considerations

- The main scan performs one subtree search per naming context, which in large forests can return millions of objects.
- Each object's security descriptor is parsed in-memory, and its DACL ACEs are filtered immediately. Only objects with findings are retained.
- Expected delegation ACEs are indexed in a `HashMap<Sid, HashMap<DelegationLocation, Vec<...>>>`, enabling efficient lookup during the matching phase.

---

## 14. Error Handling and Fault Tolerance

### LDAP Errors

- If the LDAP connection fails (`ldap_connect`, `ldap_bind_sW`), the tool prints an error message and exits with code 1.
- If the LDAP search itself fails (e.g., the server rejects the query or connection drops), the `LdapSearch` iterator returns `Err(LdapError)`. In `get_explicit_aces()`, search-level errors are propagated via `entry?`, which aborts scanning for that entire naming context (and currently the entire run).
- Per-object errors — such as failures to parse a security descriptor or read an attribute from a successfully-returned entry — are recorded as `Err(AdelegError::LdapQueryFailed(...))` entries in the result map for that object's location, and scanning continues for subsequent objects.
- These per-object error entries are reported in the CSV as `Warning` records if `--show-warning-unreadable` is enabled.

### Malformed Data

- Invalid security descriptors (failing `IsValidSecurityDescriptor`) produce an error that is stored per-object and optionally shown in the CSV.
- Invalid SDDL strings in schema `defaultSecurityDescriptor` attributes produce `AdelegError::UnableToParseDefaultSecurityDescriptor` errors.
- If an object's `objectClass` attribute is missing or unreadable, the error is recorded for that object (as `Err(AdelegError::LdapQueryFailed(...))`) and scanning continues. However, if the attribute is present but its value list is empty, the code panics via `.pop().expect("assertion failed: object with an empty objectClass!?")`, as this is considered an impossible condition in a valid Active Directory.

### Per-Location Processing Errors

The error counter (displayed as `warning_unreadable_count` in the code) tracks all per-location `Err` entries in the results map, not just unreadable security descriptors. This includes:
- Unreadable security descriptors (failed `nTSecurityDescriptor` attribute reads)
- Missing or unreadable `objectClass` attributes (`AdelegError::LdapQueryFailed`)
- Unparseable schema `defaultSecurityDescriptor` SDDL strings (`AdelegError::UnableToParseDefaultSecurityDescriptor`)

By default, these errors are silently counted and a summary message is printed to stderr:
```
[!] {count} security descriptors could not be read, use --show-warning-unreadable to see where
```
(Note: the message text says "security descriptors" but the count includes all per-location processing errors listed above.)

With `--show-warning-unreadable`, each error generates a CSV record with category `Warning`.

### JSON Parsing Errors

- Template and delegation JSON files that fail to parse produce error messages and cause the tool to exit with code 1.
- Unresolved template names, samAccountNames, or object type names in delegation files produce `AdelegError` variants and cause an exit.

---

## 15. Assumptions and Limitations

### Assumptions

1. **Single forest scope**: The tool assumes all naming contexts returned by the RootDSE belong to the same forest and that cross-forest trusts are not traversed.
2. **Standard schema**: Object type GUIDs and class names are expected to match the standard Active Directory schema. Extended or custom schema classes are supported as long as they follow standard naming conventions.
3. **Canonical ACL structure**: The tool assumes ACLs follow the canonical order (explicit deny, explicit allow, inherited deny, inherited allow) for correct analysis, but it explicitly detects and warns about non-canonical ACLs.
4. **AdminSDHolder behavior**: Objects with `adminCount != 0` are assumed to have their DACLs managed by SDProp. Their ACEs that match the AdminSDHolder DACL are excluded.
5. **Creator Owner semantics**: ACEs with the `Creator Owner` SID in schema defaults are assumed to be replaced by the object owner at creation time, following standard AD behavior.

### Limitations

1. **No SACL analysis**: The tool only inspects the DACL (discretionary ACL). The SACL (system ACL, used for auditing) is not analyzed or reported.
2. **No effective permissions calculation**: The tool reports individual ACEs and delegations, not the effective cumulative permissions for a principal. Deny ACEs, group memberships, and ACE ordering must be manually considered by the reviewer.
3. **Non-deterministic CSV ordering**: The CSV output order depends on `HashMap` iteration order, which is not deterministic across runs. The text output (non-CSV) sorts by location, but CSV does not.
4. **No offline/snapshot mode in the Rust codebase**: The Rust version requires a live LDAP connection; it does not support loading from offline dumps (unlike the C# version which supports ORADAD).
5. **Dynamic schema only**: The schema is loaded from the connected directory at runtime. If the schema is incomplete or corrupted, GUID resolution may fail, producing raw GUID strings in output.
6. **Callback ACE conditions not evaluated**: Callback ACE types are parsed and reported, but their conditional expressions are not evaluated, meaning the reported permissions may not reflect the effective conditional access.
7. **Single-threaded processing**: The tool processes naming contexts sequentially and does not parallelize queries across partitions.
8. **Incomplete group membership analysis**: The CREATE_CHILD owner analysis uses `tokenGroups` to check group membership, which may not reflect all transitive group memberships in all cases (e.g., across domain boundaries with selective authentication).

---

## 16. Security and Correctness Considerations

### Accuracy of Reported Delegations

- The tool reports **explicitly assigned** ACEs only. Inherited ACEs are excluded, which means the report reflects what was intentionally configured, not what is effectively in place through inheritance.
- Schema default ACEs are excluded, which may cause some explicitly-set ACEs that happen to match schema defaults to be incorrectly suppressed.
- The `ace_equivalent()` function ignores read-only rights and the `OBJECT_INHERIT_ACE` flag when comparing ACEs. This means two ACEs that differ only in these bits are treated as equivalent, which could mask subtle permission differences.

### Potential Ambiguities

1. **Owner-based implicit full control**: Object owners are reported in the CSV, but the implicit `WRITE_DAC` + `READ_CONTROL` rights they hold are not enumerated as separate ACEs. Reviewers must understand that an owner has full control regardless of the DACL.
2. **Deny ACE effectiveness**: Deny ACEs are reported but the tool does not evaluate whether they effectively block a corresponding allow ACE. The canonical order check helps identify potential issues, but manual review is needed.
3. **Delegation matching granularity**: An orphan ACE that partially overlaps with a delegation's expected ACEs (e.g., grants more rights than expected) will not match, appearing as both an orphan ACE and a missing expected ACE.
4. **Built-in delegation suppression**: By default, built-in delegations are hidden from the CSV. This means well-known delegations that may have been modified or are unexpected in a specific environment are not visible unless `--show-builtin` is used.

### Credential Handling

- If explicit credentials are provided via `--user`, `--domain`, and `--password`, they are passed to `ldap_bind_sW` using `SEC_WINNT_AUTH_IDENTITY_W` with Negotiate authentication.
- If `--password *` is specified, the tool reads the password interactively with echo disabled.
- Without explicit credentials, the tool uses the current Windows SSO context (implicit SSPI credentials).

> **Security note:** The `--password` argument accepts the password as a cleartext command-line value. On multi-user systems, this can leak credentials through shell history, process listings (`/proc/*/cmdline`, Task Manager), and monitoring tools. The interactive mode (`--password *`) should be preferred in environments where credential exposure is a concern.
