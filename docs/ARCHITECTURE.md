# PhantomLDAP — Technical Architecture

> **Scope:** Deep-dive reference covering every sub-system at the binary level: PEB walking, DJB2 hashing, RFC 2696 paged LDAP, DACL/ACE parsing, and the memory lifecycle of a Beacon Object File.

---

## Table of Contents

1. [BOF Execution Model](#1-bof-execution-model)
2. [PEB Walking — Module Resolution Engine](#2-peb-walking--module-resolution-engine)
3. [DJB2 Hash Algorithm](#3-djb2-hash-algorithm)
4. [Dynamic vs. Static IAT Imports](#4-dynamic-vs-static-iat-imports)
5. [LDAP Session Lifecycle](#5-ldap-session-lifecycle)
6. [RFC 2696 Paged Results Protocol](#6-rfc-2696-paged-results-protocol)
7. [DACL Binary Format Parsing](#7-dacl-binary-format-parsing)
8. [SID Binary Format](#8-sid-binary-format)
9. [PHANTOM_CONTEXT — Runtime State](#9-phantom_context--runtime-state)
10. [Tool Comparison](#10-tool-comparison)

---

## 1. BOF Execution Model

A Beacon Object File is a position-independent COFF object file (`.o`) executed **in-process** within the Cobalt Strike Beacon thread. PhantomLDAP BOFs:

- Execute synchronously in the Beacon thread (no child process)
- Communicate results via `BeaconPrintf` (encrypted C2 output)
- Are freed from memory immediately after `go()` returns
- Share the process heap with the Beacon via dynamically-resolved `HeapAlloc`

### Memory Layout

```
  Beacon Process (e.g., explorer.exe)
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │  ┌─────────────────────┐                            │
  │  │    beacon.dll (RX)   │  ← Reflective DLL         │
  │  └─────────────────────┘                            │
  │                                                     │
  │  ┌─────────────────────┐                            │
  │  │  BOF Allocation(RWX) │  ← COFF sections          │
  │  │  .text  (go() code)  │    loaded by CS loader    │
  │  │  .data  (constants)  │                            │
  │  └─────────────────────┘                            │
  │                                                     │
  │  ┌─────────────────────┐                            │
  │  │  Process Heap (RW)   │  ← PHANTOM_CONTEXT        │
  │  │  HeapAlloc buffers   │    LDAP result buffers    │
  │  └─────────────────────┘                            │
  │                                                     │
  │  wldap32.dll  ← resolved at runtime via PEB walk    │
  │  kernel32.dll ← resolved for HeapAlloc/HeapFree     │
  └─────────────────────────────────────────────────────┘
```

### Execution Lifecycle

```
  CS Operator: beacon> bof_enum_spn
       │
       ▼
  Teamserver serializes args → datap buffer (encrypted to beacon)
       │
       ▼
  Beacon:
    1. Receive task (C2 channel)
    2. Allocate RWX memory for BOF sections
    3. Apply COFF relocations
    4. Resolve Beacon$* imports
    5. Call go(char *args, int len)
       │
       ▼
  go():
    ├─ BeaconDataParse()        parse args
    ├─ phantom_ldap_init()      PEB walk → LDAP bind
    ├─ phantom_ldap_paged_search()  paged LDAP loop
    ├─ BeaconPrintf()           output to operator
    └─ phantom_ldap_cleanup()   unbind → zero context
       │
       ▼
  go() returns → BOF memory freed by Beacon loader
```

> [!NOTE]
> Because BOFs run in the Beacon thread, `PHANTOM_SEARCH_TIMEOUT_SEC` (30s) bounds each paged query to prevent blocking the C2 check-in loop indefinitely.

---

## 2. PEB Walking — Module Resolution Engine

### Memory Layout: GS → TEB → PEB → LDR → Module List

```
  x64: GS:[0x30] = TEB self pointer
       GS:[0x60] = TEB.ProcessEnvironmentBlock → PEB

  PEB (x64):
    +0x000  InheritedAddressSpace   (BYTE)
    +0x002  BeingDebugged           (BYTE)  ← anti-debug flag
    +0x008  Mutant                  (HANDLE)
    +0x010  ImageBaseAddress        (PVOID)
    +0x018  Ldr                     (PPEB_LDR_DATA)  ─────────┐
    +0x030  ProcessHeap             (PVOID)                   │
                                                              ▼
  PEB_LDR_DATA:
    +0x010  InLoadOrderModuleList   (LIST_ENTRY)
    +0x020  InMemoryOrderModuleList (LIST_ENTRY)  ← PhantomLDAP uses this
    +0x030  InInitOrderModuleList   (LIST_ENTRY)
                                                              │
  LDR_DATA_TABLE_ENTRY:                                       │
    +0x000  InLoadOrderLinks        (LIST_ENTRY)              │
    +0x010  InMemoryOrderLinks      (LIST_ENTRY) ◄────────────┘
    +0x030  DllBase                 (PVOID)       ← we want this
    +0x048  FullDllName             (UNICODE_STRING)
    +0x058  BaseDllName             (UNICODE_STRING) ← hash this
```

> [!IMPORTANT]
> The `InMemoryOrderLinks.Flink` points to the **`InMemoryOrderLinks` field** of the *next* entry, not the entry base. We must subtract `offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) = 0x10` to get the entry base.

### `phantom_get_module_base()` — Step by Step

```c
// Step 1: Get TEB via GS segment register (x64)
PTEB teb;
__asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));

// Step 2: TEB → PEB
PPEB peb = teb->ProcessEnvironmentBlock;    // TEB+0x060

// Step 3: PEB → Ldr → InMemoryOrderModuleList
PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
PLIST_ENTRY curr = head->Flink;

// Step 4: Walk the circular doubly-linked list
while (curr != head) {
    PLDR_DATA_TABLE_ENTRY entry =
        (PLDR_DATA_TABLE_ENTRY)((PBYTE)curr - 0x10);

    // Step 5: Hash BaseDllName (case-insensitive) and compare
    DWORD h = phantom_hash_unicode(entry->BaseDllName.Buffer, TRUE);
    if (h == target_hash)
        return entry->DllBase;     // ← MATCH

    curr = curr->Flink;
}
return NULL;
```

### `phantom_get_proc_addr()` — PE Export Table Walk

```
  DllBase
    │
    ├─ IMAGE_DOS_HEADER.e_magic = 0x5A4D ("MZ")
    └─ + e_lfanew → IMAGE_NT_HEADERS64
              │
              └─ OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                        │
                        └─ IMAGE_EXPORT_DIRECTORY
                              .AddressOfNames[i]     → name string
                              .AddressOfNameOrdinals[i] → ordinal index
                              .AddressOfFunctions[ordinal] → function RVA

  For each i in 0..NumberOfNames-1:
    if djb2(DllBase + AddressOfNames[i]) == target_hash:
        ordinal = AddressOfNameOrdinals[i]
        return DllBase + AddressOfFunctions[ordinal]
```

---

## 3. DJB2 Hash Algorithm

### Implementation

```c
DWORD phantom_hash_ascii(const char *str, BOOL case_insensitive) {
    DWORD hash = 5381;          // Magic seed
    int   c;

    while ((c = (unsigned char)*str++) != 0) {
        if (case_insensitive && c >= 'A' && c <= 'Z')
            c += 32;            // tolower
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}
```

### Worked Example: `djb2("wldap32.dll", ci=true)`

| Char | ASCII | Formula | Hash (hex) |
|:----:|:-----:|:--------|:----------:|
| `w`  | 119 | `5381*33 + 119` | `0x0002B51E` |
| `l`  | 108 | `prev*33 + 108` | `0x0059A5E2` → ... |
| ...  | ... | ... | ... |
| `l`  | 108 | final iteration | **`0xEEE845E3`** |

> [!NOTE]
> Overflow wraps naturally on 32-bit unsigned arithmetic.  
> `0xEEE845E3` matches `PHANTOM_HASH_WLDAP32` in `dynamic_resolve.h`. ✅

### Pre-computed Hash Table

| Constant | Hash | String |
|:---------|:----:|:-------|
| `PHANTOM_HASH_WLDAP32` | `0xEEE845E3` | `wldap32.dll` (ci) |
| `PHANTOM_HASH_KERNEL32` | `0x6DDB9555` | `kernel32.dll` (ci) |
| `PHANTOM_HASH_NTDLL` | `0x3CFA685D` | `ntdll.dll` (ci) |
| `PHANTOM_HASH_ldap_initW` | `0xB22A5F32` | `ldap_initW` |
| `PHANTOM_HASH_ldap_search_ext_sW` | `0xC15A8F60` | `ldap_search_ext_sW` |
| `PHANTOM_HASH_ldap_create_page_controlW` | `0x78E2D50F` | `ldap_create_page_controlW` |
| `PHANTOM_HASH_ldap_parse_page_controlW` | `0x59B4F83A` | `ldap_parse_page_controlW` |
| `PHANTOM_HASH_HeapAlloc` | `0x32C670D0` | `HeapAlloc` |
| `PHANTOM_HASH_HeapFree` | `0x4862531A` | `HeapFree` |

Regenerate with: `python3 scripts/gen_hashes.py`

---

## 4. Dynamic vs. Static IAT Imports

### The Static Import Problem

When a C program calls `ldap_search_ext_sW()` with a standard IAT import:

- The export name `"ldap_search_ext_sW"` appears as a literal string in the `.idata` section
- `dumpbin /imports`, `strings`, `pe-sieve`, and EDR static scanners all see it
- EDR hooks the IAT entry at DLL load time, intercepting every call transparently

### Dynamic Resolution Comparison

| Property | IAT Import | PhantomLDAP PEB Walk |
|:---------|:----------:|:-------------------:|
| Visible in `.idata` section? | ✅ Yes | ❌ No |
| Detectable by `strings`? | ✅ Yes | ❌ No (only integer hashes) |
| `dumpbin /imports` shows LDAP? | ✅ Yes | ❌ No |
| EDR IAT hook bypassed? | ❌ No | ✅ Yes |
| Inline hook in wldap32 bypassed? | ❌ No | ❌ No (VA-level hooks still active) |
| Performance overhead? | None | Negligible (one-time init) |

### Disassembly Difference

**Standard IAT import:**
```asm
call    qword ptr [__imp_ldap_search_ext_sW]   ; IAT indirect call
```

**PhantomLDAP dynamic resolve:**
```asm
; Init phase (once):
mov     rcx, 0xEEE845E3      ; wldap32 hash
call    phantom_get_module_base
mov     rdx, 0xC15A8F60      ; ldap_search_ext_sW hash
call    phantom_get_proc_addr
mov     [ctx.api+offset], rax

; Call site:
mov     rax, [ctx.api+offset]
call    rax                   ; no IAT reference — clean call
```

> [!WARNING]
> Dynamic resolution evades **static analysis** and **IAT-level hooks**. Inline trampolines applied directly to `wldap32.dll` code will still intercept calls.

---

## 5. LDAP Session Lifecycle

### `phantom_ldap_init()` Sequence

```
phantom_ldap_init(ctx, dc, use_ssl, page_size)
  │
  ├─ 1. phantom_resolve_ldap_api()
  │      PEB walk → wldap32.dll → resolve all 27 function pointers
  │
  ├─ 2. ldap_init(dc_name, port)
  │      port = use_ssl ? 636 : 389
  │
  ├─ 3. ldap_set_option(ld, LDAP_OPT_VERSION, &LDAP_VERSION3)
  │
  ├─ 4. [SSL] ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON)
  │
  ├─ 5. ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE)
  │      → SSPI Negotiate → Kerberos TGT reuse (or NTLM fallback)
  │      → No plaintext credentials transmitted
  │
  └─ 6. Search rootDSE base="" for defaultNamingContext
         → ctx->base_dn = L"DC=corp,DC=local"
         → ctx->dc_name = discovered DC hostname
```

### `LDAP_AUTH_NEGOTIATE` Breakdown

```c
#define LDAP_AUTH_SSPI      0x0E00L
#define LDAP_AUTH_NEGOTIATE (LDAP_AUTH_SSPI | 0x0400L)   // = 0x1200L
```

Automatically selects Kerberos (preferred) or NTLM fallback using the current thread's security context — no credentials required from the operator.

---

## 6. RFC 2696 Paged Results Protocol

### Why Paging?

AD enforces `MaxPageSize` (default: 1,000 objects). Queries exceeding this return `LDAP_SIZELIMIT_EXCEEDED`. RFC 2696 Simple Paged Results allows clients to iterate in pages using an opaque server-generated **cookie**.

**Paging OID:** `1.2.840.113556.1.4.319`

### Protocol Flow

```
  BOF                                     DC (LDAP)
   │                                         │
   │── ldap_search_ext_s ──────────────────►│
   │   [PagedResultControl, cookie=<empty>]  │
   │                                         │
   │◄── 500 entries + new cookie ───────────│
   │                                         │
   │   process entries → BeaconPrintf        │
   │   ldap_parse_page_control()             │
   │   ldap_msgfree()                        │
   │                                         │
   │── ldap_search_ext_s ──────────────────►│
   │   [PagedResultControl, cookie=<next>]   │
   │                                         │
   │◄── 500 entries + new cookie ───────────│
   │                                         │
   │   [... repeat ...]                      │
   │                                         │
   │◄── N entries + cookie=<empty> ─────────│
   │    DONE (empty cookie = last page)      │
```

---

## 7. DACL Binary Format Parsing

### Self-Relative SECURITY_DESCRIPTOR Layout

```
  nTSecurityDescriptor binary blob:

  Offset  Size  Field           Value Example
  ──────  ────  ──────────────  ───────────────────────────────
  +0x00   1     Revision        0x01
  +0x01   1     Sbz1            0x00
  +0x02   2     Control         0x8004  (SE_DACL_PRESENT | SE_SELF_RELATIVE)
  +0x04   4     OffsetOwner     0x00B8  → owner SID
  +0x08   4     OffsetGroup     0x00CC  → group SID
  +0x0C   4     OffsetSacl      0x0000  → no SACL
  +0x10   4     OffsetDacl      0x0014  → DACL starts here
```

### ACL Header (at OffsetDacl)

```
  Offset  Size  Field           Value Example
  ──────  ────  ──────────────  ───────────────────────────────
  +0x00   1     AclRevision     0x02 (0x04 for object ACEs)
  +0x01   1     Sbz1            0x00
  +0x02   2     AclSize         0x019C  (total ACL size in bytes)
  +0x04   2     AceCount        0x0017  (23 ACEs)
  +0x06   2     Sbz2            0x0000
```

### ACE Chain Walk

ACEs are variable-length, packed contiguously. `AceSize` points to the next:

```
  ┌─────────────────────────────────────────────────────┐
  │  ACCESS_ALLOWED_ACE (Type=0x00):                    │
  │  +0x00 AceType=0x00  AceFlags=0x12  AceSize=0x0018  │
  │  +0x04 Mask=0x000F01FF  SidStart=[SID bytes]        │
  └──────────────────────────────────┬──────────────────┘
                                     │ +AceSize (24 bytes)
  ┌──────────────────────────────────▼──────────────────┐
  │  ACCESS_ALLOWED_OBJECT_ACE (Type=0x05):              │
  │  +0x00 AceType=0x05  AceFlags=0x02  AceSize=0x0038  │
  │  +0x04 Mask=0x00000100 (DS_CONTROL_ACCESS)          │
  │  +0x08 Flags=0x00000001 (OBJ_TYPE_PRESENT)          │
  │  +0x0C ObjectType GUID = {1131f6ad-...} = DCSync!   │
  │  +0x1C InheritedObjectType GUID                     │
  │  +0x2C SidStart = [trustee SID]                     │
  └──────────────────────────────────┬──────────────────┘
                                     │ +AceSize (56 bytes)
  [next ACE...]
```

### ACE Type Table

| Type | Constant | Description |
|:----:|:---------|:------------|
| `0x00` | `ACCESS_ALLOWED_ACE_TYPE` | Standard allow |
| `0x01` | `ACCESS_DENIED_ACE_TYPE` | Standard deny |
| `0x05` | `ACCESS_ALLOWED_OBJECT_ACE_TYPE` | Allow + GUID (extended rights) |
| `0x06` | `ACCESS_DENIED_OBJECT_ACE_TYPE` | Deny + GUID |

### Interest Level Classification

| Level | Constant | Triggers |
|:-----:|:---------|:---------|
| 0 | `ACE_INTEREST_NORMAL` | Standard expected ACEs |
| 1 | `ACE_INTEREST_MEDIUM` | `GenericWrite`, `WriteProperty` on sensitive attrs |
| 2 | `ACE_INTEREST_HIGH` | `WriteDACL`, `WriteOwner`, DCSync rights |
| 3 | `ACE_INTEREST_CRITICAL` | `ForceChangePassword`, `AllExtendedRights`, RBCD write |

---

## 8. SID Binary Format

```
  SID Binary Layout (S-1-5-21-<domain>-512):

  Offset  Size  Field                   Value
  ──────  ────  ──────────────────────  ───────────────────────────────
  +0x00   1     Revision                0x01
  +0x01   1     SubAuthorityCount       0x05  (5 sub-authorities)
  +0x02   6     IdentifierAuthority     00 00 00 00 00 05  (NT Authority=5)
  +0x08   4     SubAuthority[0]         0x00000015  (= 21, domain prefix)
  +0x0C   4     SubAuthority[1]         <domain part 1> (LE DWORD)
  +0x10   4     SubAuthority[2]         <domain part 2>
  +0x14   4     SubAuthority[3]         <domain part 3>
  +0x18   4     SubAuthority[4]         0x00000200  (= 512, Domain Admins RID)

  String: S-1-5-21-<p1>-<p2>-<p3>-512
```

**Parsing in `phantom_sid_to_string()`:**
1. Read `Revision` (offset 0)
2. Read `SubAuthorityCount` (offset 1)
3. Read 6-byte big-endian `IdentifierAuthority` (offsets 2–7)
4. For each `SubAuthority[i]`: read little-endian DWORD at `8 + i*4`
5. Format as `S-{rev}-{auth}-{sa0}-{sa1}-...`

---

## 9. PHANTOM_CONTEXT — Runtime State

```c
typedef struct _PHANTOM_CONTEXT {
    LDAP            *ldap_handle;        /* Active LDAP session handle */
    WCHAR            dc_name[256];       /* Connected DC hostname */
    WCHAR            base_dn[512];       /* Domain base DN (from rootDSE) */
    BOOL             connected;          /* Session state flag */
    BOOL             use_ssl;            /* LDAPS mode flag */
    ULONG            ldap_port;          /* 389 or 636 */
    PHANTOM_LDAP_API api;               /* All 27 resolved function pointers */
    ULONG            page_size;          /* Objects per page (default: 500) */
    ULONG            search_timeout;     /* Per-page timeout (default: 30s) */
    ULONG            total_found;        /* Objects processed */
    ULONG            page_count;         /* Pages fetched */
    ULONG            error_count;        /* LDAP errors encountered */
} PHANTOM_CONTEXT, *PPHANTOM_CONTEXT;
```

Allocated on stack (zero-initialized with `{0}`). The `api` struct (27 function pointers, ~216 bytes) is populated by `phantom_resolve_ldap_api()` during `phantom_ldap_init()`. Zeroed by `phantom_ldap_cleanup()` after `ldap_unbind()`.

---

## 10. Tool Comparison

| Feature | PhantomLDAP | SharpHound | PowerView | BloodHound-CE |
|:--------|:-----------:|:----------:|:---------:|:-------------:|
| Execution model | BOF (in-thread) | Fork & Run | PowerShell | Standalone EXE |
| CLR instantiated | ❌ | ✅ | ❌ | ❌ |
| AMSI triggered | ❌ | ✅ | ✅ | ❌ |
| Static LDAP IAT | ❌ | N/A | N/A | ✅ |
| Dynamic API resolve | ✅ | ❌ | ❌ | ❌ |
| LDAP paging | ✅ | ✅ | ❌ | ✅ |
| Binary DACL parse | ✅ Full | Partial | ✅ | ✅ |
| Disk writes | ❌ | ✅ JSON | ❌ | ✅ DB |
| Process spawn | ❌ | ✅ | ❌ | ✅ |
| ETW events | Low | High | Medium | Low |
| Post-analysis GUI | ❌ | ✅ (BloodHound) | ❌ | ✅ |
