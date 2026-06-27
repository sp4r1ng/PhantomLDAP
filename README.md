<div align="center">

# 🌌 PhantomLDAP

**Advanced OpSec-Safe Active Directory Enumeration BOF Suite**

[![CI — Cross-Compile](https://github.com/PhantomLDAP/PhantomLDAP/actions/workflows/build.yml/badge.svg)](https://github.com/PhantomLDAP/PhantomLDAP/actions/workflows/build.yml)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20C99-00599C?logo=c&logoColor=white)](https://en.cppreference.com/w/c)
[![Platform](https://img.shields.io/badge/Platform-x86__64%20Windows-0078D6?logo=windows&logoColor=white)](https://github.com/PhantomLDAP/PhantomLDAP)
[![Framework](https://img.shields.io/badge/Framework-Cobalt%20Strike%204.x-red?logo=target&logoColor=white)](https://www.cobaltstrike.com/)
[![Build](https://img.shields.io/badge/Build-MinGW--w64-brightgreen?logo=gnu&logoColor=white)](https://www.mingw-w64.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet)](https://github.com/PhantomLDAP/PhantomLDAP/releases)

*Zero-import · PEB-walk API resolution · Paginated LDAP · In-memory DACL parsing · No CLR · No Fork & Run*

</div>

---

## 🧠 Overview

**PhantomLDAP** is a suite of eight *Beacon Object Files* (BOF) written in pure C, designed for **stealthy, OpSec-first enumeration** of Active Directory environments during Red Team engagements.

Unlike conventional AD tools based on .NET ([SharpHound](https://github.com/BloodHoundAD/SharpHound), [Rubeus](https://github.com/GhostPack/Rubeus)) or PowerShell ([PowerView](https://github.com/PowerShellMafia/PowerSploit)), PhantomLDAP operates **ephemerally within the Beacon's thread** — it never:

- 🚫 Instantiates the CLR (Common Language Runtime)
- 🚫 Spawns a child process (no *Fork & Run*)
- 🚫 Creates static entries in the binary's IAT for LDAP functions
- 🚫 Writes temporary files to disk
- 🚫 Loads reflective DLLs

Instead, it resolves all sensitive Windows API calls **dynamically at runtime** by walking the Process Environment Block (PEB) using a DJB2-based hash comparison — leaving the compiled `.o` file clean of any references to `wldap32.dll`.

---

## 🔬 Architecture & Evasion Techniques

### 1. Dynamic API Resolution (Zero-IAT Imports)

```
Traditional BOF          PhantomLDAP BOF
─────────────────        ──────────────────────────────────────
IAT Entry:               No IAT Entry.
  wldap32!ldap_search    
  wldap32!ldap_bind_s    Runtime: GS:[0x30] → TEB
  wldap32!ldap_init         → PEB.Ldr.InMemoryOrderModuleList
                               → hash BaseDllName (DJB2)
                                  → parse PE export table
                                     → hash export names (DJB2)
                                        → resolve VA
                                           → call via fn ptr
```

The PEB walk traverses the **InMemoryOrderModuleList** linked list, computing `djb2(BaseDllName)` for each loaded module. On a match, the export table is parsed and each `AddressOfNames` entry is hashed until the target function is found. All hash constants are pre-computed by `scripts/gen_hashes.py`.

**Result:** `x86_64-w64-mingw32-nm build/enum_spn.o | grep __imp_ldap` → *empty* ✅

### 2. Native wldap32.dll vs ADSI/COM

PhantomLDAP communicates directly with Active Directory via the native **LDAP binary protocol** through `wldap32.dll`, bypassing the overhead-heavy ADSI/COM layer used by tools like `DirectorySearcher` in .NET. This reduces:

- Allocations on the managed heap (none)
- ETW events from the .NET runtime (none — CLR never loaded)
- COM object instantiation artifacts (none)

### 3. Paginated LDAP Results (RFC 2696)

Fetching 10,000+ user objects in a single LDAP query risks:
- Memory exhaustion → Beacon crash → compromised process killed
- Server-side query cost → Event ID 1644 with high-cost search flag
- Large network burst → NDR anomaly detection

PhantomLDAP implements **LDAP Simple Paged Results** (`OID: 1.2.840.113556.1.4.319`) via `ldap_create_page_control` / `ldap_parse_page_control`. Results are processed in configurable blocks (default: **500 objects/page**), forwarded to the operator via `BeaconPrintf`, and freed before the next page is requested.

### 4. Binary DACL Parsing in C

The `bof_enum_acl` module performs **complete in-process parsing** of `nTSecurityDescriptor` binary blobs retrieved via LDAP — no offline processing required:

```c
// Self-relative SECURITY_DESCRIPTOR → DACL → ACE chain
SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)sd_bytes;
PACL dacl = (PACL)((PBYTE)sd + sd->Dacl);   // Offset from SD base

for (WORD i = 0; i < dacl->AceCount; i++) {
    PACE_HEADER ace = /* current ACE */;
    // Classify: NORMAL / MEDIUM / HIGH / CRITICAL
    // Decode SID, ACCESS_MASK, Object GUID (for extended rights)
    // Identify DCSync, ForceChangePassword, WriteDACL, WriteOwner...
    ace = (PACE_HEADER)((PBYTE)ace + ace->AceSize);  // Next ACE
}
```

Classified ACEs are output with **severity ratings** (NORMAL → MEDIUM → HIGH → CRITICAL) based on their access mask and extended rights GUID.

### 5. Zero Memory Leaks

Every LDAP object returned by `wldap32.dll` is tracked and released:

| Object Type | Release Function |
|:------------|:----------------|
| Search result chain | `ldap_msgfree()` |
| String value arrays | `ldap_value_freeW()` |
| Binary value arrays | `ldap_value_free_len()` |
| DN strings | `ldap_memfreeW()` |
| Control arrays | `ldap_controls_free()` |
| Cookie berval | Freed via `phantom_heap_free()` |
| Module heap allocs | `phantom_heap_free()` |

The `goto cleanup` pattern ensures all paths — including error paths — release every resource:

```c
void go(char *args, int len) {
    PHANTOM_CONTEXT ctx = {0};
    PWSTR *vals = NULL;
    
    if (!phantom_ldap_init(&ctx, NULL, FALSE, 0)) goto cleanup;
    vals = ctx.api.ldap_get_values(ctx.ldap_handle, entry, ATTR_SAM_ACCOUNT_NAME);
    // ... process ...
    
cleanup:
    if (vals) ctx.api.ldap_value_free(vals);
    phantom_ldap_cleanup(&ctx);  // calls ldap_unbind, zeros struct
}
```

---

## 🛠️ Modules

| Beacon Command | LDAP Filter | Primary Use Case |
|:---------------|:------------|:-----------------|
| `bof_enum_admins` | `(&(objectCategory=person)(objectClass=user)(adminCount=1))` | AdminSDHolder-protected accounts, delegation analysis |
| `bof_enum_spn` | `(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(uAC=Disabled)))` | **Kerberoasting** candidate discovery |
| `bof_enum_asrep` | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | **AS-REP Roasting** target identification |
| `bof_enum_computers` | `(objectClass=computer)` | OS inventory, stale machines, lateral movement targets |
| `bof_enum_trusts` | `(objectClass=trustedDomain)` | Cross-domain/forest lateral movement paths |
| `bof_enum_gpo` | `(objectClass=groupPolicyContainer)` | GPO abuse for persistence/priv-esc |
| `bof_enum_acl` | `(distinguishedName=<target>)` — base scope | **Full DACL analysis**: DCSync, WriteDACL, ForceChangePassword |
| `bof_ldap_query` | *Operator-supplied* | Arbitrary LDAP filter injection |

---

## 📁 Project Structure

```
PhantomLDAP/
├── src/
│   ├── core/
│   │   ├── dynamic_resolve.c   # PEB walker + DJB2 engine + heap wrappers
│   │   ├── ldap_ops.c          # LDAP init/bind/paged-search/cleanup
│   │   └── output.c            # Beacon output formatters
│   └── modules/
│       ├── enum_admins.c       # BOF: Admin account enumeration
│       ├── enum_spn.c          # BOF: Kerberoastable SPN enumeration
│       ├── enum_asrep.c        # BOF: AS-REP Roasting targets
│       ├── enum_computers.c    # BOF: Computer object inventory
│       ├── enum_trusts.c       # BOF: Domain trust enumeration
│       ├── enum_gpo.c          # BOF: Group Policy Objects
│       ├── enum_acl.c          # BOF: DACL binary parser & ACE classifier
│       └── ldap_query.c        # BOF: Custom LDAP filter execution
├── include/
│   ├── win_types.h             # Standalone Windows types (no SDK)
│   ├── ldap_types.h            # wldap32 types & function pointer typedefs
│   ├── beacon.h                # Cobalt Strike 4.x BOF API
│   ├── dynamic_resolve.h       # PEB resolver API + DJB2 hash constants
│   └── phantom_ldap.h          # PHANTOM_CONTEXT, ACE structures, shared defs
├── cna/
│   ├── phantom_ldap.cna        # Main Aggressor Script (command registration)
│   ├── menus.cna               # Beacon right-click context menu
│   └── helpers.cna             # CNA helper functions & hooks
├── build/                      # Compiled .o BOF files (created by make)
├── docs/
│   ├── ARCHITECTURE.md         # Deep-dive: PEB walk, DACL parsing, DJB2
│   ├── OPSEC.md               # Operator guide: targets, timing, TTPs
│   ├── DETECTION.md           # Blue Team: Sigma rules, Event IDs, NDR
│   ├── DEVELOPMENT.md         # Build guide, module template, contribution
│   └── detection/
│       ├── sigma_ldap_enum.yml
│       ├── sigma_wldap32_load.yml
│       └── sigma_asrep_enum.yml
├── scripts/
│   ├── gen_hashes.py          # DJB2 hash constant generator
│   └── build.ps1              # Windows PowerShell build script
├── tests/
│   └── test_hash.c            # Unit tests for DJB2 implementation
├── .github/
│   └── workflows/
│       └── build.yml          # CI/CD: MinGW cross-compile + BOF validation
├── Makefile                   # Primary build system
├── LICENSE                    # MIT License
└── README.md
```

---

## 💻 Build & Installation

### Prerequisites

| Tool | Version | Purpose |
|:-----|:--------|:--------|
| `x86_64-w64-mingw32-gcc` | ≥ 9.0 | C compiler (MinGW-w64) |
| `x86_64-w64-mingw32-ld` | any | Linker (partial link) |
| GNU Make | ≥ 4.0 | Build orchestration |
| Python 3 | ≥ 3.8 | Hash generation (optional) |
| Cobalt Strike | 4.x | BOF execution framework |

### Linux (Recommended — Kali / Ubuntu / Debian)

```bash
# Install MinGW-w64 cross-compiler
sudo apt-get update && sudo apt-get install -y mingw-w64

# Clone the repository
git clone https://github.com/PhantomLDAP/PhantomLDAP.git
cd PhantomLDAP

# Build all modules
make all

# (Optional) Regenerate DJB2 hash constants
make hashes

# Output: build/*.o — one .o per BOF module
ls -la build/
```

### Windows (PowerShell)

```powershell
# Option 1: WSL (recommended if WSL is installed)
.\scripts\build.ps1 -UseWSL

# Option 2: Native MinGW-w64
# Install: https://github.com/niXman/mingw-builds-binaries/releases
.\scripts\build.ps1

# Build specific module only
.\scripts\build.ps1 -Module enum_spn
```

### Build Output Validation

```bash
# Verify go() entry point exists
x86_64-w64-mingw32-nm build/enum_spn.o | grep "T go"
# Expected: 0000000000000000 T go

# Verify NO static LDAP IAT imports
x86_64-w64-mingw32-nm build/enum_spn.o | grep -i "__imp_ldap"
# Expected: (empty — no output)

# Check DJB2 hash constants
python3 scripts/gen_hashes.py --verify
# Expected: [OK] All N hash constants verified successfully.
```

---

## ⚙️ Usage (Cobalt Strike)

### 1. Load the Aggressor Script

In Cobalt Strike → **Cobalt Strike** → **Script Manager** → **Load** → select `cna/phantom_ldap.cna`

All `bof_*` commands and the right-click **PhantomLDAP** menu will be immediately available on all Beacons.

### 2. Module Examples

```
beacon> bof_enum_spn
[*] PhantomLDAP: Launching SPN enumeration module...

================================================================
[PhantomLDAP] SPN-ENUM :: Kerberoastable Account Discovery
================================================================
[*] Connected to: DC01.corp.local | Base DN: DC=corp,DC=local
[*] Page size: 500 | Timeout: 30s

[+] SPN Account #1: CORP\sql_svc
    DN        : CN=sql_svc,CN=Users,DC=corp,DC=local
    SPN(s)    : MSSQLSvc/db01.corp.local:1433
                MSSQLSvc/db01:1433
    UAC       : NORMAL_ACCOUNT
    Pwd Set   : 2023-08-10 08:00:00 UTC (320 days ago)
    [!] OLD PASSWORD: >365 days — likely crackable!
    [*] Attack: GetUserSPNs.py CORP/ -u user -p pass -request

----------------------------------------------------------------
[*] Enumeration complete. Objects found: 3 | Pages: 1 | Errors: 0
[*] Memory freed. Beacon stable.
```

```
beacon> bof_enum_acl "CN=Domain Admins,CN=Users,DC=corp,DC=local"

[*] DACL Analysis: CN=Domain Admins,CN=Users,DC=corp,DC=local
    Total ACEs: 14 | Interesting: 4 | Critical: 1
    ----------------------------------------------------------------
    [CRITICAL] ALLOW :: S-1-5-21-1234567890-987654321-111111111-1105
               Rights  : DS-Replication-Get-Changes-All (DCSync!)
               Object  : {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
               Flags   : CONTAINER_INHERIT_ACE
               [!!!] DCSync right — account can replicate domain secrets!
               [*]   Impacket: secretsdump.py -just-dc CORP/user@dc01
    
    [HIGH]     ALLOW :: S-1-5-21-...-1106
               Rights  : WRITE_DAC, WRITE_OWNER
               [!] WriteDACL — account can modify this object's DACL
```

```
beacon> bof_ldap_query "(&(objectClass=computer)(operatingSystem=*XP*))" "sAMAccountName,dNSHostName,operatingSystem"
```

```
beacon> bof_enum_trusts
[+] Trust #1: CORP.LOCAL --> SUBSIDIARY.COM
    Type      : Active Directory (Uplevel)
    Direction : Bidirectional
    Transitive: YES (Forest Trust)
    SID Filter: DISABLED
    [!] SID history attacks possible across this trust!
```

---

## 🔑 Key Internals

### DJB2 Hash Function

```c
DWORD phantom_hash_ascii(const char *str, BOOL case_insensitive) {
    DWORD hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        if (case_insensitive && c >= 'A' && c <= 'Z')
            c += 32;  // to lowercase
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

// djb2("wldap32.dll", ci=true) = 0xEEE845E3
// djb2("ldap_search_ext_sW", ci=false) = 0xC15A8F60
```

### PEB Walker (x64)

```c
// GS segment register holds TEB base on x64
PTEB teb;
__asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));

PPEB peb = teb->ProcessEnvironmentBlock;
PPEB_LDR_DATA ldr = peb->Ldr;

// Walk InMemoryOrderModuleList
PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
PLIST_ENTRY curr = head->Flink;
while (curr != head) {
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr,
        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    
    DWORD h = phantom_hash_unicode(entry->BaseDllName.Buffer, TRUE);
    if (h == target_hash)
        return entry->DllBase;  // Found!
    
    curr = curr->Flink;
}
```

---

## 🛡️ Defense & Detection

> [!WARNING]
> Although PhantomLDAP minimizes host-based artifacts, **network-level** activity remains detectable. The following indicators should be monitored by SOC and Threat Hunting teams.

### Event ID Matrix

| Event ID | Source | Description | Detection Value |
|:---------|:-------|:------------|:----------------|
| **1644** | Directory Service | Expensive/inefficient LDAP search on DC | 🔴 High — reveals LDAP filter |
| **4662** | Security | Object operation (DACL read via LDAP) | 🟡 Medium |
| **Sysmon 7** | Sysmon | `wldap32.dll` loaded in unexpected process | 🔴 High |
| **Sysmon 1** | Sysmon | Process creation with LDAP-querying parent | 🟡 Medium |
| **4624** | Security | Logon (SSPI bind via Kerberos) | 🟢 Low (noisy) |

### Network Indicators

- **Protocol**: LDAP over TCP/389 (or LDAPS/636)
- **Pattern**: `OID 1.2.840.113556.1.4.319` in LDAP extended request → paged enumeration
- **Anomaly**: Workstation (non-DC) initiating heavy LDAP sessions to port 389 outside of logon operations

> [!NOTE]
> **Red Team Recommendation**: Inject this BOF into a process that legitimately performs LDAP queries (e.g., `explorer.exe`, `mmc.exe`, `taskmgr.exe`) to reduce behavioral anomaly score. See [`docs/OPSEC.md`](docs/OPSEC.md) for a complete injection target analysis.

See [`docs/DETECTION.md`](docs/DETECTION.md) for:
- 4 Sigma rules (YAML format)
- Zeek/Suricata NDR signatures
- YARA rule for DJB2 pattern
- Splunk SPL queries
- Microsoft Defender for Identity alert mapping

---

## 📊 Comparison with Common AD Enumeration Tools

| Feature | PhantomLDAP | SharpHound | PowerView | ADExplorer |
|:--------|:-----------:|:----------:|:---------:|:----------:|
| Execution model | BOF (in-thread) | Fork & Run | PowerShell | Standalone EXE |
| CLR loaded | ❌ | ✅ | ❌ | ❌ |
| AMSI triggered | ❌ | ✅ | ✅ | ❌ |
| Static IAT (wldap32) | ❌ | N/A | N/A | ✅ |
| Dynamic API resolve | ✅ | ❌ | ❌ | ❌ |
| LDAP paging | ✅ | ✅ | ❌ | ✅ |
| In-memory DACL parse | ✅ | Partial | ✅ | ❌ |
| Disk writes | ❌ | ✅ (JSON) | ❌ | ✅ (binary) |
| Process spawn | ❌ | ✅ | ❌ | N/A |
| ETW provider events | Low | High | Medium | Low |

---

## 📚 Documentation

| Document | Description |
|:---------|:------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | PEB walk, DJB2, LDAP paging, DACL binary format — deep technical dive |
| [`docs/OPSEC.md`](docs/OPSEC.md) | Operator guide: process injection targets, timing, TTP chaining |
| [`docs/DETECTION.md`](docs/DETECTION.md) | Blue Team guide: Sigma rules, Event IDs, Zeek/Suricata, YARA |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Build guide, new module template, code style |

---

## ⚠️ Legal Disclaimer

> **This project is provided exclusively for:**
> - Security research and education
> - Authorized Red Team and Penetration Testing engagements
> - CTF competitions
>
> Using this tool against systems **without explicit written authorization** from the system owner is **illegal** under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in your jurisdiction.
>
> **The authors accept no liability for misuse.** You are solely responsible for your actions.

---

<div align="center">

*Built with 🔥 for the Red Team community*

</div>
