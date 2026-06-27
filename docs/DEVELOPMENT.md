# PhantomLDAP — Development Guide

> **Audience:** Contributors, security researchers, and operators who want to build PhantomLDAP from source, add new modules, or extend the framework.

---

## Table of Contents

1. [Build Requirements](#1-build-requirements)
2. [Build on Linux (Recommended)](#2-build-on-linux-recommended)
3. [Build on Windows](#3-build-on-windows)
4. [Hash Generation Workflow](#4-hash-generation-workflow)
5. [Writing a New Module](#5-writing-a-new-module)
6. [Code Style Guide](#6-code-style-guide)
7. [Testing](#7-testing)
8. [Contributing](#8-contributing)

---

## 1. Build Requirements

| Tool | Version | Purpose | Install |
|:-----|:-------:|:--------|:--------|
| `x86_64-w64-mingw32-gcc` | ≥ 9.0 | Cross-compile C for Windows x64 | `apt-get install mingw-w64` |
| `x86_64-w64-mingw32-ld` | any | Partial link (combine `.o` files) | Included with mingw-w64 |
| GNU Make | ≥ 4.0 | Build orchestration | `apt-get install make` |
| Python 3 | ≥ 3.8 | DJB2 hash generation | `apt-get install python3` |
| Cobalt Strike | 4.x | BOF execution environment | (licensed) |

> [!NOTE]
> PhantomLDAP does **not** require the Windows SDK, `winldap.h`, or any MSVC toolchain. All Windows type definitions are self-contained in `include/win_types.h` and `include/ldap_types.h`.

---

## 2. Build on Linux (Recommended)

### Quick Start (Kali / Ubuntu / Debian)

```bash
# 1. Install MinGW-w64 cross-compiler
sudo apt-get update && sudo apt-get install -y mingw-w64 python3

# 2. Clone the repository
git clone https://github.com/PhantomLDAP/PhantomLDAP.git
cd PhantomLDAP

# 3. Build all modules
make all

# 4. Verify output
ls -la build/*.o
```

### Build a Single Module

```bash
make enum_spn        # Build only the SPN enumeration module
make enum_acl        # Build only the DACL analysis module
make enum_computers  # etc.
```

### Clean Build

```bash
make clean && make all
```

### Verify Build Integrity

```bash
# Check for go() entry point in each BOF:
for f in build/*.o; do
    echo -n "$f: "
    x86_64-w64-mingw32-nm "$f" | grep "T go" && echo "OK" || echo "MISSING go()"
done

# Verify NO static LDAP IAT imports:
for f in build/*.o; do
    echo -n "$f IAT check: "
    result=$(x86_64-w64-mingw32-nm "$f" 2>/dev/null | grep -i "__imp_ldap")
    if [ -z "$result" ]; then echo "CLEAN"; else echo "FAIL: $result"; fi
done

# Validate DJB2 hash constants:
python3 scripts/gen_hashes.py --verify
```

---

## 3. Build on Windows

### Option A: Windows Subsystem for Linux (WSL)

```powershell
# Install WSL2 with Ubuntu:
wsl --install -d Ubuntu

# Then inside WSL:
sudo apt-get install -y mingw-w64 python3
cd /mnt/c/Users/User/Downloads/PhantomLDAP
make all
```

### Option B: Native MinGW-w64 (PowerShell)

```powershell
# Install MinGW-w64 via Chocolatey:
choco install mingw -y

# Or download from: https://github.com/niXman/mingw-builds-binaries/releases
# Add to PATH: C:\mingw64\bin

# Build:
.\scripts\build.ps1

# Build specific module:
.\scripts\build.ps1 -Module enum_spn

# Clean:
.\scripts\build.ps1 -Clean
```

---

## 4. Hash Generation Workflow

PhantomLDAP uses pre-computed DJB2 hash constants defined in `include/dynamic_resolve.h`. These must be recomputed whenever:

- You add a new `wldap32.dll` function to `PHANTOM_LDAP_API`
- You add a new kernel32.dll function dependency
- You add support for a new module (e.g., `netapi32.dll`)

### Regenerate Hashes

```bash
# Update include/dynamic_resolve.h with freshly computed values:
python3 scripts/gen_hashes.py

# Verify the update was applied correctly:
python3 scripts/gen_hashes.py --verify

# Print all hashes as a markdown table:
python3 scripts/gen_hashes.py --table

# Compute the hash of a specific string:
python3 scripts/gen_hashes.py --compute "MyNewFunction"
python3 scripts/gen_hashes.py --compute "mynewmodule.dll" --case-insensitive
```

### Adding a New Function to the Hash Table

1. Edit `scripts/gen_hashes.py` and add your function to the appropriate group:

```python
# In WLDAP32_FUNCTIONS dict:
"PHANTOM_HASH_ldap_new_function": ("ldap_new_function", False),

# In KERNEL32_FUNCTIONS dict (if adding a kernel32 function):
"PHANTOM_HASH_NewKernelFunc": ("NewKernelFunc", False),
```

2. Run `python3 scripts/gen_hashes.py` to update the header.

3. Add the hash constant and function pointer to `include/dynamic_resolve.h` and `include/ldap_types.h`.

4. Add the resolution call in `phantom_resolve_ldap_api()` in `src/core/dynamic_resolve.c`.

---

## 5. Writing a New Module

### Module Template

Every PhantomLDAP module follows this exact pattern:

```c
/**
 * @file enum_mymodule.c
 * @brief PhantomLDAP BOF — Brief description.
 *
 * Detailed description of what this module enumerates.
 *
 * LDAP Filter: (your LDAP filter here)
 *
 * Arguments (CNA bof_pack):
 *   [Z] dc_name - Optional DC hostname (wide string)
 *
 * @author  Your Name
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

#define MODULE_TAG   "MY-MODULE"
#define MODULE_TITLE "My Module Description"

/* Attributes to fetch per LDAP entry */
static PWSTR g_attrs[] = {
    L"sAMAccountName",
    L"distinguishedName",
    /* ... add your attributes ... */
    NULL  /* ← MUST end with NULL */
};

/**
 * @brief Callback invoked for each LDAP result entry.
 *
 * Called by phantom_ldap_paged_search() once per entry.
 * Must free all LDAP value arrays before returning.
 *
 * @return TRUE to continue, FALSE to abort early.
 */
static BOOL my_module_callback(PPHANTOM_CONTEXT ctx,
                                PLDAPMessage entry,
                                PVOID user_data) {
    (void)user_data;
    PPHANTOM_LDAP_API api = &ctx->api;

    /* Declare all value pointers (initialize to NULL!) */
    PWSTR *sam_vals = NULL;
    PWSTR *dn_vals  = NULL;

    char sam_str[128] = {0};
    char dn_str[512]  = {0};

    ctx->total_found++;

    /* Fetch attributes */
    sam_vals = api->ldap_get_values(ctx->ldap_handle, entry,
                                    ATTR_SAM_ACCOUNT_NAME);
    if (sam_vals && sam_vals[0])
        phantom_wstr_to_str(sam_vals[0], sam_str, sizeof(sam_str));

    dn_vals = api->ldap_get_values(ctx->ldap_handle, entry,
                                   ATTR_DISTINGUISHED_NAME);
    if (dn_vals && dn_vals[0])
        phantom_wstr_to_str(dn_vals[0], dn_str, sizeof(dn_str));

    /* --- Output --- */
    phantom_print_separator('-');
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Entry #%lu: %s\n",
                 (unsigned long)ctx->total_found, sam_str);
    phantom_print_kv("DN", dn_str, 4);

    /* --- Cleanup (ALWAYS!) --- */
    /* goto cleanup pattern ensures this runs on all paths */
cleanup:
    if (sam_vals) api->ldap_value_free(sam_vals);
    if (dn_vals)  api->ldap_value_free(dn_vals);

    return TRUE;
}

/**
 * @brief BOF entry point.
 * @param args Packed arguments from CNA bof_pack()
 * @param len  Buffer length in bytes
 */
void go(char *args, int len) {
    PHANTOM_CONTEXT ctx    = {0};
    datap           parser = {0};
    WCHAR           dc_name[256] = {0};
    char           *dc_arg = NULL;
    int             dc_len  = 0;

    /* Parse arguments */
    BeaconDataParse(&parser, args, len);
    dc_arg = BeaconDataExtract(&parser, &dc_len);

    if (dc_arg && dc_len > 0 && dc_arg[0] != '\0')
        for (int i = 0; i < dc_len && i < 255; i++)
            dc_name[i] = (WCHAR)(unsigned char)dc_arg[i];

    /* Print banner and header */
    phantom_print_banner();
    phantom_print_header(MODULE_TITLE, MODULE_TAG);

    /* Initialize LDAP (resolves API, binds, discovers base DN) */
    if (!phantom_ldap_init(&ctx, dc_name[0] ? dc_name : NULL, FALSE, 0)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: LDAP initialization failed.\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Base DN : %ls\n[*] Filter  : (your filter)\n\n",
        ctx.base_dn);

    /* Run paged search */
    phantom_ldap_paged_search(
        &ctx,
        ctx.base_dn,             /* Search base */
        LDAP_SCOPE_SUBTREE,      /* Scope */
        L"(your LDAP filter)",   /* Filter */
        g_attrs,                 /* Attributes */
        my_module_callback,      /* Per-entry callback */
        NULL                     /* user_data (NULL if unused) */
    );

    if (ctx.total_found == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No results found.\n");

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);  /* Always unbind + zero context */
}
```

### Adding the Module to the Build System

1. Save your module as `src/modules/enum_mymodule.c`

2. Add it to `Makefile`:
```make
# In MODULE_SOURCES:
$(SRC_MODULES)/enum_mymodule.c \

# In BOF_TARGETS:
$(BUILD)/enum_mymodule.o \

# The define macro handles the rest:
$(eval $(call BUILD_MODULE,enum_mymodule))
```

3. Register the CNA command in `cna/phantom_ldap.cna`:
```
beacon_command_register(
    "bof_mymodule",
    "Brief description",
    "Usage: bof_mymodule [dc_hostname]\n\nDetailed help text."
);

alias bof_mymodule {
    local('$bid $dc $args');
    $bid = $1; $dc = $2 ? $2 : "";
    $args = bof_pack($bid, "Z", $dc);
    phantom_exec_bof($bid, "enum_mymodule", $args);
}
```

---

## 6. Code Style Guide

### Naming Conventions

| Entity | Convention | Example |
|:-------|:----------:|:--------|
| Functions | `snake_case` with `phantom_` prefix | `phantom_sid_to_string()` |
| Types | `UPPER_SNAKE_CASE` with `PHANTOM_` prefix | `PHANTOM_CONTEXT` |
| Macros | `UPPER_SNAKE_CASE` with `PHANTOM_` prefix | `PHANTOM_FREE(ptr)` |
| Local variables | `snake_case` | `PWSTR *sam_vals` |
| Constants | `UPPER_SNAKE_CASE` | `LDAP_PORT` |

### Memory Rules

```c
/* RULE 1: Always initialize pointers to NULL */
PWSTR *vals = NULL;                     // ✅
PWSTR *vals;                            // ❌ (uninitialized)

/* RULE 2: Always free in the reverse order of allocation */
if (vals2) api->ldap_value_free(vals2); // freed first
if (vals1) api->ldap_value_free(vals1); // freed second (allocated first)

/* RULE 3: Use goto cleanup for all error paths */
if (!phantom_ldap_init(...)) goto cleanup;  // ✅
if (!phantom_ldap_init(...)) return;        // ❌ (bypasses cleanup)

/* RULE 4: Use phantom_heap_alloc for dynamic allocation */
PBYTE buf = phantom_heap_alloc(size, TRUE); // ✅ (zero-initialized)
PBYTE buf = malloc(size);                   // ❌ (CRT dependency)

/* RULE 5: Zero sensitive memory before freeing */
phantom_bzero(ctx, sizeof(PHANTOM_CONTEXT));
```

### No Standard Library

PhantomLDAP BOFs **must not** use any CRT functions. Use these alternatives:

| CRT Function | Replacement |
|:------------|:-----------|
| `strlen()` | manual loop |
| `wcslen()` | manual loop |
| `memcpy()` | manual loop |
| `memset()` | manual loop (phantom_bzero) |
| `memcmp()` | manual loop (phantom_memcmp) |
| `snprintf()` | append_* helpers in output.c |
| `malloc()/free()` | `phantom_heap_alloc()` / `phantom_heap_free()` |
| `strncpy()` | manual loop |
| `atoi()` | manual decimal parse loop |
| `printf()` | `BeaconPrintf()` |

### Documentation

Every function must have a Doxygen comment block:

```c
/**
 * @brief Convert a binary SID to its string representation.
 *
 * Parses the revision, identifier authority (6-byte big-endian), and each
 * sub-authority (4-byte little-endian DWORD) to produce the standard
 * S-R-A-SA0-SA1-...-RID format.
 *
 * @param sid_bytes  Pointer to the binary SID data
 * @param sid_len    Length of the SID data in bytes
 * @param out_buf    Output buffer for the string representation
 * @param buf_size   Size of the output buffer in bytes (minimum 16)
 * @return           TRUE on success, FALSE if SID is malformed or buffer too small
 */
BOOL phantom_sid_to_string(const BYTE *sid_bytes, DWORD sid_len,
                            char *out_buf, SIZE_T buf_size);
```

---

## 7. Testing

### Hash Verification

```bash
# Verify all pre-computed hash constants match the DJB2 reference implementation:
python3 scripts/gen_hashes.py --verify

# Compute a specific hash:
python3 scripts/gen_hashes.py --compute "ldap_search_ext_sW"
# Expected: djb2("ldap_search_ext_sW") = 0xC15A8F60
```

### Unit Tests (test_hash.c)

A standalone (non-BOF) test binary verifies the C DJB2 implementation:

```bash
# Build the test binary (requires linking kernel32 — not for BOF use):
x86_64-w64-mingw32-gcc -I include -D_WIN64 -DUNICODE \
    tests/test_hash.c \
    -o tests/test_hash.exe \
    -lkernel32

# Run on Linux via Wine:
wine tests/test_hash.exe

# Run on Windows:
.\tests\test_hash.exe
```

Expected output:
```
================================================================
 PhantomLDAP — DJB2 Hash Unit Tests
================================================================
[PASS] djb2("wldap32.dll", ci=true)         0xEEE845E3
[PASS] djb2("WLDAP32.DLL", ci=true) == ...  0xEEE845E3
[PASS] djb2("kernel32.dll", ci=true)        0x6DDB9555
...
[PASS] No collisions in tested pairs
================================================================
Results: 25/25 passed
Status: ALL TESTS PASSED ✓
```

### BOF Symbol Validation

```bash
# After make, validate each BOF:
for f in build/*.o; do
    # 1. Has go() entry point
    x86_64-w64-mingw32-nm "$f" | grep -q "T go" || echo "FAIL: $f missing go()"

    # 2. Clean IAT (no static LDAP imports)
    result=$(x86_64-w64-mingw32-nm "$f" | grep -i "__imp_ldap")
    [ -n "$result" ] && echo "FAIL: $f has IAT LDAP imports: $result"

    # 3. Reasonable size (< 256KB per BOF)
    size=$(wc -c < "$f")
    [ "$size" -gt 262144 ] && echo "WARN: $f is $size bytes (>256KB)"
done
echo "All checks passed."
```

---

## 8. Contributing

### Before Submitting a Pull Request

- [ ] Code compiles cleanly with `-Wall -Wextra` (no warnings)
- [ ] All memory allocations have corresponding frees (review cleanup path)
- [ ] No `#include <stdio.h>`, `<string.h>`, `<stdlib.h>`, or any CRT header
- [ ] `python3 scripts/gen_hashes.py --verify` passes
- [ ] New module registered in `Makefile` and `cna/phantom_ldap.cna`
- [ ] Doxygen comments on all public functions
- [ ] BOF validation checks pass (go() present, IAT clean)

### Branch Strategy

```
main        ← stable releases only
develop     ← integration branch (all PRs target this)
feature/*   ← individual feature branches
fix/*       ← bugfix branches
```

### Reporting Issues

When reporting a build failure or bug, please include:
- OS and distribution (e.g., Kali 2024.1, Ubuntu 22.04)
- MinGW-w64 version: `x86_64-w64-mingw32-gcc --version`
- Make version: `make --version`
- Full compiler error output
- The specific module that fails
