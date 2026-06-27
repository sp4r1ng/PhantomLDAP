/**
 * @file dynamic_resolve.c
 * @brief PEB-walking API resolution engine for PhantomLDAP BOF suite.
 *
 * This is the most critical file in the PhantomLDAP project. It implements
 * a zero-import mechanism for resolving Windows API function addresses at
 * runtime by:
 *
 *   1. Obtaining the TEB pointer via the GS segment register (x64 ABI).
 *   2. Deriving the PEB from TEB+0x60.
 *   3. Walking PEB->Ldr->InMemoryOrderModuleList to enumerate loaded modules.
 *   4. Matching module names via a DJB2 hash (case-insensitive).
 *   5. Parsing the target module's PE export directory.
 *   6. Matching exported function names via DJB2 hash (case-sensitive).
 *   7. Converting the matched RVA to a virtual address and returning it.
 *
 * All heap memory used outside of PEB/PE walks is managed through the
 * lazily-resolved phantom_heap_* wrappers, which themselves are bootstrapped
 * via PEB walking and therefore never touch the IAT.
 *
 * ## Compilation
 * @code
 *   x86_64-w64-mingw32-gcc -c src/core/dynamic_resolve.c \
 *       -I include/ -O2 -Wall -Wextra -nostdlib -o dynamic_resolve.o
 * @endcode
 *
 * ## OpSec notes
 * - No Windows SDK headers are included; all types come from project headers.
 * - No static imports of kernel32, wldap32, or ntdll are generated.
 * - PEB walking emits no API calls -- pure pointer arithmetic and inline ASM.
 * - The DJB2 hash is computed at compile time for constants (via macros in
 *   dynamic_resolve.h) and at runtime for walked names.
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "win_types.h"
#include "ldap_types.h"
#include "dynamic_resolve.h"
#include "beacon.h"

/* =========================================================================
 * Internal Helper -- offsetof without <stddef.h>
 *
 * The standard offsetof() macro lives in <stddef.h>, which we cannot
 * include. Replicate it here using the portable GCC built-in.
 * ========================================================================= */

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

/* =========================================================================
 * Internal type aliases for heap and library functions
 *
 * These typedefs keep the KERNEL32_CACHE struct definition clean and allow
 * the compiler to verify pointer assignments throughout this file.
 * ========================================================================= */

/** @brief HeapAlloc function pointer type. */
typedef PVOID  (WINAPI *fn_HeapAlloc_t)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

/** @brief HeapFree function pointer type. */
typedef BOOL   (WINAPI *fn_HeapFree_t)(HANDLE hHeap, DWORD dwFlags, PVOID lpMem);

/** @brief HeapReAlloc function pointer type. */
typedef PVOID  (WINAPI *fn_HeapReAlloc_t)(HANDLE hHeap, DWORD dwFlags, PVOID lpMem, SIZE_T dwBytes);

/** @brief GetProcessHeap function pointer type. */
typedef HANDLE (WINAPI *fn_GetProcessHeap_t)(void);

/** @brief LoadLibraryW function pointer type. */
typedef HMODULE (WINAPI *fn_LoadLibraryW_t)(LPCWSTR lpLibFileName);

/* =========================================================================
 * Kernel32 Cache -- Lazily Initialised Heap API Pointers
 *
 * Populated on the first call to phantom_heap_alloc(). All subsequent heap
 * operations use these cached pointers directly, avoiding repeated PEB
 * walks for every allocation. The cache is process-wide static state and is
 * intentionally never freed (its lifetime equals the BOF execution lifetime).
 * ========================================================================= */

/**
 * @brief Cache structure for kernel32.dll heap function pointers.
 *
 * @note  This is the only static state in the entire PhantomLDAP project.
 *        It is acceptable because its lifetime is bounded by the BOF
 *        execution window and it contains no sensitive data.
 */
typedef struct _KERNEL32_CACHE {
    fn_HeapAlloc_t      HeapAlloc;       /**< Cached HeapAlloc pointer       */
    fn_HeapFree_t       HeapFree;        /**< Cached HeapFree pointer         */
    fn_HeapReAlloc_t    HeapReAlloc;     /**< Cached HeapReAlloc pointer      */
    fn_GetProcessHeap_t GetProcessHeap;  /**< Cached GetProcessHeap pointer   */
    BOOL                initialised;     /**< TRUE after successful resolve   */
} KERNEL32_CACHE;

/** @brief Process-wide kernel32 heap pointer cache. */
static KERNEL32_CACHE g_k32_cache = { NULL, NULL, NULL, NULL, FALSE };

/* =========================================================================
 * 1. phantom_hash_ascii
 * ========================================================================= */

/**
 * @brief Compute a DJB2 hash of a null-terminated ASCII string.
 *
 * The DJB2 algorithm uses the recurrence:
 * @code
 *   hash = 5381
 *   hash = hash * 33 + c      (for each byte c in the input)
 * @endcode
 *
 * The multiply-by-33 is implemented as (hash << 5) + hash, which a compiler
 * can reduce to a single LEA instruction on x86-64.
 *
 * @param str               Null-terminated ASCII string to hash. Must not
 *                          be NULL; behaviour is undefined if it is.
 * @param case_insensitive  If TRUE, uppercase ASCII letters (A-Z) are
 *                          folded to lowercase before hashing. This allows
 *                          module name lookups to be case-insensitive.
 *
 * @return 32-bit DJB2 hash. Returns 5381 (the seed) for an empty string.
 *         Returns 0 if @p str is NULL.
 */
DWORD
phantom_hash_ascii(const char *str, BOOL case_insensitive)
{
    DWORD         hash = 5381;
    unsigned char c;

    if (!str) {
        return 0;
    }

    while ((c = (unsigned char)*str++) != '\0') {
        /*
         * Case folding: convert uppercase ASCII letters to lowercase by
         * ORing bit 5. Only applies to characters in [A-Z] (0x41-0x5A).
         */
        if (case_insensitive && c >= 'A' && c <= 'Z') {
            c |= 0x20; /* 'A' -> 'a', 'B' -> 'b', ... 'Z' -> 'z' */
        }

        /* DJB2: hash = hash * 33 + c */
        hash = ((hash << 5) + hash) + (DWORD)c;
    }

    return hash;
}

/* =========================================================================
 * 2. phantom_hash_unicode
 * ========================================================================= */

/**
 * @brief Compute a DJB2 hash of a null-terminated Unicode (wide) string.
 *
 * Windows module names (BaseDllName) and export names are stored as Unicode
 * strings in the PEB loader lists. Rather than converting the entire string
 * to ASCII first, we project each WCHAR down to its low byte (cast WCHAR to
 * unsigned char). This is intentionally lossy but entirely correct for the
 * ASCII-only names used by Windows DLLs and their exports (all characters
 * fall in the 0x00-0x7F range).
 *
 * The same DJB2 algorithm is used as in phantom_hash_ascii, ensuring that
 * hashing "kernel32.dll" as an ASCII string and as a Unicode string produces
 * identical results.
 *
 * @param str               Null-terminated wide string. Must not be NULL.
 * @param case_insensitive  If TRUE, uppercase letters are folded to
 *                          lowercase before hashing.
 *
 * @return 32-bit DJB2 hash of the ASCII-projected string.
 *         Returns 0 if @p str is NULL.
 */
DWORD
phantom_hash_unicode(const WCHAR *str, BOOL case_insensitive)
{
    DWORD         hash = 5381;
    unsigned char c;

    if (!str) {
        return 0;
    }

    while (*str != L'\0') {
        /*
         * Project the WCHAR to its low byte. For codepoints 0x00-0x7F
         * (the ASCII range), this is an exact lossless representation.
         * All Windows module and export names are pure 7-bit ASCII.
         */
        c = (unsigned char)((ULONG_PTR)*str & 0xFF);
        str++;

        if (case_insensitive && c >= 'A' && c <= 'Z') {
            c |= 0x20;
        }

        hash = ((hash << 5) + hash) + (DWORD)c;
    }

    return hash;
}

/* =========================================================================
 * 3. phantom_get_module_base
 * ========================================================================= */

/**
 * @brief Locate a loaded module's base address by its DJB2 hash.
 *
 * ### PEB Walk -- Step-by-Step
 *
 * @code
 *  GS:[0x30] --> TEB.Self (pointer to TEB)
 *  TEB+0x060 --> ProcessEnvironmentBlock (PPEB)
 *  PEB+0x018 --> Ldr (PPEB_LDR_DATA)
 *  Ldr+0x020 --> InMemoryOrderModuleList (LIST_ENTRY head/sentinel)
 * @endcode
 *
 * For each node in the circular list:
 * @code
 *  LIST_ENTRY *link  = InMemoryOrderModuleList.Flink
 *  LDR_DATA_TABLE_ENTRY *entry = link - offsetof(InMemoryOrderLinks)
 *  hash = phantom_hash_unicode(entry->BaseDllName.Buffer, TRUE)
 *  if hash == module_hash: return entry->DllBase
 * @endcode
 *
 * ### InMemoryOrderList layout note
 * The Flink pointer within InMemoryOrderModuleList does NOT point to the
 * start of an LDR_DATA_TABLE_ENTRY. It points to the InMemoryOrderLinks
 * field within the entry (at byte offset 0x10 from the entry base). We must
 * subtract that offset to recover the entry base pointer.
 *
 * ### List ordering
 * The first entry in InMemoryOrderModuleList is always the main EXE image
 * and the second is always ntdll.dll. Subsequent entries are other loaded
 * modules. We walk all entries including the first two to stay general.
 *
 * @param module_hash   Pre-computed DJB2 hash of the target module name
 *                      (case-insensitive, e.g. PHANTOM_HASH_KERNEL32).
 *
 * @return DllBase (mapped base address) of the matching module, or NULL
 *         if the module is not currently loaded.
 *
 * @note The __attribute__((noinline)) prevents the compiler from inlining
 *       this function into callers, which could interfere with the inline
 *       assembly on aggressive optimisation levels.
 */
__attribute__((noinline))
PVOID
phantom_get_module_base(DWORD module_hash)
{
    PPEB                  peb        = NULL;
    PPEB_LDR_DATA         ldr        = NULL;
    PLIST_ENTRY           list_head  = NULL;
    PLIST_ENTRY           list_entry = NULL;
    PLDR_DATA_TABLE_ENTRY ldr_entry  = NULL;
    DWORD                 name_hash  = 0;

    /* ------------------------------------------------------------------
     * Step 1: Obtain TEB via GS register, derive PEB from TEB+0x60.
     *
     * NtCurrentTeb() is defined as an inline in win_types.h and emits:
     *   movq %gs:0x30, <reg>
     * The TEB.ProcessEnvironmentBlock field is at offset 0x60 on x64.
     * ------------------------------------------------------------------ */
    peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb) {
        return NULL;
    }

    /* ------------------------------------------------------------------
     * Step 2: Navigate to the PEB loader data.
     *
     * PEB->Ldr points to PEB_LDR_DATA, which contains the three circular
     * doubly-linked lists of loaded modules.
     * ------------------------------------------------------------------ */
    ldr = peb->Ldr;
    if (!ldr) {
        return NULL;
    }

    /* ------------------------------------------------------------------
     * Step 3: Iterate InMemoryOrderModuleList.
     *
     * Ldr->InMemoryOrderModuleList is the sentinel (head) node of the
     * circular list. We iterate Flink links until we return to the head.
     * ------------------------------------------------------------------ */
    list_head  = &ldr->InMemoryOrderModuleList;
    list_entry = list_head->Flink;

    while (list_entry != list_head) {
        /*
         * Recover the LDR_DATA_TABLE_ENTRY base from the InMemoryOrderLinks
         * field pointer. The Flink points at InMemoryOrderLinks inside the
         * entry, so we subtract the field offset to get the struct base.
         */
        ldr_entry = (PLDR_DATA_TABLE_ENTRY)(
            (PBYTE)list_entry
            - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
        );

        /*
         * Guard against entries with no name buffer. This can occur for
         * the host EXE entry on some Windows versions, or for partially-
         * initialised entries during early process startup.
         */
        if (ldr_entry->BaseDllName.Buffer != NULL &&
            ldr_entry->BaseDllName.Length  > 0)
        {
            /*
             * Hash the BaseDllName (Unicode wide string) case-insensitively.
             * The Buffer is null-terminated, so phantom_hash_unicode() can
             * iterate until the null WCHAR.
             */
            name_hash = phantom_hash_unicode(
                ldr_entry->BaseDllName.Buffer,
                TRUE /* case_insensitive */
            );

            if (name_hash == module_hash) {
                /* Found -- return the mapped base address of this module. */
                return ldr_entry->DllBase;
            }
        }

        /* Advance to the next node in the circular list. */
        list_entry = list_entry->Flink;
    }

    /* Module not found in the in-memory module list. */
    return NULL;
}

/* =========================================================================
 * 4. phantom_get_proc_addr
 * ========================================================================= */

/**
 * @brief Resolve a function's virtual address from a module's PE export table.
 *
 * ### PE Export Table Walk -- Algorithm
 *
 * @code
 *  RVA(exp_dir) = NT_HDRS.OptionalHeader
 *                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
 *
 *  IMAGE_EXPORT_DIRECTORY fields used:
 *    NumberOfNames        -- count of named exports
 *    AddressOfNames[]     -- array of RVAs to null-terminated name strings
 *    AddressOfNameOrdinals[] -- parallel array of ordinal slot indices
 *    AddressOfFunctions[] -- array of function RVAs indexed by slot
 *
 *  For i in [0, NumberOfNames):
 *    name = (char*)(module_base + AddressOfNames[i])
 *    if djb2(name) == func_hash:
 *        slot    = AddressOfNameOrdinals[i]
 *        fn_rva  = AddressOfFunctions[slot]
 *        return (void*)(module_base + fn_rva)
 * @endcode
 *
 * ### Forwarded Export Detection
 * A forwarded export's AddressOfFunctions RVA falls within the export
 * directory's own [VirtualAddress, VirtualAddress+Size) byte range.
 * The data at that RVA is a "ModuleName.FunctionName" ASCII string.
 * PhantomLDAP skips forwarded exports (returning NULL) because:
 *   - None of the target functions in wldap32/kernel32 are forwarded.
 *   - Recursive resolution would require heap allocation.
 *   - Returning NULL triggers a named-export error in the caller.
 *
 * @param module_base   Mapped base address of the target module. If NULL,
 *                      returns NULL immediately.
 * @param func_hash     DJB2 hash of the target export name (case-sensitive).
 *
 * @return Virtual address of the exported function, or NULL if:
 *           - @p module_base is NULL or has no export directory
 *           - The export name is not found
 *           - The matched export is a forwarded export
 */
PVOID
phantom_get_proc_addr(PVOID module_base, DWORD func_hash)
{
    PIMAGE_DOS_HEADER       dos_hdr   = NULL;
    PIMAGE_NT_HEADERS64     nt_hdrs   = NULL;
    PIMAGE_EXPORT_DIRECTORY exp_dir   = NULL;
    PDWORD                  names     = NULL;
    PDWORD                  functions = NULL;
    PWORD                   ordinals  = NULL;
    PBYTE                   base      = NULL;
    DWORD                   exp_rva   = 0;
    DWORD                   exp_size  = 0;
    DWORD                   i         = 0;
    DWORD                   name_hash = 0;
    DWORD                   func_rva  = 0;
    WORD                    ordinal   = 0;
    const char             *name_str  = NULL;

    if (!module_base) {
        return NULL;
    }

    base    = (PBYTE)module_base;
    dos_hdr = (PIMAGE_DOS_HEADER)base;

    /* ------------------------------------------------------------------
     * Validate the MZ signature (0x5A4D). Guards against a bad base
     * pointer that would cause an access violation below.
     * ------------------------------------------------------------------ */
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    /* ------------------------------------------------------------------
     * Locate IMAGE_NT_HEADERS64 via the e_lfanew stub offset.
     * Validate the PE\0\0 signature (0x00004550).
     * ------------------------------------------------------------------ */
    nt_hdrs = (PIMAGE_NT_HEADERS64)(base + dos_hdr->e_lfanew);
    if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    /* ------------------------------------------------------------------
     * Read the export data directory entry (index 0).
     * VirtualAddress == 0 means the module exports nothing.
     * ------------------------------------------------------------------ */
    exp_rva  = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exp_size = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exp_rva == 0) {
        return NULL;
    }

    exp_dir = (PIMAGE_EXPORT_DIRECTORY)(base + exp_rva);

    /* ------------------------------------------------------------------
     * Resolve the three export arrays from their stored RVAs.
     *
     *   AddressOfNames[i]        -- RVA to null-terminated export name
     *   AddressOfNameOrdinals[i] -- ordinal slot for that name
     *   AddressOfFunctions[slot] -- RVA of the function
     *
     * All three RVAs are relative to module_base.
     * ------------------------------------------------------------------ */
    names     = (PDWORD)(base + exp_dir->AddressOfNames);
    ordinals  = (PWORD) (base + exp_dir->AddressOfNameOrdinals);
    functions = (PDWORD)(base + exp_dir->AddressOfFunctions);

    /* ------------------------------------------------------------------
     * Linear scan over named exports, comparing DJB2 hashes.
     * ------------------------------------------------------------------ */
    for (i = 0; i < exp_dir->NumberOfNames; i++) {
        name_str  = (const char *)(base + names[i]);
        name_hash = phantom_hash_ascii(name_str, FALSE /* case-sensitive */);

        if (name_hash != func_hash) {
            continue;
        }

        /*
         * Hash matched. Resolve the function RVA through the ordinal table.
         *
         * AddressOfNameOrdinals[i] is a zero-based slot index into
         * AddressOfFunctions[], NOT a Win32 ordinal number.
         */
        ordinal  = ordinals[i];
        func_rva = functions[ordinal];

        /*
         * Forwarded export detection:
         * If func_rva falls in [exp_rva, exp_rva + exp_size), the "address"
         * is actually a forwarding string ("ntdll.RtlAllocateHeap").
         * We log a diagnostic and return NULL -- the caller's NULL check
         * will report the specific export name.
         */
        if (func_rva >= exp_rva && func_rva < (exp_rva + exp_size)) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: Export '%s' is forwarded -- skipping.\n",
                name_str);
            return NULL;
        }

        /* Return the resolved virtual address. */
        return (PVOID)(base + func_rva);
    }

    /* Function name not found in this module's export table. */
    return NULL;
}

/* =========================================================================
 * 5. phantom_resolve -- Combined One-Shot Resolution
 * ========================================================================= */

/**
 * @brief Combined module-lookup and function-resolution in a single call.
 *
 * Convenience wrapper composing phantom_get_module_base() and
 * phantom_get_proc_addr() into one operation. Suitable for one-off
 * resolutions (e.g., resolving LoadLibraryW during bootstrap).
 *
 * For bulk resolutions from the same module, prefer calling
 * phantom_get_module_base() once and phantom_get_proc_addr() in a loop,
 * to avoid re-walking the full PEB list for every function.
 *
 * @param mod_hash   DJB2 hash of the module name (case-insensitive)
 * @param func_hash  DJB2 hash of the function name (case-sensitive)
 *
 * @return Virtual address of the function, or NULL if either the module
 *         or the function could not be found.
 */
PVOID
phantom_resolve(DWORD mod_hash, DWORD func_hash)
{
    PVOID module_base = phantom_get_module_base(mod_hash);
    if (!module_base) {
        return NULL;
    }
    return phantom_get_proc_addr(module_base, func_hash);
}

/* =========================================================================
 * 6. Kernel32 Cache Initialisation (internal)
 * ========================================================================= */

/**
 * @brief Lazily populate the kernel32 heap function pointer cache.
 *
 * Called on every entry to phantom_heap_alloc(). The initialised flag makes
 * the fast path a single unpredicted branch. This function is NOT thread-safe,
 * which is acceptable because Cobalt Strike BOFs run on a single thread.
 *
 * ### Bootstrap Constraint
 * This function MUST NOT call phantom_heap_alloc() (directly or indirectly),
 * because it is the bootstrap path for heap allocation. All operations here
 * are pure PEB/PE walks with no memory allocations.
 *
 * @return TRUE if the cache is (or was already) successfully populated.
 *         FALSE if any kernel32 symbol could not be resolved.
 */
static BOOL
phantom_init_k32_cache(void)
{
    PVOID k32_base = NULL;

    /* Fast path: already initialised on a prior call. */
    if (g_k32_cache.initialised) {
        return TRUE;
    }

    /* Locate kernel32.dll base via PEB walk. */
    k32_base = phantom_get_module_base(PHANTOM_HASH_KERNEL32);
    if (!k32_base) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: kernel32.dll not found in PEB module list.\n");
        return FALSE;
    }

    /* Resolve HeapAlloc. */
    g_k32_cache.HeapAlloc = (fn_HeapAlloc_t)
        phantom_get_proc_addr(k32_base, PHANTOM_HASH_HeapAlloc);
    if (!g_k32_cache.HeapAlloc) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: Failed to resolve kernel32!HeapAlloc.\n");
        return FALSE;
    }

    /* Resolve HeapFree. */
    g_k32_cache.HeapFree = (fn_HeapFree_t)
        phantom_get_proc_addr(k32_base, PHANTOM_HASH_HeapFree);
    if (!g_k32_cache.HeapFree) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: Failed to resolve kernel32!HeapFree.\n");
        return FALSE;
    }

    /* Resolve HeapReAlloc. */
    g_k32_cache.HeapReAlloc = (fn_HeapReAlloc_t)
        phantom_get_proc_addr(k32_base, PHANTOM_HASH_HeapReAlloc);
    if (!g_k32_cache.HeapReAlloc) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: Failed to resolve kernel32!HeapReAlloc.\n");
        return FALSE;
    }

    /* Resolve GetProcessHeap. */
    g_k32_cache.GetProcessHeap = (fn_GetProcessHeap_t)
        phantom_get_proc_addr(k32_base, PHANTOM_HASH_GetProcessHeap);
    if (!g_k32_cache.GetProcessHeap) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: Failed to resolve kernel32!GetProcessHeap.\n");
        return FALSE;
    }

    /* All four pointers resolved -- mark cache as ready. */
    g_k32_cache.initialised = TRUE;
    return TRUE;
}

/* =========================================================================
 * 7. phantom_heap_alloc
 * ========================================================================= */

/**
 * @brief Allocate memory from the process heap via dynamically-resolved HeapAlloc.
 *
 * Lazily initialises the kernel32 cache on the first call. Subsequent calls
 * incur only a single branch check (g_k32_cache.initialised) before
 * dispatching directly to the cached HeapAlloc pointer.
 *
 * @param size    Number of bytes to allocate. Must be > 0.
 * @param zeroed  If TRUE, passes HEAP_ZERO_MEMORY to HeapAlloc, ensuring the
 *                returned block is zero-initialised. Equivalent to calloc().
 *
 * @return Pointer to the allocated memory block, or NULL if the cache
 *         could not be initialised or HeapAlloc returned NULL (OOM).
 */
PVOID
phantom_heap_alloc(SIZE_T size, BOOL zeroed)
{
    HANDLE heap  = NULL;
    DWORD  flags = 0;

    if (!phantom_init_k32_cache()) {
        return NULL;
    }

    heap  = g_k32_cache.GetProcessHeap();
    flags = zeroed ? HEAP_ZERO_MEMORY : 0;

    return g_k32_cache.HeapAlloc(heap, flags, size);
}

/* =========================================================================
 * 8. phantom_heap_free
 * ========================================================================= */

/**
 * @brief Free a heap block previously allocated by phantom_heap_alloc().
 *
 * Calls HeapFree on the process default heap. Passing NULL is silently
 * ignored, matching the behaviour of the PHANTOM_FREE() macro.
 *
 * If the kernel32 cache is not yet populated (which would only occur if
 * phantom_heap_free is somehow called before phantom_heap_alloc), the
 * function returns silently to avoid a null-pointer dereference.
 *
 * @param ptr  Pointer to free. NULL is silently ignored.
 */
void
phantom_heap_free(PVOID ptr)
{
    HANDLE heap = NULL;

    if (!ptr) {
        return;
    }

    /*
     * Guard: it is theoretically impossible to have a valid phantom-allocated
     * pointer without having gone through phantom_init_k32_cache, but we
     * check defensively to avoid dereferencing a NULL function pointer.
     */
    if (!g_k32_cache.initialised   ||
        !g_k32_cache.HeapFree      ||
        !g_k32_cache.GetProcessHeap)
    {
        return;
    }

    heap = g_k32_cache.GetProcessHeap();
    g_k32_cache.HeapFree(heap, 0, ptr);
}

/* =========================================================================
 * 9. phantom_heap_realloc
 * ========================================================================= */

/**
 * @brief Resize a heap allocation via dynamically-resolved HeapReAlloc.
 *
 * Semantics closely match realloc():
 * - If @p ptr is NULL, delegates to phantom_heap_alloc(@p new_size, FALSE).
 * - If @p new_size is 0, HeapReAlloc frees the block and returns NULL.
 * - On failure, the original allocation is NOT freed.
 *
 * @param ptr       Existing allocation from phantom_heap_alloc(). May be NULL.
 * @param new_size  Desired new size in bytes.
 *
 * @return Pointer to the (possibly relocated) block, or NULL on failure.
 */
PVOID
phantom_heap_realloc(PVOID ptr, SIZE_T new_size)
{
    HANDLE heap = NULL;

    if (!phantom_init_k32_cache()) {
        return NULL;
    }

    if (!ptr) {
        /* Degenerate case: realloc(NULL, size) == alloc(size). */
        return phantom_heap_alloc(new_size, FALSE);
    }

    heap = g_k32_cache.GetProcessHeap();
    return g_k32_cache.HeapReAlloc(heap, 0, ptr, new_size);
}

/* =========================================================================
 * 10. phantom_resolve_ldap_api
 * ========================================================================= */

/**
 * @brief Resolve all 27 wldap32.dll function pointers into a PHANTOM_LDAP_API.
 *
 * This function is the entry-point for LDAP API table initialisation. It must
 * be called exactly once before any LDAP operations are attempted. The caller
 * provides a zeroed PHANTOM_LDAP_API structure which is populated in-place.
 *
 * ### Resolution strategy
 *
 * 1. **PEB search**: Walk InMemoryOrderModuleList for wldap32.dll.
 *    wldap32 is already present in any target process that has completed
 *    Kerberos or NTLM authentication (e.g., almost all domain workstations
 *    with an active Beacon session).
 *
 * 2. **LoadLibraryW fallback**: If wldap32 is not in the PEB list, resolve
 *    LoadLibraryW from kernel32 (itself already bootstrapped by the heap
 *    cache) and call it with the L"wldap32.dll" wide string literal. The
 *    literal is embedded in .rdata by the compiler -- no heap needed.
 *
 * 3. **Export resolution**: For each of the 27 exports, call
 *    phantom_get_proc_addr() with the pre-computed hash from dynamic_resolve.h.
 *    We call phantom_get_proc_addr() directly (not phantom_resolve()) to avoid
 *    re-walking the PEB list 27 times.
 *
 * 4. **Verification pass**: After all 27 resolutions, each field is checked
 *    for NULL. This two-pass strategy reports ALL missing exports rather than
 *    failing on the first, enabling complete diagnosis from a single run.
 *
 * @param api  Pointer to a zeroed PHANTOM_LDAP_API. Must not be NULL.
 *
 * @return TRUE  All 27 wldap32 function pointers resolved successfully.
 * @return FALSE One or more resolutions failed. @p api must not be used.
 */
BOOL
phantom_resolve_ldap_api(PPHANTOM_LDAP_API api)
{
    PVOID             wldap32_base     = NULL;
    fn_LoadLibraryW_t pfn_LoadLibraryW = NULL;
    BOOL              all_ok           = TRUE;

    if (!api) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: phantom_resolve_ldap_api called with NULL api.\n");
        return FALSE;
    }

    /* ------------------------------------------------------------------
     * Step 1: Search for wldap32.dll in the PEB module list.
     * ------------------------------------------------------------------ */
    wldap32_base = phantom_get_module_base(PHANTOM_HASH_WLDAP32);

    if (!wldap32_base) {
        /* ------------------------------------------------------------------
         * Step 2: wldap32 not yet loaded -- use LoadLibraryW to load it.
         *
         * LoadLibraryW is resolved from kernel32 via phantom_resolve().
         * The wide-string literal L"wldap32.dll" is embedded in .rdata by
         * the compiler and requires no runtime allocation.
         * ------------------------------------------------------------------ */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP: wldap32.dll not in PEB -- attempting LoadLibraryW.\n");

        pfn_LoadLibraryW = (fn_LoadLibraryW_t)
            phantom_resolve(PHANTOM_HASH_KERNEL32, PHANTOM_HASH_LoadLibraryW);

        if (!pfn_LoadLibraryW) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: Failed to resolve kernel32!LoadLibraryW.\n");
            return FALSE;
        }

        /*
         * L"wldap32.dll" is a compile-time UTF-16LE string literal stored
         * in the .rdata section. No heap allocation is performed here.
         */
        wldap32_base = (PVOID)pfn_LoadLibraryW(L"wldap32.dll");

        if (!wldap32_base) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: LoadLibraryW(\"wldap32.dll\") returned NULL.\n");
            return FALSE;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP: wldap32.dll loaded at base 0x%p.\n",
            wldap32_base);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP: wldap32.dll found in PEB at base 0x%p.\n",
            wldap32_base);
    }

    /* ------------------------------------------------------------------
     * Step 3: Resolve all 27 wldap32 named exports.
     *
     * Order matches the declaration order in PHANTOM_LDAP_API (ldap_types.h).
     * We resolve all 27 unconditionally before the verification pass below,
     * so that a complete set of errors can be reported in one run.
     * ------------------------------------------------------------------ */

    api->ldap_init = (fn_ldap_initW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_initW);

    api->ldap_set_option = (fn_ldap_set_option_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_set_option);

    api->ldap_get_option = (fn_ldap_get_option_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_get_option);

    api->ldap_connect = (fn_ldap_connect_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_connect);

    api->ldap_bind_s = (fn_ldap_bind_sW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_bind_sW);

    api->ldap_unbind = (fn_ldap_unbind_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_unbind);

    api->ldap_search_ext_s = (fn_ldap_search_ext_sW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_search_ext_sW);

    api->ldap_count_entries = (fn_ldap_count_entries_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_count_entries);

    api->ldap_first_entry = (fn_ldap_first_entry_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_first_entry);

    api->ldap_next_entry = (fn_ldap_next_entry_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_next_entry);

    api->ldap_get_values = (fn_ldap_get_valuesW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_get_valuesW);

    api->ldap_get_values_len = (fn_ldap_get_values_lenW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_get_values_lenW);

    api->ldap_count_values = (fn_ldap_count_valuesW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_count_valuesW);

    api->ldap_count_values_len = (fn_ldap_count_values_len_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_count_values_len);

    api->ldap_value_free = (fn_ldap_value_freeW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_value_freeW);

    api->ldap_value_free_len = (fn_ldap_value_free_len_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_value_free_len);

    api->ldap_msgfree = (fn_ldap_msgfree_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_msgfree);

    api->ldap_get_dn = (fn_ldap_get_dnW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_get_dnW);

    api->ldap_memfree = (fn_ldap_memfreeW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_memfreeW);

    api->ldap_first_attribute = (fn_ldap_first_attributeW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_first_attributeW);

    api->ldap_next_attribute = (fn_ldap_next_attributeW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_next_attributeW);

    api->ber_free = (fn_ber_free_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ber_free);

    api->ldap_create_page_control = (fn_ldap_create_page_controlW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_create_page_controlW);

    api->ldap_parse_page_control = (fn_ldap_parse_page_controlW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_parse_page_controlW);

    api->ldap_parse_result = (fn_ldap_parse_resultW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_parse_resultW);

    api->ldap_controls_free = (fn_ldap_controls_freeA_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_controls_freeA);

    api->ldap_err2string = (fn_ldap_err2stringW_t)
        phantom_get_proc_addr(wldap32_base, PHANTOM_HASH_ldap_err2stringW);

    /* ------------------------------------------------------------------
     * Step 4: Verification pass -- check every pointer for NULL.
     *
     * The PHANTOM_CHECK_LDAP_FN_EX macro emits a named error for each
     * missing export and accumulates failures into all_ok. This means ALL
     * missing exports are reported in a single invocation, not just the first.
     *
     * The macro takes (struct_field, export_name_string, hash_constant).
     * ------------------------------------------------------------------ */

#define PHANTOM_CHECK_LDAP_FN_EX(field, export_name, hash_val)      \
    do {                                                             \
        if (!(api->field)) {                                         \
            BeaconPrintf(CALLBACK_ERROR,                             \
                "[!] PhantomLDAP: wldap32!%s unresolved "           \
                "(hash=0x%08lX).\n",                                 \
                (export_name), (ULONG)(hash_val));                   \
            all_ok = FALSE;                                          \
        }                                                            \
    } while(0)

    PHANTOM_CHECK_LDAP_FN_EX(ldap_init,                "ldap_initW",
                              PHANTOM_HASH_ldap_initW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_set_option,          "ldap_set_option",
                              PHANTOM_HASH_ldap_set_option);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_get_option,          "ldap_get_option",
                              PHANTOM_HASH_ldap_get_option);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_connect,             "ldap_connect",
                              PHANTOM_HASH_ldap_connect);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_bind_s,              "ldap_bind_sW",
                              PHANTOM_HASH_ldap_bind_sW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_unbind,              "ldap_unbind",
                              PHANTOM_HASH_ldap_unbind);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_search_ext_s,        "ldap_search_ext_sW",
                              PHANTOM_HASH_ldap_search_ext_sW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_count_entries,       "ldap_count_entries",
                              PHANTOM_HASH_ldap_count_entries);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_first_entry,         "ldap_first_entry",
                              PHANTOM_HASH_ldap_first_entry);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_next_entry,          "ldap_next_entry",
                              PHANTOM_HASH_ldap_next_entry);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_get_values,          "ldap_get_valuesW",
                              PHANTOM_HASH_ldap_get_valuesW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_get_values_len,      "ldap_get_values_lenW",
                              PHANTOM_HASH_ldap_get_values_lenW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_count_values,        "ldap_count_valuesW",
                              PHANTOM_HASH_ldap_count_valuesW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_count_values_len,    "ldap_count_values_len",
                              PHANTOM_HASH_ldap_count_values_len);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_value_free,          "ldap_value_freeW",
                              PHANTOM_HASH_ldap_value_freeW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_value_free_len,      "ldap_value_free_len",
                              PHANTOM_HASH_ldap_value_free_len);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_msgfree,             "ldap_msgfree",
                              PHANTOM_HASH_ldap_msgfree);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_get_dn,              "ldap_get_dnW",
                              PHANTOM_HASH_ldap_get_dnW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_memfree,             "ldap_memfreeW",
                              PHANTOM_HASH_ldap_memfreeW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_first_attribute,     "ldap_first_attributeW",
                              PHANTOM_HASH_ldap_first_attributeW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_next_attribute,      "ldap_next_attributeW",
                              PHANTOM_HASH_ldap_next_attributeW);
    PHANTOM_CHECK_LDAP_FN_EX(ber_free,                 "ber_free",
                              PHANTOM_HASH_ber_free);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_create_page_control, "ldap_create_page_controlW",
                              PHANTOM_HASH_ldap_create_page_controlW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_parse_page_control,  "ldap_parse_page_controlW",
                              PHANTOM_HASH_ldap_parse_page_controlW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_parse_result,        "ldap_parse_resultW",
                              PHANTOM_HASH_ldap_parse_resultW);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_controls_free,       "ldap_controls_freeA",
                              PHANTOM_HASH_ldap_controls_freeA);
    PHANTOM_CHECK_LDAP_FN_EX(ldap_err2string,          "ldap_err2stringW",
                              PHANTOM_HASH_ldap_err2stringW);

#undef PHANTOM_CHECK_LDAP_FN_EX

    /* ------------------------------------------------------------------
     * Final result: return FALSE if any export was unresolved.
     * ------------------------------------------------------------------ */
    if (!all_ok) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: LDAP API table incomplete -- aborting.\n");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] PhantomLDAP: All 27 wldap32 exports resolved successfully.\n");

    return TRUE;
}

/* =========================================================================
 * End of dynamic_resolve.c
 * ========================================================================= */
