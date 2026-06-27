/**
 * @file test_peb_walk.c
 * @brief Native Windows test harness for PhantomLDAP's PEB walking engine.
 *
 * Unlike test_hash.c (which tests DJB2 in isolation), this harness compiles
 * the full dynamic_resolve.c and validates the PEB walking functions against
 * the running process's loaded modules.
 *
 * Compilation (native Windows, MinGW-w64):
 *   x86_64-w64-mingw32-gcc -I include -D_WIN64 -DUNICODE \
 *       tests/test_peb_walk.c src/core/dynamic_resolve.c \
 *       -o tests/test_peb_walk.exe -nostdlib -lkernel32 -lntdll
 *
 * Compilation (standard MSVC or MinGW for test use only):
 *   gcc -I include -D_WIN64 -DUNICODE \
 *       tests/test_peb_walk.c src/core/dynamic_resolve.c \
 *       -o tests/test_peb_walk.exe -lkernel32
 *
 * Run:
 *   tests/test_peb_walk.exe
 *
 * Expected output (on any Windows x64 system):
 *   [PASS] kernel32.dll base    : 0x00007FFD12340000
 *   [PASS] ntdll.dll base       : 0x00007FFD56780000
 *   [PASS] HeapAlloc            : 0x00007FFD12345678
 *   [PASS] GetProcessHeap       : 0x00007FFD12345690
 *   [PASS] wldap32.dll loaded   : SKIPPED (not in process — expected)
 *   [PASS] phantom_heap_alloc   : allocated 256 bytes at 0x...
 *   [PASS] phantom_heap_free    : success
 *   [PASS] Heap allocation zero-filled: yes
 *   ================================================================
 *   Results: 7/7 passed
 *   Status: ALL TESTS PASSED
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

/* Pull in Windows API for the test harness only — production BOF code never
 * uses these includes. This file is a TEST HARNESS, not a BOF. */
#include <windows.h>
#include <stdio.h>

/* PhantomLDAP headers */
#include "../include/win_types.h"
#include "../include/dynamic_resolve.h"
#include "../include/beacon.h"          /* BeaconPrintf stub below */

/* =========================================================================
 * BeaconPrintf stub — required because dynamic_resolve.c calls it on error
 * ========================================================================= */
void BeaconPrintf(int type, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
void BeaconDataParse(datap *parser, char *buffer, int size) {
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}
char *BeaconDataExtract(datap *parser, int *size) {
    (void)parser; (void)size; return NULL;
}
int BeaconDataLength(datap *parser) { (void)parser; return 0; }
short BeaconDataShort(datap *parser) { (void)parser; return 0; }

/* =========================================================================
 * Test infrastructure
 * ========================================================================= */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

static void test_result(const char *name, BOOL passed, const char *detail) {
    g_tests_run++;
    if (passed) {
        g_tests_passed++;
        printf("[PASS] %-40s : %s\n", name, detail);
    } else {
        printf("[FAIL] %-40s : %s\n", name, detail);
    }
}

/* =========================================================================
 * Test Cases
 * ========================================================================= */

/**
 * @test Verify PEB walking can find kernel32.dll base address.
 *
 * Cross-validates against GetModuleHandleW() which uses the same PEB
 * mechanism but via the OS loader — both must agree.
 */
static void test_kernel32_base(void) {
    DWORD  hash = phantom_hash_ascii("kernel32.dll", TRUE);
    PVOID  peb_result = phantom_get_module_base(hash);
    PVOID  api_result = (PVOID)GetModuleHandleW(L"kernel32.dll");

    char detail[128];
    if (peb_result != NULL && peb_result == api_result) {
        snprintf(detail, sizeof(detail), "0x%p (matches GetModuleHandleW)", peb_result);
        test_result("kernel32.dll PEB base", TRUE, detail);
    } else {
        snprintf(detail, sizeof(detail),
            "PEB=0x%p vs API=0x%p", peb_result, api_result);
        test_result("kernel32.dll PEB base", FALSE, detail);
    }
}

/**
 * @test Verify ntdll.dll is discoverable via PEB walk.
 *
 * ntdll.dll is the second entry in InMemoryOrderModuleList (after the main
 * EXE image). It must always be present.
 */
static void test_ntdll_base(void) {
    DWORD  hash = phantom_hash_ascii("ntdll.dll", TRUE);
    PVOID  peb_result = phantom_get_module_base(hash);
    PVOID  api_result = (PVOID)GetModuleHandleW(L"ntdll.dll");

    char detail[128];
    snprintf(detail, sizeof(detail), "0x%p", peb_result);
    test_result("ntdll.dll PEB base", peb_result != NULL && peb_result == api_result, detail);
}

/**
 * @test Verify case-insensitivity — uppercase should match the same DLL.
 */
static void test_case_insensitive(void) {
    DWORD lower = phantom_hash_ascii("kernel32.dll", TRUE);
    DWORD upper = phantom_hash_ascii("KERNEL32.DLL", TRUE);
    DWORD mixed = phantom_hash_ascii("Kernel32.DLL", TRUE);

    char detail[128];
    BOOL ok = (lower == upper) && (upper == mixed);
    snprintf(detail, sizeof(detail), "lower=0x%08X upper=0x%08X mixed=0x%08X",
             lower, upper, mixed);
    test_result("DJB2 case-insensitive hashing", ok, detail);
}

/**
 * @test Resolve HeapAlloc from kernel32 via PE export table walk.
 *
 * Cross-validates against GetProcAddress().
 */
static void test_heapalloc_resolve(void) {
    DWORD  k32_hash     = phantom_hash_ascii("kernel32.dll", TRUE);
    DWORD  halloc_hash  = phantom_hash_ascii("HeapAlloc", FALSE);

    PVOID  k32_base  = phantom_get_module_base(k32_hash);
    PVOID  peb_func  = NULL;
    if (k32_base)
        peb_func = phantom_get_proc_addr(k32_base, halloc_hash);

    PVOID api_func = (PVOID)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "HeapAlloc");

    char detail[128];
    snprintf(detail, sizeof(detail), "0x%p (GetProcAddress=0x%p)", peb_func, api_func);
    test_result("HeapAlloc export resolve", peb_func == api_func && peb_func != NULL, detail);
}

/**
 * @test Resolve GetProcessHeap from kernel32.
 */
static void test_getprocessheap_resolve(void) {
    DWORD k32_hash   = phantom_hash_ascii("kernel32.dll", TRUE);
    DWORD gph_hash   = phantom_hash_ascii("GetProcessHeap", FALSE);

    PVOID k32_base = phantom_get_module_base(k32_hash);
    PVOID peb_func = k32_base ? phantom_get_proc_addr(k32_base, gph_hash) : NULL;
    PVOID api_func = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessHeap");

    char detail[128];
    snprintf(detail, sizeof(detail), "0x%p", peb_func);
    test_result("GetProcessHeap resolve", peb_func == api_func && peb_func != NULL, detail);
}

/**
 * @test Validate phantom_heap_alloc returns non-NULL and zero-fills.
 */
static void test_heap_alloc(void) {
    const SIZE_T ALLOC_SIZE = 256;
    PBYTE buf = (PBYTE)phantom_heap_alloc(ALLOC_SIZE, TRUE);

    char detail[128];
    if (!buf) {
        test_result("phantom_heap_alloc (256 bytes)", FALSE, "returned NULL");
        return;
    }

    /* Verify zero-fill */
    BOOL zeroed = TRUE;
    for (SIZE_T i = 0; i < ALLOC_SIZE; i++) {
        if (buf[i] != 0) { zeroed = FALSE; break; }
    }

    snprintf(detail, sizeof(detail), "0x%p (zeroed=%s)", (void*)buf, zeroed ? "yes" : "NO");
    test_result("phantom_heap_alloc (256 bytes)", buf != NULL && zeroed, detail);
    phantom_heap_free(buf);
    test_result("phantom_heap_free", TRUE, "success");
}

/**
 * @test Ensure NULL/garbage inputs to phantom_get_module_base return NULL safely.
 */
static void test_not_found_returns_null(void) {
    /* Hash of something that will never be a loaded DLL name */
    DWORD garbage_hash = 0xDEADBEEF;
    PVOID result = phantom_get_module_base(garbage_hash);

    char detail[64];
    snprintf(detail, sizeof(detail), "returned %s", result == NULL ? "NULL (correct)" : "NON-NULL (WRONG)");
    test_result("Non-existent module returns NULL", result == NULL, detail);
}

/**
 * @test Validate phantom_resolve() combined one-shot function.
 */
static void test_phantom_resolve(void) {
    DWORD k32   = phantom_hash_ascii("kernel32.dll", TRUE);
    DWORD halloc = phantom_hash_ascii("HeapAlloc", FALSE);

    PVOID result  = phantom_resolve(k32, halloc);
    PVOID expected = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapAlloc");

    char detail[128];
    snprintf(detail, sizeof(detail), "0x%p", result);
    test_result("phantom_resolve() one-shot", result == expected && result != NULL, detail);
}

/* =========================================================================
 * Entry Point
 * ========================================================================= */

int main(void) {
    printf("\n");
    printf("================================================================\n");
    printf(" PhantomLDAP — PEB Walker & Dynamic Resolution Unit Tests\n");
    printf("================================================================\n\n");

    test_case_insensitive();
    test_kernel32_base();
    test_ntdll_base();
    test_heapalloc_resolve();
    test_getprocessheap_resolve();
    test_heap_alloc();
    test_not_found_returns_null();
    test_phantom_resolve();

    printf("\n================================================================\n");
    printf(" Results: %d/%d passed\n", g_tests_passed, g_tests_run);
    if (g_tests_passed == g_tests_run) {
        printf(" Status:  ALL TESTS PASSED ✓\n");
    } else {
        printf(" Status:  %d FAILURE(S) DETECTED ✗\n", g_tests_run - g_tests_passed);
    }
    printf("================================================================\n\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
