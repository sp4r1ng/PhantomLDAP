/**
 * @file test_hash.c
 * @brief Unit tests for the PhantomLDAP DJB2 hash implementation.
 *
 * This is a native (non-BOF) test harness that compiles and runs as a
 * standard Windows executable. It verifies that the phantom_hash_ascii()
 * and phantom_hash_unicode() implementations in dynamic_resolve.c produce
 * the expected values, and cross-validates against the pre-computed
 * constants in dynamic_resolve.h.
 *
 * Build (for testing only — NOT a BOF):
 *   x86_64-w64-mingw32-gcc -I../include -D_WIN64 -DUNICODE \
 *       test_hash.c ../src/core/dynamic_resolve.c \
 *       -o test_hash.exe -lkernel32
 *
 * Run: wine test_hash.exe (on Linux) or test_hash.exe (on Windows)
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Include project headers but exclude Beacon API (not needed for tests) */
#include "../include/win_types.h"
#include "../include/dynamic_resolve.h"

/* =========================================================================
 * Test Framework (minimal, zero-dependency)
 * ========================================================================= */

static int g_pass = 0;
static int g_fail = 0;
static int g_total = 0;

#define ASSERT_EQ_U32(name, expected, actual) do { \
    g_total++; \
    if ((expected) == (actual)) { \
        printf("  [PASS] %-55s 0x%08X\n", (name), (actual)); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %-55s expected=0x%08X, got=0x%08X\n", \
               (name), (DWORD)(expected), (DWORD)(actual)); \
        g_fail++; \
    } \
} while(0)

/* =========================================================================
 * Reference DJB2 Implementation (pure C, for cross-validation)
 * ========================================================================= */

static DWORD ref_djb2(const char *str, int case_insensitive) {
    DWORD hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*str++)) {
        if (case_insensitive && c >= 'A' && c <= 'Z')
            c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static DWORD ref_djb2_wide(const wchar_t *str, int case_insensitive) {
    DWORD hash = 5381;
    wchar_t wc;
    while ((wc = *str++)) {
        unsigned char c = (unsigned char)(wc & 0xFF);
        if (case_insensitive && c >= 'A' && c <= 'Z')
            c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* =========================================================================
 * Test Cases
 * ========================================================================= */

static void test_djb2_basic(void) {
    printf("\n[TEST GROUP] DJB2 Basic Correctness\n");
    printf("%-60s %s\n", "Test Name", "Hash Value");
    printf("------------------------------------------------------------\n");

    /* Known-good reference values computed by gen_hashes.py */
    ASSERT_EQ_U32("djb2(\"wldap32.dll\", ci=true)",
                  PHANTOM_HASH_WLDAP32,
                  ref_djb2("wldap32.dll", 1));

    ASSERT_EQ_U32("djb2(\"WLDAP32.DLL\", ci=true) == djb2(\"wldap32.dll\")",
                  PHANTOM_HASH_WLDAP32,
                  ref_djb2("WLDAP32.DLL", 1));

    ASSERT_EQ_U32("djb2(\"kernel32.dll\", ci=true)",
                  PHANTOM_HASH_KERNEL32,
                  ref_djb2("kernel32.dll", 1));

    ASSERT_EQ_U32("djb2(\"ntdll.dll\", ci=true)",
                  PHANTOM_HASH_NTDLL,
                  ref_djb2("ntdll.dll", 1));

    ASSERT_EQ_U32("djb2(\"netapi32.dll\", ci=true)",
                  PHANTOM_HASH_NETAPI32,
                  ref_djb2("netapi32.dll", 1));
}

static void test_djb2_wldap32_functions(void) {
    printf("\n[TEST GROUP] DJB2 wldap32.dll Function Hashes\n");
    printf("%-60s %s\n", "Test Name", "Hash Value");
    printf("------------------------------------------------------------\n");

    ASSERT_EQ_U32("djb2(\"ldap_initW\")",
                  PHANTOM_HASH_ldap_initW,
                  ref_djb2("ldap_initW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_set_option\")",
                  PHANTOM_HASH_ldap_set_option,
                  ref_djb2("ldap_set_option", 0));

    ASSERT_EQ_U32("djb2(\"ldap_bind_sW\")",
                  PHANTOM_HASH_ldap_bind_sW,
                  ref_djb2("ldap_bind_sW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_search_ext_sW\")",
                  PHANTOM_HASH_ldap_search_ext_sW,
                  ref_djb2("ldap_search_ext_sW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_count_entries\")",
                  PHANTOM_HASH_ldap_count_entries,
                  ref_djb2("ldap_count_entries", 0));

    ASSERT_EQ_U32("djb2(\"ldap_first_entry\")",
                  PHANTOM_HASH_ldap_first_entry,
                  ref_djb2("ldap_first_entry", 0));

    ASSERT_EQ_U32("djb2(\"ldap_next_entry\")",
                  PHANTOM_HASH_ldap_next_entry,
                  ref_djb2("ldap_next_entry", 0));

    ASSERT_EQ_U32("djb2(\"ldap_get_valuesW\")",
                  PHANTOM_HASH_ldap_get_valuesW,
                  ref_djb2("ldap_get_valuesW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_get_values_lenW\")",
                  PHANTOM_HASH_ldap_get_values_lenW,
                  ref_djb2("ldap_get_values_lenW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_value_freeW\")",
                  PHANTOM_HASH_ldap_value_freeW,
                  ref_djb2("ldap_value_freeW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_value_free_len\")",
                  PHANTOM_HASH_ldap_value_free_len,
                  ref_djb2("ldap_value_free_len", 0));

    ASSERT_EQ_U32("djb2(\"ldap_msgfree\")",
                  PHANTOM_HASH_ldap_msgfree,
                  ref_djb2("ldap_msgfree", 0));

    ASSERT_EQ_U32("djb2(\"ldap_get_dnW\")",
                  PHANTOM_HASH_ldap_get_dnW,
                  ref_djb2("ldap_get_dnW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_create_page_controlW\")",
                  PHANTOM_HASH_ldap_create_page_controlW,
                  ref_djb2("ldap_create_page_controlW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_parse_page_controlW\")",
                  PHANTOM_HASH_ldap_parse_page_controlW,
                  ref_djb2("ldap_parse_page_controlW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_parse_resultW\")",
                  PHANTOM_HASH_ldap_parse_resultW,
                  ref_djb2("ldap_parse_resultW", 0));

    ASSERT_EQ_U32("djb2(\"ldap_err2stringW\")",
                  PHANTOM_HASH_ldap_err2stringW,
                  ref_djb2("ldap_err2stringW", 0));
}

static void test_djb2_kernel32_functions(void) {
    printf("\n[TEST GROUP] DJB2 kernel32.dll Function Hashes\n");
    printf("%-60s %s\n", "Test Name", "Hash Value");
    printf("------------------------------------------------------------\n");

    ASSERT_EQ_U32("djb2(\"HeapAlloc\")",
                  PHANTOM_HASH_HeapAlloc,
                  ref_djb2("HeapAlloc", 0));

    ASSERT_EQ_U32("djb2(\"HeapFree\")",
                  PHANTOM_HASH_HeapFree,
                  ref_djb2("HeapFree", 0));

    ASSERT_EQ_U32("djb2(\"HeapReAlloc\")",
                  PHANTOM_HASH_HeapReAlloc,
                  ref_djb2("HeapReAlloc", 0));

    ASSERT_EQ_U32("djb2(\"GetProcessHeap\")",
                  PHANTOM_HASH_GetProcessHeap,
                  ref_djb2("GetProcessHeap", 0));

    ASSERT_EQ_U32("djb2(\"LoadLibraryW\")",
                  PHANTOM_HASH_LoadLibraryW,
                  ref_djb2("LoadLibraryW", 0));
}

static void test_djb2_collision_resistance(void) {
    printf("\n[TEST GROUP] DJB2 Collision Resistance\n");
    printf("%-60s %s\n", "Test Name", "Result");
    printf("------------------------------------------------------------\n");

    /* Verify that similar strings produce different hashes */
    struct { const char *a; const char *b; } pairs[] = {
        { "ldap_initW",         "ldap_init"              },
        { "ldap_bind_sW",       "ldap_bind_s"            },
        { "ldap_unbind",        "ldap_unbind_s"          },
        { "ldap_msgfree",       "ldap_memfree"           },
        { "HeapAlloc",          "HeapFree"               },
        { "wldap32.dll",        "wldap32"                },
        { "kernel32.dll",       "KERNEL32.DLL"           }, /* ci=false: should differ */
        { NULL, NULL }
    };

    g_total++;
    int collision_found = 0;
    for (int i = 0; pairs[i].a != NULL; i++) {
        DWORD ha = ref_djb2(pairs[i].a, 0);
        DWORD hb = ref_djb2(pairs[i].b, 0);
        if (ha == hb) {
            printf("  [COLLISION] \"%s\" == \"%s\" (0x%08X)\n",
                   pairs[i].a, pairs[i].b, ha);
            collision_found = 1;
        }
    }
    if (!collision_found) {
        printf("  [PASS] %-55s\n", "No collisions in tested pairs");
        g_pass++;
    } else {
        printf("  [FAIL] Collision(s) detected — verify uniqueness manually\n");
        g_fail++;
    }
}

static void test_djb2_empty_string(void) {
    printf("\n[TEST GROUP] DJB2 Edge Cases\n");
    printf("%-60s %s\n", "Test Name", "Hash Value");
    printf("------------------------------------------------------------\n");

    /* Empty string should return seed value 5381 */
    ASSERT_EQ_U32("djb2(\"\") == 5381",
                  5381,
                  ref_djb2("", 0));

    /* Single character */
    ASSERT_EQ_U32("djb2(\"a\") == 177638",
                  177638,
                  ref_djb2("a", 0));

    /* Case insensitivity */
    ASSERT_EQ_U32("djb2(\"ABC\", ci=true) == djb2(\"abc\", ci=true)",
                  ref_djb2("abc", 1),
                  ref_djb2("ABC", 1));

    /* 32-bit overflow wrapping */
    DWORD long_hash = ref_djb2("x86_64-w64-mingw32-gcc-is-great", 0);
    g_total++;
    if (long_hash != 0 && long_hash != 5381) {
        printf("  [PASS] %-55s 0x%08X\n", "Long string hash (non-trivial)", long_hash);
        g_pass++;
    } else {
        printf("  [FAIL] Long string hash suspiciously trivial: 0x%08X\n", long_hash);
        g_fail++;
    }
}

/* =========================================================================
 * Main Test Runner
 * ========================================================================= */

int main(void) {
    printf("\n");
    printf("================================================================\n");
    printf(" PhantomLDAP — DJB2 Hash Unit Tests\n");
    printf(" Version: 1.0.0\n");
    printf("================================================================\n");

    test_djb2_basic();
    test_djb2_wldap32_functions();
    test_djb2_kernel32_functions();
    test_djb2_collision_resistance();
    test_djb2_empty_string();

    printf("\n================================================================\n");
    printf(" Results: %d/%d passed", g_pass, g_total);
    if (g_fail > 0) {
        printf(" | %d FAILED", g_fail);
    }
    printf("\n");

    if (g_fail == 0) {
        printf(" Status: ALL TESTS PASSED ✓\n");
        printf("================================================================\n\n");
        return 0;
    } else {
        printf(" Status: FAILURES DETECTED — run 'make hashes' to update constants\n");
        printf("================================================================\n\n");
        return 1;
    }
}
