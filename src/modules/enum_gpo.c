/**
 * @file enum_gpo.c
 * @brief PhantomLDAP BOF module — Group Policy Object (GPO) Enumeration
 *
 * Enumerates all groupPolicyContainer objects from
 * CN=Policies,CN=System,<base_dn> via paged LDAP search.
 *
 * For each GPO the module outputs:
 *  - Display name and distinguished name
 *  - Extracted GUID (between first CN= and first comma in the DN)
 *  - SYSVOL UNC path (gPCFileSysPath) — readable: check if writable for abuse
 *  - Version numbers split into user-half and computer-half
 *  - Enabled/Disabled status (flags attribute bit 0 = all disabled,
 *    bit 1 = computer settings disabled, bit 2 = user settings disabled)
 *  - Heuristic flags for security-relevant GPO names
 *
 * Abuse notes:
 *  - A writable SYSVOL path allows planting scripts/payloads (GPO abuse).
 *  - GPOs containing "LAPS", "Applocker", "BitLocker" etc. indicate controls
 *    worth understanding before bypassing.
 *  - A disabled GPO linked to a sensitive OU may have been deliberately
 *    disabled — worth restoring for persistence.
 *
 * Usage (from Cobalt Strike CNA script):
 *   bof_pack args:
 *     z  dc_name    (optional — empty string for current domain)
 *
 * Compilation:
 *   x86_64-w64-mingw32-gcc -o enum_gpo.o -c enum_gpo.c \
 *     -I../../include -Wall -Wextra -masm=intel
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "phantom_ldap.h"
#include "beacon.h"

/* =========================================================================
 * Module-local constants
 * ========================================================================= */

#define GPO_SEPARATOR \
    "------------------------------------------------------------------------"

/** LDAP filter — retrieves all Group Policy Container objects. */
#define GPO_FILTER  L"(objectClass=groupPolicyContainer)"

/** GPO flags bits (from gPCFunctionalityVersion / flags attribute). */
#define GPO_FLAG_ALL_DISABLED       0x00000001  /**< All settings disabled      */
#define GPO_FLAG_USER_DISABLED      0x00000002  /**< User configuration disabled */
#define GPO_FLAG_COMPUTER_DISABLED  0x00000004  /**< Computer config disabled   */

/* =========================================================================
 * Internal structures
 * ========================================================================= */

/**
 * @brief Decoded representation of a single GPO.
 */
typedef struct _GPO_INFO {
    char  display_name[256];    /**< Human-readable GPO name (displayName)      */
    char  dn[1024];             /**< Full distinguished name                    */
    char  guid[64];             /**< GUID extracted from DN, e.g. {31B2F340-…} */
    char  sysvol_path[512];     /**< UNC path to SYSVOL share (gPCFileSysPath)  */
    DWORD version_number;       /**< Combined version number (gPCVersionNumber) */
    DWORD flags;                /**< Status flags (GPO_FLAG_*)                  */
    BOOL  has_version;
    BOOL  has_flags;
} GPO_INFO, *PGPO_INFO;

/**
 * @brief Callback user-data structure for the paged search.
 */
typedef struct _GPO_CB_DATA {
    PPHANTOM_CONTEXT ctx;       /**< Back-pointer to the module context         */
    DWORD            gpo_index; /**< 1-based count of GPOs enumerated so far    */
} GPO_CB_DATA, *PGPO_CB_DATA;

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/**
 * @brief Manually compute the length of a narrow string (no strlen).
 *
 * @param s     Null-terminated string
 * @return      Number of characters before the null terminator
 */
static SIZE_T str_len(const char *s)
{
    SIZE_T n = 0;
    while (s && s[n]) n++;
    return n;
}

/**
 * @brief Case-insensitive substring search within a narrow string.
 *
 * Converts both characters to lowercase before comparing.  No CRT required.
 *
 * @param haystack  String to search within
 * @param needle    Substring to find
 * @return          TRUE if needle is found within haystack (case-insensitive)
 */
static BOOL str_icontains(const char *haystack, const char *needle)
{
    SIZE_T hn = str_len(haystack);
    SIZE_T nn = str_len(needle);
    SIZE_T i, j;

    if (!haystack || !needle || nn == 0 || nn > hn) {
        return FALSE;
    }

    for (i = 0; i <= hn - nn; i++) {
        BOOL match = TRUE;
        for (j = 0; j < nn; j++) {
            char h = haystack[i + j];
            char n = needle[j];
            /* Convert to lowercase. */
            if (h >= 'A' && h <= 'Z') h = (char)(h + 32);
            if (n >= 'A' && n <= 'Z') n = (char)(n + 32);
            if (h != n) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/**
 * @brief Extract the GUID substring from a DN like
 *        "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,...".
 *
 * The GUID is the value of the first CN RDN component.  It starts after
 * "CN=" and ends before the first comma.
 *
 * @param dn        Full DN in narrow ASCII
 * @param out_guid  Output buffer (at least 64 bytes)
 * @param buf_size  Size of out_guid
 */
static void extract_guid_from_dn(const char *dn, char *out_guid, SIZE_T buf_size)
{
    const char *p;
    SIZE_T      i;

    out_guid[0] = '\0';

    if (!dn) return;

    /* Find "CN=" at start (case-insensitive). */
    p = dn;
    if ((p[0] == 'C' || p[0] == 'c') &&
        (p[1] == 'N' || p[1] == 'n') &&
         p[2] == '=') {
        p += 3;
    } else {
        return;
    }

    /* Copy characters until comma or end of string. */
    for (i = 0; *p && *p != ',' && i + 1 < buf_size; i++, p++) {
        out_guid[i] = *p;
    }
    out_guid[i] = '\0';
}

/**
 * @brief Extract a single-value DWORD attribute (numeric string → DWORD).
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param entry     LDAP entry
 * @param attr      Wide attribute name
 * @param out_val   Receives parsed value on success
 * @return          TRUE on success
 */
static BOOL extract_dword_attr(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     entry,
    PWSTR            attr,
    DWORD           *out_val)
{
    PWSTR *vals = NULL;
    BOOL   ok   = FALSE;

    vals = ctx->api.ldap_get_values(ctx->ldap_handle, entry, attr);
    if (!vals || !vals[0]) goto cleanup;

    {
        PWSTR p   = vals[0];
        DWORD acc = 0;
        while (*p >= L'0' && *p <= L'9') {
            acc = acc * 10u + (DWORD)(*p - L'0');
            p++;
        }
        *out_val = acc;
    }
    ok = TRUE;

cleanup:
    if (vals) ctx->api.ldap_value_free(vals);
    return ok;
}

/**
 * @brief Extract a single-value wide-string attribute into a narrow buffer.
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param entry     LDAP entry
 * @param attr      Wide attribute name
 * @param out_buf   Output narrow buffer
 * @param buf_size  Size of out_buf in bytes
 * @return          TRUE on success
 */
static BOOL extract_str_attr(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     entry,
    PWSTR            attr,
    char            *out_buf,
    SIZE_T           buf_size)
{
    PWSTR *vals = NULL;
    BOOL   ok   = FALSE;

    vals = ctx->api.ldap_get_values(ctx->ldap_handle, entry, attr);
    if (!vals || !vals[0]) goto cleanup;

    phantom_wstr_to_str(vals[0], out_buf, buf_size);
    ok = TRUE;

cleanup:
    if (vals) ctx->api.ldap_value_free(vals);
    return ok;
}

/* =========================================================================
 * Output helper
 * ========================================================================= */

/**
 * @brief Decode the GPO status flags into a human-readable label.
 *
 * @param flags     Raw flags DWORD from gPCFunctionalityVersion / flags attr
 * @return          Static ASCII string
 */
static const char *gpo_status_str(DWORD flags)
{
    if (flags & GPO_FLAG_ALL_DISABLED)      return "All Settings Disabled";
    if (flags & GPO_FLAG_USER_DISABLED)     return "User Settings Disabled";
    if (flags & GPO_FLAG_COMPUTER_DISABLED) return "Computer Settings Disabled";
    return "Enabled (All Settings Active)";
}

/**
 * @brief Print a single decoded GPO entry plus any heuristic notes.
 *
 * @param info       Decoded GPO information (read-only)
 * @param gpo_index  1-based ordinal
 */
static void print_gpo(const GPO_INFO *info, DWORD gpo_index)
{
    /* Version number: low 16 bits = user version, high 16 bits = computer. */
    DWORD user_ver     = info->has_version ? (info->version_number & 0xFFFFu)       : 0;
    DWORD computer_ver = info->has_version ? ((info->version_number >> 16) & 0xFFFFu) : 0;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] GPO #%lu: %s\n"
        "    DN      : %s\n"
        "    GUID    : %s\n"
        "    SYSVOL  : %s\n"
        "    Version : User=%lu, Computer=%lu\n"
        "    Status  : %s\n",
        (unsigned long)gpo_index,
        info->display_name[0] ? info->display_name : "(no displayName)",
        info->dn[0]           ? info->dn           : "(no DN)",
        info->guid[0]         ? info->guid         : "(no GUID)",
        info->sysvol_path[0]  ? info->sysvol_path  : "(no SYSVOL path)",
        (unsigned long)user_ver,
        (unsigned long)computer_ver,
        info->has_flags       ? gpo_status_str(info->flags) : "Unknown");

    /* ------------------------------------------------------------------- */
    /* Security-relevant heuristic notes.                                   */
    /* ------------------------------------------------------------------- */

    /* SYSVOL path presence — always note writeability concern. */
    if (info->sysvol_path[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] SYSVOL path visible. If the share is writable by your context,\n"
            "        you can plant scripts/executables for GPO-based code execution.\n"
            "        Check write access: net use \\\\dc\\sysvol then icacls <path>\n");
    }

    /* Security controls detection — interesting GPOs to note. */
    if (str_icontains(info->display_name, "laps")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] LAPS GPO detected -- local administrator passwords are managed.\n"
            "        Enumerate ms-Mcs-AdmPwd / msLAPS-Password if you have read rights.\n");
    }
    if (str_icontains(info->display_name, "applocker") ||
        str_icontains(info->display_name, "srp")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] AppLocker/SRP GPO detected -- code execution may be restricted.\n"
            "        Review rules: Get-AppLockerPolicy -Effective | Test-AppLockerPolicy\n");
    }
    if (str_icontains(info->display_name, "bitlocker")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] BitLocker GPO detected -- disk encryption policy enforced.\n");
    }
    if (str_icontains(info->display_name, "firewall")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] Firewall GPO detected -- review rules for inbound/outbound gaps.\n");
    }
    if (str_icontains(info->display_name, "antivirus") ||
        str_icontains(info->display_name, "defender") ||
        str_icontains(info->display_name, "av ") ||
        str_icontains(info->display_name, " av")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] AV/Defender GPO detected -- review exclusions for bypass paths.\n");
    }
    if (str_icontains(info->display_name, "powershell") ||
        str_icontains(info->display_name, "constrained")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] PowerShell policy GPO detected -- Constrained Language Mode may apply.\n");
    }
    if (str_icontains(info->display_name, "audit") ||
        str_icontains(info->display_name, "logging")) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] Audit/Logging GPO detected -- review audit categories being captured.\n");
    }

    /* Disabled GPO note — may indicate intentional gap or misconfiguration. */
    if (info->has_flags && (info->flags & GPO_FLAG_ALL_DISABLED)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] This GPO is FULLY DISABLED -- no settings are currently enforced.\n"
            "        A disabled security GPO (e.g., AV, LAPS) may represent a misconfiguration\n"
            "        or deliberate gap. Verify whether it is linked to any OUs.\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", GPO_SEPARATOR);
}

/* =========================================================================
 * Paged-search callback
 * ========================================================================= */

/**
 * @brief Paged-search callback invoked once per result page.
 *
 * Iterates all entries in the page, extracts GPO attributes, and calls
 * print_gpo() for each decoded object.
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param message   Page LDAPMessage chain
 * @param user_data Pointer to GPO_CB_DATA
 * @return          TRUE to continue; FALSE to abort
 */
static BOOL gpo_callback(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     message,
    PVOID            user_data)
{
    PGPO_CB_DATA cb    = (PGPO_CB_DATA)user_data;
    PLDAPMessage entry = NULL;

    if (!message || !cb) return FALSE;

    entry = ctx->api.ldap_first_entry(ctx->ldap_handle, message);

    while (entry) {
        GPO_INFO info;
        PWSTR   *dn_val = NULL;

        /* Zero-init without memset. */
        {
            PBYTE  p = (PBYTE)&info;
            SIZE_T s = sizeof(info);
            while (s--) { *p++ = 0; }
        }

        /* Extract the DN (distinguishedName) from the entry itself. */
        {
            PWSTR dn_wide = ctx->api.ldap_get_dn(ctx->ldap_handle, entry);
            if (dn_wide) {
                phantom_wstr_to_str(dn_wide, info.dn, sizeof(info.dn));
                ctx->api.ldap_memfree(dn_wide);
            }
        }
        (void)dn_val; /* suppress unused-variable warning */

        /* Extract displayName. */
        extract_str_attr(ctx, entry, ATTR_GPO_DISPLAY_NAME,
                         info.display_name, sizeof(info.display_name));

        /* Extract gPCFileSysPath (SYSVOL UNC). */
        extract_str_attr(ctx, entry, ATTR_GPO_FILE_SYS_PATH,
                         info.sysvol_path, sizeof(info.sysvol_path));

        /* Extract versionNumber. */
        info.has_version =
            extract_dword_attr(ctx, entry, ATTR_GPO_VERSION,
                               &info.version_number);

        /* Extract flags (gPCFunctionalityVersion). */
        info.has_flags =
            extract_dword_attr(ctx, entry, ATTR_GPO_FUNC_VERSION,
                               &info.flags);

        /* Extract GUID from the DN. */
        extract_guid_from_dn(info.dn, info.guid, sizeof(info.guid));

        cb->gpo_index++;
        print_gpo(&info, cb->gpo_index);

        entry = ctx->api.ldap_next_entry(ctx->ldap_handle, entry);
    }

    return TRUE;
}

/* =========================================================================
 * BOF entry point
 * ========================================================================= */

/**
 * @brief BOF entry point for GPO enumeration.
 *
 * Argument buffer (packed by CNA bof_pack):
 *   [z]  dc_name   — Target DC hostname. Empty string means auto-discover.
 *
 * Execution flow:
 *   1. Parse BOF arguments.
 *   2. Initialize LDAP session via phantom_ldap_init().
 *   3. Build search base CN=Policies,CN=System,<base_dn>.
 *   4. Execute paged search for (objectClass=groupPolicyContainer).
 *   5. gpo_callback() decodes and prints each GPO per page.
 *   6. Emit footer and clean up.
 *
 * @param args  Raw BOF argument buffer
 * @param alen  Buffer length in bytes
 */
void go(char *args, int alen)
{
    datap         parser;
    char         *dc_name_a  = NULL;
    int           dc_name_sz = 0;
    PHANTOM_CONTEXT ctx;
    GPO_CB_DATA   cb_data;
    WCHAR         search_base[768];
    DWORD         rc = 0;
    BOOL          ok = FALSE;

    PWSTR attrs[] = {
        ATTR_GPO_DISPLAY_NAME,
        ATTR_GPO_FILE_SYS_PATH,
        ATTR_GPO_VERSION,
        ATTR_GPO_FUNC_VERSION,
        ATTR_DISTINGUISHED_NAME,
        NULL
    };

    /* Zero-init stack structures. */
    {
        PBYTE p = (PBYTE)&ctx; SIZE_T s = sizeof(ctx); while (s--) { *p++ = 0; }
    }
    {
        PBYTE p = (PBYTE)&cb_data; SIZE_T s = sizeof(cb_data); while (s--) { *p++ = 0; }
    }
    {
        PBYTE p = (PBYTE)search_base; SIZE_T s = sizeof(search_base); while (s--) { *p++ = 0; }
    }

    /* ------------------------------------------------------------------ */
    /* 1. Parse arguments.                                                  */
    /* ------------------------------------------------------------------ */
    BeaconDataParse(&parser, args, alen);
    dc_name_a = BeaconDataExtract(&parser, &dc_name_sz);

    /* ------------------------------------------------------------------ */
    /* 2. Banner.                                                           */
    /* ------------------------------------------------------------------ */
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] PhantomLDAP :: GPO Enumeration v" PHANTOM_VERSION_STR "\n"
        "    DC target : %s\n"
        "    %s\n",
        (dc_name_a && dc_name_a[0]) ? dc_name_a : "(auto-discover via DNS)",
        GPO_SEPARATOR);

    /* ------------------------------------------------------------------ */
    /* 3. LDAP init.                                                        */
    /* ------------------------------------------------------------------ */
    {
        WCHAR dc_wide[256];
        {
            PBYTE p = (PBYTE)dc_wide; SIZE_T s = sizeof(dc_wide); while (s--) { *p++ = 0; }
        }
        if (dc_name_a && dc_name_a[0]) {
            phantom_str_to_wstr(dc_name_a, dc_wide, 256);
        }
        ok = phantom_ldap_init(
            &ctx,
            (dc_name_a && dc_name_a[0]) ? dc_wide : NULL,
            FALSE,
            0
        );
    }

    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_gpo: phantom_ldap_init failed. "
            "Verify DC reachability and Kerberos ticket.\n");
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Build search base: CN=Policies,CN=System,<base_dn>               */
    /* ------------------------------------------------------------------ */
    {
        const WCHAR prefix[] = L"CN=Policies,CN=System,";
        SIZE_T pi = 0;
        SIZE_T bi = 0;
        while (prefix[pi] && pi < 767) {
            search_base[pi] = prefix[pi];
            pi++;
        }
        while (ctx.base_dn[bi] && (pi + bi) < 767) {
            search_base[pi + bi] = ctx.base_dn[bi];
            bi++;
        }
        search_base[pi + bi] = L'\0';
    }

    /* ------------------------------------------------------------------ */
    /* 5. Paged search.                                                     */
    /* ------------------------------------------------------------------ */
    cb_data.ctx       = &ctx;
    cb_data.gpo_index = 0;

    rc = phantom_ldap_paged_search(
        &ctx,
        search_base,
        LDAP_SCOPE_ONELEVEL,
        GPO_FILTER,
        attrs,
        gpo_callback,
        &cb_data
    );

    /* ------------------------------------------------------------------ */
    /* 6. Footer.                                                           */
    /* ------------------------------------------------------------------ */
    if (rc != LDAP_SUCCESS && rc != LDAP_NO_RESULTS_RETURNED) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_gpo: search returned LDAP error 0x%02lX.\n",
            (unsigned long)rc);
    }

    if (cb_data.gpo_index == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] No GPO objects found under CN=Policies,CN=System.\n"
            "    The search base may be inaccessible or the domain uses a non-standard layout.\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] GPO enumeration complete.\n"
        "    Total GPOs   : %lu\n"
        "    LDAP pages   : %lu\n"
        "    %s\n\n",
        (unsigned long)cb_data.gpo_index,
        (unsigned long)ctx.page_count,
        GPO_SEPARATOR);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
