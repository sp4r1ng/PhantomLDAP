/**
 * @file enum_computers.c
 * @brief PhantomLDAP BOF — Enumerate computer objects with OS analysis.
 *
 * Retrieves all computer accounts from Active Directory, categorizes them
 * by operating system family, identifies stale/inactive machines, and
 * flags legacy OS versions that represent high-value lateral movement targets.
 *
 * LDAP Filter: (objectClass=computer)
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

#define MODULE_TAG   "COMPUTER-ENUM"
#define MODULE_TITLE "Computer Object Inventory & OS Analysis"

/* Staleness threshold: machines inactive for > 90 days */
#define STALE_DAYS_THRESHOLD 90ULL

static PWSTR g_attrs[] = {
    L"dNSHostName",
    L"sAMAccountName",
    L"distinguishedName",
    L"operatingSystem",
    L"operatingSystemVersion",
    L"operatingSystemServicePack",
    L"lastLogonTimestamp",
    L"userAccountControl",
    L"description",
    L"objectSid",
    NULL
};

/* OS summary counters */
typedef struct {
    DWORD server2022;
    DWORD server2019;
    DWORD server2016;
    DWORD server2012;
    DWORD server2008;
    DWORD win11;
    DWORD win10;
    DWORD win7_8;
    DWORD winxp_2003;
    DWORD linux_other;
    DWORD unknown;
    DWORD stale;
    DWORD dc_count;
} OS_STATS;

static OS_STATS g_os = {0};

/** Simple case-insensitive substring check */
static BOOL str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return FALSE;
    const char *h = haystack;
    while (*h) {
        const char *hp = h, *np = needle;
        while (*hp && *np) {
            char hc = *hp >= 'A' && *hp <= 'Z' ? *hp + 32 : *hp;
            char nc = *np >= 'A' && *np <= 'Z' ? *np + 32 : *np;
            if (hc != nc) break;
            hp++; np++;
        }
        if (!*np) return TRUE;
        h++;
    }
    return FALSE;
}

static BOOL enum_computers_callback(PPHANTOM_CONTEXT ctx, PLDAPMessage entry, PVOID user_data) {
    (void)user_data;
    PPHANTOM_LDAP_API api = &ctx->api;

    PWSTR *dns_vals   = NULL;
    PWSTR *sam_vals   = NULL;
    PWSTR *dn_vals    = NULL;
    PWSTR *os_vals    = NULL;
    PWSTR *osver_vals = NULL;
    PWSTR *ossp_vals  = NULL;
    PWSTR *ts_vals    = NULL;
    PWSTR *uac_vals   = NULL;
    PWSTR *desc_vals  = NULL;
    PLDAP_BERVAL *sid_vals = NULL;

    char dns_str[256] = {0};
    char sam_str[128] = {0};
    char dn_str[512]  = {0};
    char os_str[128]  = {0};
    char osver[64]    = {0};
    char ts_str[48]   = {0};
    char ts_age[48]   = {0};
    char sid_str[185] = {0};
    char desc_str[256] = {0};

    ctx->total_found++;

    dns_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DNS_HOST_NAME);
    if (dns_vals && dns_vals[0]) phantom_wstr_to_str(dns_vals[0], dns_str, sizeof(dns_str));

    sam_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_SAM_ACCOUNT_NAME);
    if (sam_vals && sam_vals[0]) phantom_wstr_to_str(sam_vals[0], sam_str, sizeof(sam_str));

    dn_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DISTINGUISHED_NAME);
    if (dn_vals && dn_vals[0]) phantom_wstr_to_str(dn_vals[0], dn_str, sizeof(dn_str));

    os_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_OS);
    if (os_vals && os_vals[0]) phantom_wstr_to_str(os_vals[0], os_str, sizeof(os_str));

    osver_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_OS_VERSION);
    if (osver_vals && osver_vals[0]) phantom_wstr_to_str(osver_vals[0], osver, sizeof(osver));

    desc_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DESCRIPTION);
    if (desc_vals && desc_vals[0]) phantom_wstr_to_str(desc_vals[0], desc_str, sizeof(desc_str));

    DWORD uac_val = 0;
    uac_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_USER_ACCOUNT_CTRL);
    if (uac_vals && uac_vals[0]) {
        PWSTR w = uac_vals[0];
        while (*w >= L'0' && *w <= L'9') { uac_val = uac_val * 10 + (DWORD)(*w - L'0'); w++; }
    }

    LONGLONG ts_ft = 0;
    ts_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_LAST_LOGON_TIMESTAMP);
    if (ts_vals && ts_vals[0]) {
        PWSTR w = ts_vals[0];
        while (*w >= L'0' && *w <= L'9') { ts_ft = ts_ft * 10 + (LONGLONG)(*w - L'0'); w++; }
        phantom_filetime_to_str(ts_ft, ts_str, sizeof(ts_str));
        phantom_filetime_to_age(ts_ft, ts_age, sizeof(ts_age));
    }

    sid_vals = api->ldap_get_values_len(ctx->ldap_handle, entry, ATTR_OBJECT_SID);
    if (sid_vals && sid_vals[0])
        phantom_sid_to_string((BYTE *)sid_vals[0]->bv_val,
                              (DWORD)sid_vals[0]->bv_len, sid_str, sizeof(sid_str));

    /* Classify OS */
    BOOL is_dc    = (uac_val & UAC_SERVER_TRUST_ACCOUNT) != 0;
    BOOL is_stale = FALSE;
    BOOL is_legacy = FALSE;

    if (ts_ft != 0) {
        unsigned long long ft_unix = (unsigned long long)(ts_ft - 116444736000000000LL) / 10000000ULL;
        unsigned long long days_old = (1750000000ULL > ft_unix) ? (1750000000ULL - ft_unix) / 86400ULL : 0;
        if (days_old > STALE_DAYS_THRESHOLD) { is_stale = TRUE; g_os.stale++; }
    } else {
        /* No logon timestamp = stale */
        is_stale = TRUE; g_os.stale++;
    }

    if (is_dc) g_os.dc_count++;

    /* Categorize OS for statistics */
    if (str_contains(os_str, "2022"))       g_os.server2022++;
    else if (str_contains(os_str, "2019"))  g_os.server2019++;
    else if (str_contains(os_str, "2016"))  g_os.server2016++;
    else if (str_contains(os_str, "2012"))  g_os.server2012++;
    else if (str_contains(os_str, "2008"))  { g_os.server2008++; is_legacy = TRUE; }
    else if (str_contains(os_str, "2003"))  { g_os.winxp_2003++; is_legacy = TRUE; }
    else if (str_contains(os_str, "Windows 11")) g_os.win11++;
    else if (str_contains(os_str, "Windows 10")) g_os.win10++;
    else if (str_contains(os_str, "Windows 7") || str_contains(os_str, "Windows 8")) {
        g_os.win7_8++; is_legacy = TRUE;
    }
    else if (str_contains(os_str, "XP") || str_contains(os_str, "Windows XP")) {
        g_os.winxp_2003++; is_legacy = TRUE;
    }
    else if (os_str[0] == '\0') g_os.unknown++;
    else g_os.linux_other++;

    /* Output — stale/legacy computers get a warning prefix */
    phantom_print_separator('-');
    if (is_legacy && is_stale) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!!!] CRITICAL TARGET #%lu: %s (%s) — Legacy OS + Stale!\n",
            (unsigned long)ctx->total_found,
            dns_str[0] ? dns_str : "(no DNS)", sam_str);
    } else if (is_legacy) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] LEGACY OS #%lu: %s (%s)\n",
            (unsigned long)ctx->total_found,
            dns_str[0] ? dns_str : "(no DNS)", sam_str);
    } else if (is_stale) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[~] STALE Computer #%lu: %s (%s)\n",
            (unsigned long)ctx->total_found,
            dns_str[0] ? dns_str : "(no DNS)", sam_str);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Computer #%lu: %s (%s)%s\n",
            (unsigned long)ctx->total_found,
            dns_str[0] ? dns_str : "(no DNS)", sam_str,
            is_dc ? " [DOMAIN CONTROLLER]" : "");
    }

    phantom_print_kv("DN",  dn_str,                         4);
    phantom_print_kv("OS",  os_str[0] ? os_str : "Unknown", 4);
    if (osver[0]) phantom_print_kv("OS Ver", osver, 4);
    if (desc_str[0]) phantom_print_kv("Desc", desc_str, 4);

    if (ts_ft == 0) {
        phantom_print_kv("Last Logon", "Never (or too old)", 4);
    } else {
        char combined[128];
        char *p = combined, *e = combined + sizeof(combined) - 1;
        for (const char *s = ts_str; *s && p<e;) *p++ = *s++;
        *p++ = ' '; *p++ = '(';
        for (const char *s = ts_age; *s && p<e;) *p++ = *s++;
        if (is_stale)  { for (const char *s = " - STALE"; *s && p<e;) *p++ = *s++; }
        *p++ = ')'; *p = '\0';
        phantom_print_kv("Last Logon", combined, 4);
    }

    if (sid_str[0]) phantom_print_kv("SID", sid_str, 4);

    if (is_legacy)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] LEGACY OS: EOL/no patches — high vulnerability surface\n"
            "    [*] Recommend: EternalBlue/MS17-010, PrintNightmare, SMBGhost scan\n");

    if (is_stale && !is_dc)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [~] STALE: Machine may have weak password or reused local admin\n"
            "    [*] Try:   CrackMapExec smb %s -u administrator -p 'Welcome1'\n",
            dns_str[0] ? dns_str : sam_str);

    if (dns_vals)  api->ldap_value_free(dns_vals);
    if (sam_vals)  api->ldap_value_free(sam_vals);
    if (dn_vals)   api->ldap_value_free(dn_vals);
    if (os_vals)   api->ldap_value_free(os_vals);
    if (osver_vals) api->ldap_value_free(osver_vals);
    if (ossp_vals) api->ldap_value_free(ossp_vals);
    if (ts_vals)   api->ldap_value_free(ts_vals);
    if (uac_vals)  api->ldap_value_free(uac_vals);
    if (desc_vals) api->ldap_value_free(desc_vals);
    if (sid_vals)  api->ldap_value_free_len(sid_vals);

    return TRUE;
}

void go(char *args, int len) {
    PHANTOM_CONTEXT ctx    = {0};
    datap           parser = {0};
    WCHAR           dc_name[256] = {0};
    char           *dc_arg = NULL;
    int             dc_len  = 0;

    BeaconDataParse(&parser, args, len);
    dc_arg = BeaconDataExtract(&parser, &dc_len);
    if (dc_arg && dc_len > 0 && dc_arg[0] != '\0')
        for (int i = 0; i < dc_len && i < 255; i++)
            dc_name[i] = (WCHAR)(unsigned char)dc_arg[i];

    phantom_print_banner();
    phantom_print_header(MODULE_TITLE, MODULE_TAG);

    if (!phantom_ldap_init(&ctx, dc_name[0] ? dc_name : NULL, FALSE, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PhantomLDAP: LDAP init failed.\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Base DN: %ls | Stale threshold: %llu days\n\n",
                 ctx.base_dn, STALE_DAYS_THRESHOLD);

    phantom_ldap_paged_search(&ctx, ctx.base_dn, LDAP_SCOPE_SUBTREE,
                               FILTER_COMPUTERS, g_attrs,
                               enum_computers_callback, NULL);

    /* OS distribution summary */
    phantom_print_separator('=');
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] OS Distribution Summary:\n"
        "    Server 2022         : %lu\n"
        "    Server 2019         : %lu\n"
        "    Server 2016         : %lu\n"
        "    Server 2012/R2      : %lu\n"
        "    Server 2008/R2 [!]  : %lu\n"
        "    Windows 11          : %lu\n"
        "    Windows 10          : %lu\n"
        "    Windows 7/8 [!]     : %lu\n"
        "    XP/2003 [!!!]       : %lu\n"
        "    Linux/Other         : %lu\n"
        "    Unknown             : %lu\n"
        "\n"
        "    Domain Controllers  : %lu\n"
        "    Stale (>%llu days)  : %lu\n",
        (unsigned long)g_os.server2022,
        (unsigned long)g_os.server2019,
        (unsigned long)g_os.server2016,
        (unsigned long)g_os.server2012,
        (unsigned long)g_os.server2008,
        (unsigned long)g_os.win11,
        (unsigned long)g_os.win10,
        (unsigned long)g_os.win7_8,
        (unsigned long)g_os.winxp_2003,
        (unsigned long)g_os.linux_other,
        (unsigned long)g_os.unknown,
        (unsigned long)g_os.dc_count,
        STALE_DAYS_THRESHOLD,
        (unsigned long)g_os.stale);

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
