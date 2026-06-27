/**
 * @file enum_admins.c
 * @brief PhantomLDAP BOF — Enumerate AdminSDHolder-protected accounts.
 *
 * Searches Active Directory for all user accounts with adminCount=1, which
 * indicates the account has been (or is currently) a member of a privileged
 * group protected by AdminSDHolder. These accounts have their DACLs reset
 * by the SDProp process hourly, making them high-value targets.
 *
 * LDAP Filter: (&(objectCategory=person)(objectClass=user)(adminCount=1))
 *
 * Arguments (packed by CNA via bof_pack):
 *   [Z] dc_name - Optional DC hostname (wide string, empty = auto-discover)
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

/* =========================================================================
 * Module Tag & Attribute List
 * ========================================================================= */

#define MODULE_TAG   "ADMIN-ENUM"
#define MODULE_TITLE "AdminSDHolder Protected Account Enumeration"

static PWSTR g_attrs[] = {
    L"sAMAccountName",
    L"distinguishedName",
    L"memberOf",
    L"userAccountControl",
    L"adminCount",
    L"pwdLastSet",
    L"lastLogon",
    L"description",
    L"objectSid",
    NULL
};

/* =========================================================================
 * Per-Entry Callback
 * ========================================================================= */

/**
 * @brief Callback invoked by phantom_ldap_paged_search for each LDAP entry.
 * @return TRUE to continue iteration, FALSE to stop.
 */
static BOOL enum_admins_callback(PPHANTOM_CONTEXT ctx, PLDAPMessage entry, PVOID user_data) {
    (void)user_data;
    PPHANTOM_LDAP_API api = &ctx->api;

    PWSTR *sam_vals  = NULL;
    PWSTR *dn_vals   = NULL;
    PWSTR *uac_vals  = NULL;
    PWSTR *pwd_vals  = NULL;
    PWSTR *logon_vals = NULL;
    PWSTR *desc_vals = NULL;
    PWSTR *members   = NULL;
    PLDAP_BERVAL *sid_vals = NULL;

    char  sam_str[128]    = {0};
    char  dn_str[512]     = {0};
    char  uac_str[256]    = {0};
    char  pwd_str[48]     = {0};
    char  pwd_age[48]     = {0};
    char  logon_str[48]   = {0};
    char  logon_age[48]   = {0};
    char  sid_str[185]    = {0};
    char  desc_str[256]   = {0};

    ctx->total_found++;

    /* ── sAMAccountName ── */
    sam_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_SAM_ACCOUNT_NAME);
    if (sam_vals && sam_vals[0])
        phantom_wstr_to_str(sam_vals[0], sam_str, sizeof(sam_str));

    /* ── distinguishedName ── */
    dn_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DISTINGUISHED_NAME);
    if (dn_vals && dn_vals[0])
        phantom_wstr_to_str(dn_vals[0], dn_str, sizeof(dn_str));

    /* ── userAccountControl ── */
    DWORD uac_val = 0;
    uac_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_USER_ACCOUNT_CTRL);
    if (uac_vals && uac_vals[0]) {
        /* Parse wide decimal string to DWORD */
        PWSTR w = uac_vals[0];
        while (*w >= L'0' && *w <= L'9') {
            uac_val = uac_val * 10 + (DWORD)(*w - L'0');
            w++;
        }
        phantom_decode_uac(uac_val, uac_str, sizeof(uac_str));
    }

    /* ── pwdLastSet (FILETIME) ── */
    LONGLONG pwd_ft = 0;
    pwd_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_PWD_LAST_SET);
    if (pwd_vals && pwd_vals[0]) {
        PWSTR w = pwd_vals[0];
        while (*w >= L'0' && *w <= L'9') {
            pwd_ft = pwd_ft * 10 + (LONGLONG)(*w - L'0');
            w++;
        }
        phantom_filetime_to_str(pwd_ft, pwd_str, sizeof(pwd_str));
        phantom_filetime_to_age(pwd_ft, pwd_age, sizeof(pwd_age));
    }

    /* ── lastLogon (FILETIME) ── */
    LONGLONG logon_ft = 0;
    logon_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_LAST_LOGON);
    if (logon_vals && logon_vals[0]) {
        PWSTR w = logon_vals[0];
        while (*w >= L'0' && *w <= L'9') {
            logon_ft = logon_ft * 10 + (LONGLONG)(*w - L'0');
            w++;
        }
        phantom_filetime_to_str(logon_ft, logon_str, sizeof(logon_str));
        phantom_filetime_to_age(logon_ft, logon_age, sizeof(logon_age));
    }

    /* ── description ── */
    desc_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DESCRIPTION);
    if (desc_vals && desc_vals[0])
        phantom_wstr_to_str(desc_vals[0], desc_str, sizeof(desc_str));

    /* ── objectSid (binary) ── */
    sid_vals = api->ldap_get_values_len(ctx->ldap_handle, entry, ATTR_OBJECT_SID);
    if (sid_vals && sid_vals[0])
        phantom_sid_to_string((BYTE *)sid_vals[0]->bv_val,
                              (DWORD)sid_vals[0]->bv_len,
                              sid_str, sizeof(sid_str));

    /* ── Output header ── */
    phantom_print_separator('-');
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Account #%lu: %s\n",
        (unsigned long)ctx->total_found, sam_str);
    phantom_print_kv("DN",        dn_str,   4);
    phantom_print_kv("UAC",       uac_str,  4);

    /* Password age */
    if (pwd_ft == 0) {
        phantom_print_kv("Pwd Set", "NEVER (password not required or not set!)", 4);
    } else {
        char pwd_combined[128];
        char *p = pwd_combined, *e = pwd_combined + sizeof(pwd_combined) - 1;
        const char *src = pwd_str;
        while (*src && p < e) *p++ = *src++;
        *p++ = ' '; *p++ = '(';
        src = pwd_age;
        while (*src && p < e) *p++ = *src++;
        *p++ = ')'; *p = '\0';
        phantom_print_kv("Pwd Set",    pwd_combined,  4);
    }

    if (logon_ft == 0) {
        phantom_print_kv("Last Logon", "Never", 4);
    } else {
        char logon_combined[128];
        char *p = logon_combined, *e = logon_combined + sizeof(logon_combined) - 1;
        const char *src = logon_str;
        while (*src && p < e) *p++ = *src++;
        *p++ = ' '; *p++ = '(';
        src = logon_age;
        while (*src && p < e) *p++ = *src++;
        *p++ = ')'; *p = '\0';
        phantom_print_kv("Last Logon", logon_combined, 4);
    }

    if (desc_str[0])
        phantom_print_kv("Description", desc_str, 4);

    if (sid_str[0])
        phantom_print_kv("SID", sid_str, 4);

    /* ── memberOf ── */
    members = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_MEMBER_OF);
    if (members) {
        ULONG mem_count = api->ldap_count_values(members);
        BeaconPrintf(CALLBACK_OUTPUT, "      %-26s: (%lu group(s))\n",
                     "Member Of", (unsigned long)mem_count);
        for (ULONG i = 0; i < mem_count && i < PHANTOM_MAX_ATTR_VALUES; i++) {
            char grp[256] = {0};
            phantom_wstr_to_str(members[i], grp, sizeof(grp));
            BeaconPrintf(CALLBACK_OUTPUT, "                                  %s\n", grp);
        }
    }

    /* ── Risk Analysis ── */
    if (uac_val & UAC_TRUSTED_FOR_DELEGATION)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: UNCONSTRAINED DELEGATION — Kerberos TGTs can be captured!\n"
            "        Attack: Rubeus.exe monitor /interval:5 /nowrap (on target machine)\n");

    if (uac_val & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: CONSTRAINED DELEGATION (S4U2Proxy) — potential impersonation\n");

    if (uac_val & UAC_DONT_REQUIRE_PREAUTH)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: AS-REP ROASTABLE — no Kerberos pre-auth required!\n"
            "        Attack: GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass\n");

    if (uac_val & UAC_PASSWD_NOTREQD)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: EMPTY PASSWORD ALLOWED — account may have blank password\n");

    if (uac_val & UAC_ACCOUNTDISABLE)
        BeaconPrintf(CALLBACK_OUTPUT, "    [~] Note: Account is DISABLED\n");

    if (pwd_ft != 0) {
        /* Warn if password older than 365 days */
        unsigned long long ft_unix = (unsigned long long)(pwd_ft - 116444736000000000LL) / 10000000ULL;
        unsigned long long days_old = (1750000000ULL - ft_unix) / 86400ULL;
        if (days_old > 365)
            BeaconPrintf(CALLBACK_OUTPUT,
                "    [!] OLD PASSWORD: %lu days — high cracking probability if Kerberoastable\n",
                (unsigned long)days_old);
    }

    if (sam_vals)  api->ldap_value_free(sam_vals);
    if (dn_vals)   api->ldap_value_free(dn_vals);
    if (uac_vals)  api->ldap_value_free(uac_vals);
    if (pwd_vals)  api->ldap_value_free(pwd_vals);
    if (logon_vals) api->ldap_value_free(logon_vals);
    if (desc_vals) api->ldap_value_free(desc_vals);
    if (members)   api->ldap_value_free(members);
    if (sid_vals)  api->ldap_value_free_len(sid_vals);

    return TRUE;
}

/* =========================================================================
 * BOF Entry Point
 * ========================================================================= */

/**
 * @brief BOF entry point — called by Cobalt Strike Beacon loader.
 * @param args  Packed argument buffer from CNA bof_pack()
 * @param len   Buffer length in bytes
 */
void go(char *args, int len) {
    PHANTOM_CONTEXT ctx    = {0};
    datap           parser = {0};
    WCHAR           dc_name[256] = {0};
    char           *dc_arg = NULL;
    int             dc_len  = 0;

    /* ── Parse arguments ── */
    BeaconDataParse(&parser, args, len);
    dc_arg = BeaconDataExtract(&parser, &dc_len);

    if (dc_arg && dc_len > 0 && dc_arg[0] != '\0') {
        /* Convert narrow DC arg to wide */
        for (int i = 0; i < dc_len && i < 255; i++)
            dc_name[i] = (WCHAR)(unsigned char)dc_arg[i];
    }

    /* ── Banner ── */
    phantom_print_banner();
    phantom_print_header(MODULE_TITLE, MODULE_TAG);

    /* ── Initialize LDAP ── */
    if (!phantom_ldap_init(&ctx, dc_name[0] ? dc_name : NULL, FALSE, 0)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: LDAP initialization failed. Check connectivity and permissions.\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Filter  : %ls\n"
        "[*] Base DN : %ls\n"
        "[*] Page sz : %lu\n\n",
        FILTER_ADMIN_ACCOUNTS, ctx.base_dn,
        (unsigned long)ctx.page_size);

    /* ── Paged search ── */
    phantom_ldap_paged_search(
        &ctx,
        ctx.base_dn,
        LDAP_SCOPE_SUBTREE,
        FILTER_ADMIN_ACCOUNTS,
        g_attrs,
        enum_admins_callback,
        NULL
    );

    if (ctx.total_found == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No adminCount=1 accounts found.\n");

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
