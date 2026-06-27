/**
 * @file ldap_query.c
 * @brief PhantomLDAP BOF — Custom LDAP filter injection.
 *
 * Executes an arbitrary LDAP query with operator-supplied filter and
 * attribute list. Supports all LDAP scopes and custom base DN.
 *
 * Arguments (CNA bof_pack order):
 *   [Z] filter      - LDAP filter (wide string), e.g.: (&(objectClass=computer)(os=*Server*))
 *   [Z] attrs_csv   - Comma-separated attribute names (narrow string)
 *   [Z] dc_name     - Optional DC hostname (wide string, empty = auto)
 *   [i] scope       - Search scope: 0=BASE, 1=ONELEVEL, 2=SUBTREE (default 2)
 *   [Z] base_dn     - Optional base DN override (wide string, empty = rootDSE)
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

#define MODULE_TAG   "LDAP-QUERY"
#define MODULE_TITLE "Custom LDAP Filter Execution"

#define MAX_CUSTOM_ATTRS  32
#define MAX_ATTR_NAME_LEN 128

/* Module state passed as user_data to callback */
typedef struct {
    PWSTR *attrs;       /* Attribute list (for value fetching) */
    DWORD  attr_count;  /* Number of attributes */
} QUERY_STATE;

static BOOL ldap_query_callback(PPHANTOM_CONTEXT ctx, PLDAPMessage entry, PVOID user_data) {
    QUERY_STATE      *state = (QUERY_STATE *)user_data;
    PPHANTOM_LDAP_API api   = &ctx->api;

    ctx->total_found++;

    /* DN */
    PWSTR dn = api->ldap_get_dn(ctx->ldap_handle, entry);
    char dn_str[512] = {0};
    if (dn) {
        phantom_wstr_to_str(dn, dn_str, sizeof(dn_str));
        api->ldap_memfree(dn);
    }

    phantom_print_separator('-');
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Result #%lu:\n", (unsigned long)ctx->total_found);
    phantom_print_kv("dn", dn_str, 4);

    /* Enumerate requested attributes */
    for (DWORD ai = 0; state && ai < state->attr_count; ai++) {
        char attr_name[MAX_ATTR_NAME_LEN] = {0};
        phantom_wstr_to_str(state->attrs[ai], attr_name, sizeof(attr_name));

        /* Try string values first */
        PWSTR *str_vals = api->ldap_get_values(ctx->ldap_handle, entry, state->attrs[ai]);
        if (str_vals) {
            ULONG cnt = api->ldap_count_values(str_vals);
            for (ULONG vi = 0; vi < cnt && vi < PHANTOM_MAX_ATTR_VALUES; vi++) {
                char val[PHANTOM_MAX_ATTR_LEN] = {0};
                phantom_wstr_to_str(str_vals[vi], val, sizeof(val));
                if (vi == 0) phantom_print_kv(attr_name, val, 4);
                else         BeaconPrintf(CALLBACK_OUTPUT,
                                 "                                  %s\n", val);
            }
            api->ldap_value_free(str_vals);
            continue;
        }

        /* Fall back to binary (berval) values */
        PLDAP_BERVAL *bin_vals = api->ldap_get_values_len(ctx->ldap_handle, entry, state->attrs[ai]);
        if (bin_vals && bin_vals[0]) {
            (void)api->ldap_count_values_len(bin_vals);
            /* Special handling for known binary attributes */
            if (attr_name[0]=='o'&&attr_name[1]=='b'&&attr_name[2]=='j'&&
                attr_name[7]=='S'&&attr_name[8]=='i'&&attr_name[9]=='d') {
                /* objectSid */
                char sid_str[185] = {0};
                phantom_sid_to_string((BYTE *)bin_vals[0]->bv_val,
                                      (DWORD)bin_vals[0]->bv_len,
                                      sid_str, sizeof(sid_str));
                phantom_print_kv(attr_name, sid_str, 4);
            } else {
                /* Generic binary: print as hex (max 64 bytes) */
                char hex_buf[200] = {0};
                char *p = hex_buf, *e = hex_buf + sizeof(hex_buf) - 4;
                DWORD blen = (DWORD)bin_vals[0]->bv_len;
                if (blen > 64) blen = 64;
                for (DWORD bi = 0; bi < blen && p < e; bi++) {
                    unsigned char byte = (unsigned char)bin_vals[0]->bv_val[bi];
                    *p++ = "0123456789ABCDEF"[byte >> 4];
                    *p++ = "0123456789ABCDEF"[byte & 0xF];
                    *p++ = ' ';
                }
                if (bin_vals[0]->bv_len > 64) { *p++ = '.'; *p++ = '.'; *p++ = '.'; }
                *p = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "      %-26s: [binary %lu bytes] %s\n",
                             attr_name, (unsigned long)bin_vals[0]->bv_len, hex_buf);
            }
            api->ldap_value_free_len(bin_vals);
        }
    }

    return TRUE;
}

/**
 * @brief Parse a comma-separated narrow attribute string into a wide PWSTR array.
 * @return Number of attributes parsed, 0 on failure.
 */
static DWORD parse_attrs_csv(const char *csv, WCHAR attr_storage[][MAX_ATTR_NAME_LEN],
                              PWSTR attr_ptrs[], DWORD max_attrs) {
    if (!csv || !*csv) return 0;

    DWORD count = 0;
    const char *start = csv;

    while (*start && count < max_attrs) {
        /* Find end of this attribute name */
        const char *end = start;
        while (*end && *end != ',') end++;

        /* Copy and convert to wide */
        int i = 0;
        while (start + i < end && i < MAX_ATTR_NAME_LEN - 1) {
            char c = start[i];
            /* Skip whitespace */
            if (c != ' ' && c != '\t') {
                attr_storage[count][i] = (WCHAR)(unsigned char)c;
                i++;
            }
        }
        attr_storage[count][i] = L'\0';

        if (i > 0) {
            attr_ptrs[count] = attr_storage[count];
            count++;
        }

        if (*end == ',') end++;
        start = end;
    }

    /* Null-terminate the pointer array */
    if (count < max_attrs) attr_ptrs[count] = NULL;

    return count;
}

void go(char *args, int len) {
    PHANTOM_CONTEXT ctx    = {0};
    datap           parser = {0};

    WCHAR  filter_w[1024] = {0};
    WCHAR  dc_name[256]   = {0};
    WCHAR  base_dn_w[512] = {0};
    WCHAR  attr_storage[MAX_CUSTOM_ATTRS][MAX_ATTR_NAME_LEN];
    PWSTR  attr_ptrs[MAX_CUSTOM_ATTRS + 1] = {0};
    QUERY_STATE state = {0};

    char *filter_arg = NULL; int filter_len = 0;
    char *attrs_arg  = NULL; int attrs_len  = 0;
    char *dc_arg     = NULL; int dc_len     = 0;
    int   scope      = LDAP_SCOPE_SUBTREE;
    char *base_arg   = NULL; int base_len   = 0;

    BeaconDataParse(&parser, args, len);

    filter_arg = BeaconDataExtract(&parser, &filter_len);
    attrs_arg  = BeaconDataExtract(&parser, &attrs_len);
    dc_arg     = BeaconDataExtract(&parser, &dc_len);

    /* scope is passed as int16 */
    if (BeaconDataLength(&parser) >= 2) {
        short scope_s = BeaconDataShort(&parser);
        scope = (int)scope_s;
        if (scope < 0 || scope > 2) scope = LDAP_SCOPE_SUBTREE;
    }

    base_arg = BeaconDataExtract(&parser, &base_len);

    /* Convert filter to wide */
    if (!filter_arg || filter_len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PhantomLDAP: LDAP filter is required.\n");
        return;
    }
    for (int i = 0; i < filter_len && i < 1023; i++)
        filter_w[i] = (WCHAR)(unsigned char)filter_arg[i];

    /* Convert DC name to wide */
    if (dc_arg && dc_len > 0 && dc_arg[0] != '\0')
        for (int i = 0; i < dc_len && i < 255; i++)
            dc_name[i] = (WCHAR)(unsigned char)dc_arg[i];

    /* Convert base DN to wide */
    if (base_arg && base_len > 0 && base_arg[0] != '\0')
        for (int i = 0; i < base_len && i < 511; i++)
            base_dn_w[i] = (WCHAR)(unsigned char)base_arg[i];

    /* Parse attribute list */
    DWORD attr_count = 0;
    if (attrs_arg && attrs_len > 0 && attrs_arg[0] != '\0') {
        attr_count = parse_attrs_csv(attrs_arg, attr_storage, attr_ptrs, MAX_CUSTOM_ATTRS);
    }

    /* If no attrs specified, use a wildcard-like approach with common attrs */
    static PWSTR default_attrs[] = {
        L"sAMAccountName", L"distinguishedName", L"objectClass",
        L"description", L"whenCreated", NULL
    };
    PWSTR *attrs_to_use = (attr_count > 0) ? attr_ptrs : default_attrs;
    state.attrs      = attrs_to_use;
    state.attr_count = attr_count > 0 ? attr_count : 5;

    phantom_print_banner();
    phantom_print_header(MODULE_TITLE, MODULE_TAG);

    if (!phantom_ldap_init(&ctx, dc_name[0] ? dc_name : NULL, FALSE, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PhantomLDAP: LDAP init failed.\n");
        goto cleanup;
    }

    PWSTR search_base = (base_dn_w[0]) ? base_dn_w : ctx.base_dn;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Filter : %ls\n"
        "[*] Base   : %ls\n"
        "[*] Scope  : %s\n"
        "[*] Attrs  : %s\n\n",
        filter_w, search_base,
        scope == 0 ? "BASE" : scope == 1 ? "ONELEVEL" : "SUBTREE",
        attrs_arg && attrs_arg[0] ? attrs_arg : "(default)");

    phantom_ldap_paged_search(&ctx, search_base, (ULONG)scope,
                               filter_w, attrs_to_use,
                               ldap_query_callback, &state);

    if (ctx.total_found == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No results returned for this filter.\n");

    phantom_print_footer(&ctx);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
