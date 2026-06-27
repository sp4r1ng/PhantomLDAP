/**
 * @file enum_trusts.c
 * @brief PhantomLDAP BOF module — Active Directory Domain Trust Enumeration
 *
 * Enumerates all trustedDomain objects from CN=System,<base_dn> via paged
 * LDAP search and produces a colour-coded operator report that classifies
 * each trust by type, direction, transitivity, and SID-filtering posture.
 *
 * Attack-path notes are emitted automatically:
 *  - Missing SID filtering (TRUST_ATTR_QUARANTINED not set) → SID history
 *    escalation possible via Impacket ticketer.py / mimikatz.
 *  - Bidirectional forest-transitive trusts → highest lateral-movement risk.
 *  - Inbound trusts → remote domain principals can authenticate here.
 *
 * Usage (from Cobalt Strike CNA script):
 *   bof_pack args:
 *     z  dc_name    (optional — empty string for current domain)
 *
 * Compilation:
 *   x86_64-w64-mingw32-gcc -o enum_trusts.o -c enum_trusts.c \
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

/** Separator string width matches PHANTOM_SEPARATOR_WIDTH (72 chars). */
#define TRUST_SEPARATOR \
    "------------------------------------------------------------------------"

/** LDAP filter — retrieves all trusted domain objects. */
#define TRUST_FILTER    L"(objectClass=trustedDomain)"

/* =========================================================================
 * Internal structures
 * ========================================================================= */

/**
 * @brief Holds the decoded representation of a single trustedDomain object.
 *
 * Populated incrementally as LDAP attributes are extracted.  All string
 * fields are narrow ASCII for BeaconPrintf compatibility.
 */
typedef struct _TRUST_INFO {
    char  local_domain[256];    /**< flatName of the LOCAL side (from ctx)      */
    char  partner[256];         /**< trustPartner — the remote domain DNS name  */
    char  flat_name[64];        /**< flatName — NetBIOS name of remote domain   */
    DWORD trust_type;           /**< Raw trustType integer value                */
    DWORD trust_direction;      /**< Raw trustDirection integer value           */
    DWORD trust_attributes;     /**< Raw trustAttributes bitfield               */
    BOOL  has_type;
    BOOL  has_direction;
    BOOL  has_attributes;
} TRUST_INFO, *PTRUST_INFO;

/**
 * @brief Callback user-data structure passed through the paged search.
 */
typedef struct _TRUST_CB_DATA {
    PPHANTOM_CONTEXT  ctx;          /**< Back-pointer to the module context     */
    DWORD             trust_index;  /**< 1-based count of trusts found so far   */
} TRUST_CB_DATA, *PTRUST_CB_DATA;

/* =========================================================================
 * Internal helpers — string decoders
 * ========================================================================= */

/**
 * @brief Decode the trustType integer into a human-readable description.
 *
 * @param type      Raw trustType value from LDAP
 * @return          Static ASCII string; never NULL.
 */
static const char *trust_type_str(DWORD type)
{
    switch (type) {
    case TRUST_TYPE_DOWNLEVEL: return "Windows NT 4.0 (Downlevel)";
    case TRUST_TYPE_UPLEVEL:   return "Active Directory (Uplevel)";
    case TRUST_TYPE_MIT:       return "MIT Kerberos Realm";
    case TRUST_TYPE_DCE:       return "DCE Realm";
    default:                   return "Unknown";
    }
}

/**
 * @brief Decode the trustDirection integer into a human-readable description.
 *
 * @param dir   Raw trustDirection value from LDAP
 * @return      Static ASCII string; never NULL.
 */
static const char *trust_direction_str(DWORD dir)
{
    switch (dir) {
    case TRUST_DIRECTION_DISABLED: return "Disabled";
    case TRUST_DIRECTION_INBOUND:  return "Inbound  (Remote trusts US -- they can auth here)";
    case TRUST_DIRECTION_OUTBOUND: return "Outbound (WE trust THEM -- we can auth there)";
    case TRUST_DIRECTION_BIDIRECT: return "Bidirectional (Both domains trust each other)";
    default:                       return "Unknown";
    }
}

/**
 * @brief Append a literal token string to buf (no snprintf/strcat needed).
 *
 * @param buf       Destination character buffer (null-terminated)
 * @param buf_size  Total capacity of buf in bytes
 * @param tok       Token to append
 */
static void buf_append(char *buf, SIZE_T buf_size, const char *tok)
{
    SIZE_T cur = 0;
    while (buf[cur]) cur++;
    SIZE_T ti = 0;
    while (tok[ti] && cur + ti + 1 < buf_size) {
        buf[cur + ti] = tok[ti];
        ti++;
    }
    buf[cur + ti] = '\0';
}

/**
 * @brief Decode the trustAttributes bitfield into a pipe-separated string.
 *
 * @param attrs     Raw trustAttributes DWORD value
 * @param buf       Output buffer for the result string
 * @param buf_size  Size of buf in bytes
 */
static void trust_attributes_str(DWORD attrs, char *buf, SIZE_T buf_size)
{
    BOOL first = TRUE;
    buf[0] = '\0';

/* Helper: append flag name if bit is set, prefixed with " | " if needed. */
#define APPEND_FLAG(flag, name) \
    if ((attrs) & (flag)) { \
        if (!first) { buf_append(buf, buf_size, " | "); } \
        buf_append(buf, buf_size, (name)); \
        first = FALSE; \
    }

    APPEND_FLAG(TRUST_ATTR_NON_TRANSITIVE,    "NON_TRANSITIVE")
    APPEND_FLAG(TRUST_ATTR_UPLEVEL_ONLY,      "UPLEVEL_ONLY")
    APPEND_FLAG(TRUST_ATTR_QUARANTINED,       "SID_FILTERING_ON")
    APPEND_FLAG(TRUST_ATTR_FOREST_TRANSITIVE, "FOREST_TRANSITIVE")
    APPEND_FLAG(TRUST_ATTR_CROSS_ORG,         "CROSS_ORGANIZATION")
    APPEND_FLAG(TRUST_ATTR_WITHIN_FOREST,     "WITHIN_FOREST")
    APPEND_FLAG(TRUST_ATTR_TREAT_AS_EXTERNAL, "TREAT_AS_EXTERNAL")
    APPEND_FLAG(TRUST_ATTR_PAM_TRUST,         "PAM_TRUST")

#undef APPEND_FLAG

    if (first) {
        buf_append(buf, buf_size, "NONE");
    }
}

/* =========================================================================
 * Attribute extraction helpers
 * ========================================================================= */

/**
 * @brief Extract a single-value DWORD attribute from an LDAPMessage entry.
 *
 * Uses ldap_get_values (string) then converts via manual wide-string parse
 * to avoid any C runtime dependency on wcstoul/atoi.
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param entry     LDAP entry message pointer
 * @param attr      Wide-string attribute name
 * @param out_val   Receives the parsed DWORD on success
 * @return          TRUE if the attribute was found and parsed; FALSE otherwise
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
    if (!vals || !vals[0]) {
        goto cleanup;
    }

    /* Manual wide-string to DWORD conversion — avoids any CRT call. */
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
    if (vals) {
        ctx->api.ldap_value_free(vals);
    }
    return ok;
}

/**
 * @brief Extract a single-value wide string attribute into a narrow buffer.
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param entry     LDAP entry message pointer
 * @param attr      Wide-string attribute name
 * @param out_buf   Narrow output buffer
 * @param buf_size  Size of out_buf in bytes
 * @return          TRUE on success; FALSE if attribute not present
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
    if (!vals || !vals[0]) {
        goto cleanup;
    }

    phantom_wstr_to_str(vals[0], out_buf, buf_size);
    ok = TRUE;

cleanup:
    if (vals) {
        ctx->api.ldap_value_free(vals);
    }
    return ok;
}

/* =========================================================================
 * Output helper
 * ========================================================================= */

/**
 * @brief Print a fully-decoded trust entry to the Beacon console.
 *
 * Emits the formatted block including attack-path advisories based on the
 * decoded trust attributes.
 *
 * @param info          Decoded trust information structure (read-only)
 * @param trust_index   1-based trust ordinal for labelling
 */
static void print_trust(const TRUST_INFO *info, DWORD trust_index)
{
    char attr_buf[256];
    BOOL sid_filtered;
    BOOL is_bidi;
    BOOL is_forest;

    /* Build the attribute flag string. */
    trust_attributes_str(info->trust_attributes, attr_buf, sizeof(attr_buf));

    sid_filtered = (info->trust_attributes & TRUST_ATTR_QUARANTINED) != 0;
    is_bidi      = (info->trust_direction == TRUST_DIRECTION_BIDIRECT);
    is_forest    = (info->trust_attributes & TRUST_ATTR_FOREST_TRANSITIVE) != 0;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] Trust #%lu: %s --> %s\n"
        "    Partner  : %s\n"
        "    FlatName : %s\n"
        "    Type     : %s\n"
        "    Direction: %s\n"
        "    SIDFilter: %s\n"
        "    Attrs    : %s\n",
        (unsigned long)trust_index,
        info->local_domain[0] ? info->local_domain : "(local domain)",
        info->partner[0]      ? info->partner       : "(unknown)",
        info->partner[0]      ? info->partner       : "(unknown)",
        info->flat_name[0]    ? info->flat_name      : "(unavailable)",
        info->has_type      ? trust_type_str(info->trust_type)           : "(unknown)",
        info->has_direction ? trust_direction_str(info->trust_direction) : "(unknown)",
        sid_filtered        ? "ENABLED  (SID history attacks mitigated)"
                            : "DISABLED [!] SID History attacks POSSIBLE",
        attr_buf);

    /* ------------------------------------------------------------------- */
    /* Attack-path advisories                                               */
    /* ------------------------------------------------------------------- */

    if (!sid_filtered) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] ATTACK PATH: No SID filtering -- SID history injection possible.\n"
            "        If you can forge a TGT or compromise the inter-realm trust key,\n"
            "        inject a SID from the TARGET domain (e.g. Domain Admins) into a\n"
            "        ticket belonging to a principal in THIS domain.\n"
            "    [*] Tool: Impacket ticketer.py --extra-sid <TargetDomainAdminsSID>\n"
            "              mimikatz: kerberos::golden /extra-sid:<SID> /domain:... /sid:...\n");
    }

    if (is_bidi) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: Bidirectional trust -- highest lateral-movement risk.\n"
            "        Compromise of either forest is a direct threat to the other.\n");
    }

    if (is_forest) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] NOTE: Forest-transitive trust -- scope spans the ENTIRE forest.\n"
            "        All child domains in both forests inherit this trust relationship.\n");
    }

    if (info->trust_direction == TRUST_DIRECTION_INBOUND && !sid_filtered) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] RISK: Inbound trust without SID filtering -- remote principals\n"
            "        can authenticate HERE and may escalate via SID history injection.\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", TRUST_SEPARATOR);
}

/* =========================================================================
 * Paged-search callback
 * ========================================================================= */

/**
 * @brief Paged-search callback invoked once per LDAPMessage result page.
 *
 * Iterates all entries in the page, extracts trust attributes, and
 * calls print_trust() for each decoded object.
 *
 * @param ctx       Active PHANTOM_CONTEXT (provided by the paged search engine)
 * @param message   Pointer to the page's LDAPMessage chain
 * @param user_data Pointer to TRUST_CB_DATA (cast from PVOID)
 * @return          TRUE to continue iteration; FALSE to abort early
 */
static BOOL trust_callback(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     message,
    PVOID            user_data)
{
    PTRUST_CB_DATA cb    = (PTRUST_CB_DATA)user_data;
    PLDAPMessage   entry = NULL;

    if (!message || !cb) {
        return FALSE;
    }

    entry = ctx->api.ldap_first_entry(ctx->ldap_handle, message);

    while (entry) {
        TRUST_INFO info;

        /* Zero-init the info block without memset (no libc). */
        {
            PBYTE  p = (PBYTE)&info;
            SIZE_T s = sizeof(info);
            while (s--) { *p++ = 0; }
        }

        extract_str_attr(ctx, entry, ATTR_TRUST_PARTNER,
                         info.partner, sizeof(info.partner));

        extract_str_attr(ctx, entry, ATTR_FLAT_NAME,
                         info.flat_name, sizeof(info.flat_name));

        /* Use the base_dn as a stand-in for the local domain. */
        phantom_wstr_to_str(ctx->base_dn, info.local_domain,
                            sizeof(info.local_domain));

        info.has_type =
            extract_dword_attr(ctx, entry, ATTR_TRUST_TYPE,
                               &info.trust_type);

        info.has_direction =
            extract_dword_attr(ctx, entry, ATTR_TRUST_DIRECTION,
                               &info.trust_direction);

        info.has_attributes =
            extract_dword_attr(ctx, entry, ATTR_TRUST_ATTRIBUTES,
                               &info.trust_attributes);

        cb->trust_index++;
        print_trust(&info, cb->trust_index);

        entry = ctx->api.ldap_next_entry(ctx->ldap_handle, entry);
    }

    return TRUE; /* Continue to next page. */
}

/* =========================================================================
 * BOF entry point
 * ========================================================================= */

/**
 * @brief BOF entry point for the trust enumeration module.
 *
 * Argument buffer (packed by CNA bof_pack):
 *   [z]  dc_name   — Target DC hostname. Empty string means auto-discover.
 *
 * Execution flow:
 *   1. Parse arguments from the BOF argument buffer.
 *   2. Call phantom_ldap_init() to establish an authenticated LDAP session.
 *   3. Construct CN=System,<base_dn> as the search base.
 *   4. Execute a paged search for (objectClass=trustedDomain) objects.
 *   5. For each result page, trust_callback() decodes and prints each trust.
 *   6. Print a summary footer and call phantom_ldap_cleanup().
 *
 * @param args  Raw BOF argument buffer supplied by the Beacon loader
 * @param alen  Length of args in bytes
 */
void go(char *args, int alen)
{
    datap          parser;
    char          *dc_name_a  = NULL;
    int            dc_name_sz = 0;
    PHANTOM_CONTEXT ctx;
    TRUST_CB_DATA  cb_data;
    WCHAR          search_base[768];
    DWORD          rc = 0;
    BOOL           ok = FALSE;

    /* Attribute list for the trust search — NULL-terminated. */
    PWSTR attrs[] = {
        ATTR_TRUST_PARTNER,
        ATTR_TRUST_TYPE,
        ATTR_TRUST_DIRECTION,
        ATTR_TRUST_ATTRIBUTES,
        ATTR_FLAT_NAME,
        NULL
    };

    /* ------------------------------------------------------------------ */
    /* Zero-init stack structures (no memset/ZeroMemory available).        */
    /* ------------------------------------------------------------------ */
    {
        PBYTE p  = (PBYTE)&ctx;
        SIZE_T s = sizeof(ctx);
        while (s--) { *p++ = 0; }
    }
    {
        PBYTE p  = (PBYTE)&cb_data;
        SIZE_T s = sizeof(cb_data);
        while (s--) { *p++ = 0; }
    }
    {
        PBYTE p  = (PBYTE)search_base;
        SIZE_T s = sizeof(search_base);
        while (s--) { *p++ = 0; }
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
        "\n[*] PhantomLDAP :: Trust Enumeration v" PHANTOM_VERSION_STR "\n"
        "    DC target : %s\n"
        "    %s\n",
        (dc_name_a && dc_name_a[0]) ? dc_name_a : "(auto-discover via DNS)",
        TRUST_SEPARATOR);

    /* ------------------------------------------------------------------ */
    /* 3. LDAP initialisation.                                              */
    /* ------------------------------------------------------------------ */
    {
        WCHAR dc_wide[256];
        {
            PBYTE p  = (PBYTE)dc_wide;
            SIZE_T s = sizeof(dc_wide);
            while (s--) { *p++ = 0; }
        }
        if (dc_name_a && dc_name_a[0]) {
            phantom_str_to_wstr(dc_name_a, dc_wide, 256);
        }

        ok = phantom_ldap_init(
            &ctx,
            (dc_name_a && dc_name_a[0]) ? dc_wide : NULL,
            FALSE,  /* No LDAPS — use port 389 */
            0       /* Default page size (PHANTOM_DEFAULT_PAGE_SIZE) */
        );
    }

    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_trusts: phantom_ldap_init failed. "
            "Verify DC reachability and Kerberos ticket validity.\n");
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Build search base: CN=System,<base_dn>                            */
    /* ------------------------------------------------------------------ */
    {
        const WCHAR prefix[] = L"CN=System,";
        SIZE_T pi = 0;
        SIZE_T bi = 0;
        /* Append prefix. */
        while (prefix[pi] && pi < 767) {
            search_base[pi] = prefix[pi];
            pi++;
        }
        /* Append base_dn. */
        while (ctx.base_dn[bi] && (pi + bi) < 767) {
            search_base[pi + bi] = ctx.base_dn[bi];
            bi++;
        }
        search_base[pi + bi] = L'\0';
    }

    /* ------------------------------------------------------------------ */
    /* 5. Execute paged search.                                             */
    /* ------------------------------------------------------------------ */
    cb_data.ctx         = &ctx;
    cb_data.trust_index = 0;

    rc = phantom_ldap_paged_search(
        &ctx,
        search_base,
        LDAP_SCOPE_ONELEVEL,    /* One level under CN=System */
        TRUST_FILTER,
        attrs,
        trust_callback,
        &cb_data
    );

    /* ------------------------------------------------------------------ */
    /* 6. Footer.                                                           */
    /* ------------------------------------------------------------------ */
    if (rc != LDAP_SUCCESS && rc != LDAP_NO_RESULTS_RETURNED) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_trusts: search returned LDAP error 0x%02lX.\n",
            (unsigned long)rc);
    }

    if (cb_data.trust_index == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] No trust objects found. The domain may have no external trusts,\n"
            "    or the search base CN=System may not exist / is inaccessible.\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Trust enumeration complete.\n"
        "    Total trusts : %lu\n"
        "    LDAP pages   : %lu\n"
        "    %s\n\n",
        (unsigned long)cb_data.trust_index,
        (unsigned long)ctx.page_count,
        TRUST_SEPARATOR);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
