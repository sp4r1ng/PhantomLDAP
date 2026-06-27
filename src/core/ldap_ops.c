/**
 * @file ldap_ops.c
 * @brief Core LDAP operations engine for the PhantomLDAP BOF suite.
 *
 * This translation unit implements:
 *   - phantom_ldap_init()            — Session bootstrap (resolve API, bind, rootDSE)
 *   - phantom_ldap_cleanup()         — Graceful unbind and context zeroing
 *   - phantom_ldap_paged_search()    — RFC 2696 paged search loop (all modules call this)
 *   - phantom_sid_to_string()        — Binary SID -> "S-1-5-21-..." formatter
 *   - phantom_guid_to_string()       — 16-byte GUID -> "{XXXXXXXX-...}" formatter
 *   - phantom_filetime_to_str()      — FILETIME -> "YYYY-MM-DD HH:MM:SS UTC" (no CRT)
 *   - phantom_filetime_to_age()      — FILETIME -> "X days ago" (no CRT)
 *   - phantom_wstr_to_str()          — Wide -> narrow ASCII cast loop
 *   - phantom_str_to_wstr()          — Narrow -> wide ASCII cast loop
 *   - phantom_lookup_extended_right()— GUID -> well-known AD right name table
 *   - phantom_decode_uac()           — userAccountControl bitmask -> text flags
 *   - phantom_decode_access_mask()   — AD ACCESS_MASK -> text flags
 *
 * ## Design Decisions
 *
 * ### No CRT
 * All string manipulation, memory operations and formatting are implemented
 * inline using manual loops. No sprintf(), strlen(), memset(), memcpy() or
 * any other CRT function is called directly. The BOF environment provides no
 * guaranteed CRT linkage, and static-linking the CRT would bloat the object
 * file and introduce unwanted imports.
 *
 * ### Paged Search Engine
 * LDAP servers enforce a server-side result size limit (typically 1000 objects
 * by default on AD). The paged search engine (RFC 2696) uses the
 * LDAP_PAGED_RESULT_OID_STRING server control to retrieve all objects across
 * multiple network round-trips, reassembling them for the caller's callback.
 * The cookie mechanism allows the server to maintain cursor state between pages.
 *
 * ### GetSystemTimeAsFileTime Resolution
 * phantom_filetime_to_age() needs the current system time. Rather than
 * importing kernel32 statically, we resolve GetSystemTimeAsFileTime at
 * runtime via phantom_resolve() using the pre-computed DJB2 hash.
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

/* =========================================================================
 * Forward declarations of static helpers
 * ========================================================================= */

static void     phantom_memzero(void *ptr, SIZE_T len);
static int      phantom_memcmp(const void *a, const void *b, SIZE_T len);
static void     phantom_buf_append_str(char *buf, SIZE_T buf_size, SIZE_T *pos, const char *src);
static void     phantom_append_flag(char *buf, SIZE_T buf_size, SIZE_T *pos, BOOL *first, const char *name);
static void     phantom_buf_append_u64(char *buf, SIZE_T buf_size, SIZE_T *pos, ULONGLONG value);
static void     phantom_buf_append_u32(char *buf, SIZE_T buf_size, SIZE_T *pos, ULONG value);
static void     phantom_buf_append_hex_byte(char *buf, SIZE_T buf_size, SIZE_T *pos, BYTE b);
static void     phantom_buf_append_hex32(char *buf, SIZE_T buf_size, SIZE_T *pos, DWORD v);
static void     phantom_buf_append_hex16(char *buf, SIZE_T buf_size, SIZE_T *pos, WORD v);
static void     phantom_buf_append_ch(char *buf, SIZE_T buf_size, SIZE_T *pos, char c);
static LONGLONG phantom_filetime_diff_days(LONGLONG a, LONGLONG b);
static void     phantom_wcsncpy(WCHAR *dst, const WCHAR *src, SIZE_T dst_len);

/* =========================================================================
 * Type alias for GetSystemTimeAsFileTime (dynamically resolved)
 * ========================================================================= */

/** GetSystemTimeAsFileTime — dynamically resolved from kernel32.dll */
typedef void (WINAPI *fn_GetSystemTimeAsFileTime_t)(FILETIME *lpSystemTimeAsFileTime);

/** Pre-computed DJB2 hash for "GetSystemTimeAsFileTime" (case-sensitive) */
#define PHANTOM_HASH_GetSystemTimeAsFileTime   0xC8AC8026UL

/* =========================================================================
 * Static Helper Implementations
 * ========================================================================= */

/**
 * @brief Zero a memory region via a volatile pointer.
 *
 * The volatile cast prevents the compiler from treating the writes as dead
 * code and eliminating them during optimisation — critical when wiping
 * sensitive context data (credentials, tokens) before returning.
 *
 * @param ptr   Start of region to zero
 * @param len   Number of bytes to zero
 */
static void phantom_memzero(void *ptr, SIZE_T len)
{
    volatile BYTE *p = (volatile BYTE *)ptr;
    SIZE_T i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

/**
 * @brief Compare two memory regions byte-by-byte.
 *
 * @param a   First buffer
 * @param b   Second buffer
 * @param len Number of bytes to compare
 * @return    0 if equal; negative if *a < *b at first difference; positive otherwise
 */
static int phantom_memcmp(const void *a, const void *b, SIZE_T len)
{
    const BYTE *pa = (const BYTE *)a;
    const BYTE *pb = (const BYTE *)b;
    SIZE_T i;
    for (i = 0; i < len; i++) {
        if (pa[i] != pb[i]) {
            return (int)pa[i] - (int)pb[i];
        }
    }
    return 0;
}

/**
 * @brief Append a single character into buf at position *pos.
 *
 * Ensures there is always a NUL terminator by refusing to write past
 * (buf_size - 1). The caller must ensure buf[0] = '\0' initially.
 *
 * @param buf       Destination buffer (NUL-terminated)
 * @param buf_size  Total buffer capacity in bytes
 * @param pos       Current write offset (updated in-place)
 * @param c         Character to append
 */
static void phantom_buf_append_ch(char *buf, SIZE_T buf_size,
                                  SIZE_T *pos, char c)
{
    if (*pos + 1 < buf_size) {
        buf[(*pos)++] = c;
        buf[*pos] = '\0';
    }
}

/**
 * @brief Append a NUL-terminated ASCII string to buf at position *pos.
 *
 * Silently truncates if the destination buffer is full.
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param src       Source string to append (may be NULL — no-op)
 */
static void phantom_buf_append_str(char *buf, SIZE_T buf_size,
                                   SIZE_T *pos, const char *src)
{
    SIZE_T i;
    if (!src) return;
    for (i = 0; src[i] != '\0'; i++) {
        if (*pos + 1 >= buf_size) break;
        buf[(*pos)++] = src[i];
    }
    buf[*pos] = '\0';
}

/**
 * @brief Format an unsigned 64-bit value as decimal digits into buf.
 *
 * Uses a temporary reverse buffer to avoid needing to know digit count
 * in advance, then writes digits forward into the output buffer.
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param value     Value to format
 */
static void phantom_buf_append_u64(char *buf, SIZE_T buf_size,
                                   SIZE_T *pos, ULONGLONG value)
{
    char tmp[21]; /* max 20 decimal digits for UINT64_MAX, plus NUL */
    int  tlen = 0;
    int  i;

    if (value == 0) {
        phantom_buf_append_ch(buf, buf_size, pos, '0');
        return;
    }
    while (value > 0 && tlen < 20) {
        tmp[tlen++] = (char)('0' + (int)(value % 10));
        value /= 10;
    }
    /* Digits were accumulated in reverse; write them forward */
    for (i = tlen - 1; i >= 0; i--) {
        phantom_buf_append_ch(buf, buf_size, pos, tmp[i]);
    }
}

/**
 * @brief Format an unsigned 32-bit value as decimal digits into buf.
 */
static void phantom_buf_append_u32(char *buf, SIZE_T buf_size,
                                   SIZE_T *pos, ULONG value)
{
    phantom_buf_append_u64(buf, buf_size, pos, (ULONGLONG)value);
}

/**
 * @brief Format a single byte as two uppercase hex characters (e.g., 0x0F -> "0F").
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param b         Byte value to format
 */
static void phantom_buf_append_hex_byte(char *buf, SIZE_T buf_size,
                                        SIZE_T *pos, BYTE b)
{
    static const char hex[] = "0123456789ABCDEF";
    phantom_buf_append_ch(buf, buf_size, pos, hex[(b >> 4) & 0xF]);
    phantom_buf_append_ch(buf, buf_size, pos, hex[b & 0xF]);
}

/**
 * @brief Format a DWORD as exactly 8 uppercase hex digits (big-endian digit order).
 *
 * e.g., 0x0000002A -> "0000002A"
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param v         DWORD value to format
 */
static void phantom_buf_append_hex32(char *buf, SIZE_T buf_size,
                                     SIZE_T *pos, DWORD v)
{
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)((v >> 24) & 0xFF));
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)((v >> 16) & 0xFF));
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)((v >>  8) & 0xFF));
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)(v         & 0xFF));
}

/**
 * @brief Format a WORD as exactly 4 uppercase hex digits.
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param v         WORD value to format
 */
static void phantom_buf_append_hex16(char *buf, SIZE_T buf_size,
                                     SIZE_T *pos, WORD v)
{
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)((v >> 8) & 0xFF));
    phantom_buf_append_hex_byte(buf, buf_size, pos, (BYTE)(v        & 0xFF));
}

/**
 * @brief Append a flag name to a comma-separated list, managing the comma.
 *
 * On the first call (when *first == TRUE) the name is appended directly.
 * On subsequent calls, ", " is prepended before the name. The first flag
 * is set to FALSE after the first successful append.
 *
 * @param buf       Destination buffer
 * @param buf_size  Total buffer capacity
 * @param pos       Current write offset (updated in-place)
 * @param first     Caller-maintained boolean; TRUE on first call, then FALSE
 * @param name      Flag name to append
 */
static void phantom_append_flag(char *buf, SIZE_T buf_size, SIZE_T *pos,
                                BOOL *first, const char *name)
{
    if (!*first) {
        phantom_buf_append_str(buf, buf_size, pos, ", ");
    }
    phantom_buf_append_str(buf, buf_size, pos, name);
    *first = FALSE;
}

/**
 * @brief Compute the signed difference in whole days between two FILETIME values.
 *
 * Both values are 100-nanosecond intervals. One day = 864000000000 ticks.
 *
 * @param a   Earlier FILETIME (subtracted from b)
 * @param b   Later FILETIME
 * @return    (b - a) / ticks_per_day; negative if b < a
 */
static LONGLONG phantom_filetime_diff_days(LONGLONG a, LONGLONG b)
{
    LONGLONG diff          = b - a;
    LONGLONG ticks_per_day = (LONGLONG)10000000 * (LONGLONG)86400;
    if (diff < 0) {
        return -( (-diff) / ticks_per_day );
    }
    return diff / ticks_per_day;
}



/**
 * @brief Copy at most (dst_len - 1) WCHARs from src into dst, always NUL-terminate.
 *
 * @param dst      Destination wide buffer
 * @param src      Source wide string (may be NULL — writes empty string)
 * @param dst_len  Destination capacity in WCHARs (including NUL)
 */
static void phantom_wcsncpy(WCHAR *dst, const WCHAR *src, SIZE_T dst_len)
{
    SIZE_T i;
    if (!dst || dst_len == 0) return;
    for (i = 0; i < dst_len - 1 && src && src[i] != L'\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = L'\0';
}

/* =========================================================================
 * phantom_ldap_init
 * ========================================================================= */

/**
 * @brief Initialize a PHANTOM_CONTEXT for LDAP operations.
 *
 * Performs the complete session bootstrap:
 *
 *  1. Resolves all wldap32.dll function pointers via PEB walker (no IAT entries).
 *  2. Configures operational parameters (page_size, port, SSL flag).
 *  3. Calls ldap_init() to allocate the LDAP session handle.
 *  4. Sets LDAPv3 protocol version, disables referral chasing.
 *  5. Enables LDAP signing (LDAP_OPT_SIGN) and sealing (LDAP_OPT_ENCRYPT)
 *     for channel binding protection against LDAP relay attacks.
 *  6. Performs Negotiate bind (Kerberos preferred, NTLM fallback) via SSPI.
 *  7. Queries the rootDSE (base="", scope=BASE) to populate:
 *       - ctx->base_dn  <- defaultNamingContext
 *       - ctx->dc_name  <- dnsHostName (only if dc_name param was NULL)
 *  8. Prints a connection banner.
 *
 * On any failure, all allocated LDAP resources are freed and ctx->ldap_handle
 * is set to NULL. The caller should still call phantom_ldap_cleanup() to zero
 * the context.
 *
 * @param ctx       Zeroed PHANTOM_CONTEXT (stack-allocated in go())
 * @param dc_name   DC FQDN in wide chars, or NULL for auto-discovery
 * @param use_ssl   TRUE to connect on LDAPS port 636
 * @param page_size Objects per paginated page (0 => PHANTOM_DEFAULT_PAGE_SIZE)
 * @return          TRUE on success, FALSE on any failure
 */
BOOL phantom_ldap_init(PPHANTOM_CONTEXT ctx, const WCHAR *dc_name,
                       BOOL use_ssl, DWORD page_size)
{
    ULONG          rc              = LDAP_SUCCESS;
    ULONG          ldap_version    = LDAP_VERSION3;
    ULONG          sign_val        = 1;
    ULONG          encrypt_val     = 1;
    PLDAPMessage   rootdse_result  = NULL;
    PLDAPMessage   rootdse_entry   = NULL;
    PWSTR         *dn_vals         = NULL;
    PWSTR         *host_vals       = NULL;
    BOOL           success         = FALSE;

    /* rootDSE attribute request list — null-terminated */
    PWSTR rootdse_attrs[3];
    rootdse_attrs[0] = L"defaultNamingContext";
    rootdse_attrs[1] = L"dnsHostName";
    rootdse_attrs[2] = NULL;

    /* Timeout for the rootDSE search */
    LDAP_TIMEVAL tv;
    tv.tv_sec  = (LONG)PHANTOM_SEARCH_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (!ctx) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: phantom_ldap_init() called with NULL context\n");
        return FALSE;
    }

    /* ------------------------------------------------------------------
     * Step 1: Resolve all wldap32.dll function pointers via PEB walker.
     * This populates ctx->api entirely from wldap32's export table without
     * creating any static IAT entries in our object file.
     * ------------------------------------------------------------------ */
    if (!phantom_resolve_ldap_api(&ctx->api)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: Failed to resolve wldap32.dll exports.\n"
            "[!]   Ensure the beacon process is domain-joined or wldap32.dll is loaded.\n");
        return FALSE;
    }

    /* ------------------------------------------------------------------
     * Step 2: Operational parameters.
     * ------------------------------------------------------------------ */
    ctx->page_size      = page_size ? page_size : PHANTOM_DEFAULT_PAGE_SIZE;
    ctx->use_ssl        = use_ssl;
    ctx->ldap_port      = use_ssl ? (ULONG)LDAP_SSL_PORT : (ULONG)LDAP_PORT;
    ctx->search_timeout = PHANTOM_SEARCH_TIMEOUT_SEC;

    /* ------------------------------------------------------------------
     * Step 3: Create the LDAP session handle.
     *
     * When dc_name == NULL, wldap32 uses the host's DNS domain suffix and
     * the _ldap._tcp SRV record to locate the closest DC automatically.
     * ------------------------------------------------------------------ */
    ctx->ldap_handle = ctx->api.ldap_init((PWSTR)dc_name, ctx->ldap_port);
    if (!ctx->ldap_handle) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: ldap_init() returned NULL.\n"
            "[!]   Check DC connectivity on port %lu.\n", ctx->ldap_port);
        goto cleanup;
    }

    /* ------------------------------------------------------------------
     * Step 4: Session options.
     * ------------------------------------------------------------------ */

    /* LDAPv3 is required for extended controls (paging, SD flags, etc.) */
    rc = ctx->api.ldap_set_option(ctx->ldap_handle, LDAP_OPT_VERSION, &ldap_version);
    PHANTOM_LDAP_CHECK(rc, "ldap_set_option(LDAP_OPT_VERSION=3)", cleanup);

    /* Disable referral chasing to avoid unexpected cross-domain traffic */
    rc = ctx->api.ldap_set_option(ctx->ldap_handle, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    PHANTOM_LDAP_CHECK(rc, "ldap_set_option(LDAP_OPT_REFERRALS=OFF)", cleanup);

    /* Enable LDAP signing — protects against LDAP relay (e.g., Responder -> LDAP) */
    rc = ctx->api.ldap_set_option(ctx->ldap_handle, LDAP_OPT_SIGN, &sign_val);
    if (rc != LDAP_SUCCESS) {
        /* Non-fatal: some non-AD LDAP servers do not support signing */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP: Warning — LDAP_OPT_SIGN unsupported (rc=0x%02lX). "
            "Channel may be unprotected.\n", rc);
    }

    /* Enable LDAP sealing (encryption of PDUs) */
    rc = ctx->api.ldap_set_option(ctx->ldap_handle, LDAP_OPT_ENCRYPT, &encrypt_val);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP: Warning — LDAP_OPT_ENCRYPT unsupported (rc=0x%02lX).\n", rc);
    }

    /* ------------------------------------------------------------------
     * Step 5: Authenticate via SSPI Negotiate (Kerberos/NTLM).
     *
     * Passing NULL for both dn and cred causes wldap32 to use the current
     * thread security context — honours BeaconUseToken() impersonation.
     * ------------------------------------------------------------------ */
    rc = ctx->api.ldap_bind_s(ctx->ldap_handle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    PHANTOM_LDAP_CHECK(rc, "ldap_bind_s(LDAP_AUTH_NEGOTIATE)", cleanup);

    /* ------------------------------------------------------------------
     * Step 6: rootDSE query.
     * ------------------------------------------------------------------ */
    rc = ctx->api.ldap_search_ext_s(
        ctx->ldap_handle,
        L"",                /* base = "" => rootDSE           */
        LDAP_SCOPE_BASE,    /* scope = base object only        */
        L"(objectClass=*)", /* filter matches everything       */
        rootdse_attrs,      /* attribute list                  */
        0,                  /* attrsonly = FALSE               */
        NULL,               /* server controls (none)          */
        NULL,               /* client controls (none)          */
        &tv,                /* timeout                         */
        0,                  /* sizelimit (0 = no limit)        */
        &rootdse_result
    );
    PHANTOM_LDAP_CHECK(rc, "ldap_search_ext_s(rootDSE)", cleanup);

    rootdse_entry = ctx->api.ldap_first_entry(ctx->ldap_handle, rootdse_result);
    if (!rootdse_entry) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: rootDSE returned no entries — is the target an AD DC?\n");
        goto cleanup;
    }

    /* Extract defaultNamingContext -> ctx->base_dn */
    dn_vals = ctx->api.ldap_get_values(ctx->ldap_handle, rootdse_entry,
                                        L"defaultNamingContext");
    if (!dn_vals || !dn_vals[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: rootDSE missing defaultNamingContext.\n");
        goto cleanup;
    }
    phantom_wcsncpy(ctx->base_dn, dn_vals[0],
                    sizeof(ctx->base_dn) / sizeof(WCHAR));

    /* Extract dnsHostName -> ctx->dc_name (when caller did not supply one) */
    host_vals = ctx->api.ldap_get_values(ctx->ldap_handle, rootdse_entry,
                                          L"dnsHostName");
    if (dc_name == NULL) {
        if (host_vals && host_vals[0]) {
            phantom_wcsncpy(ctx->dc_name, host_vals[0],
                            sizeof(ctx->dc_name) / sizeof(WCHAR));
        } else {
            phantom_wcsncpy(ctx->dc_name, L"(unknown-dc)",
                            sizeof(ctx->dc_name) / sizeof(WCHAR));
        }
    } else {
        phantom_wcsncpy(ctx->dc_name, dc_name,
                        sizeof(ctx->dc_name) / sizeof(WCHAR));
    }

    /* ------------------------------------------------------------------
     * Step 7: Mark connected and print banner.
     * ------------------------------------------------------------------ */
    ctx->connected = TRUE;

    {
        char dc_str[256]   = {0};
        char base_str[512] = {0};
        phantom_wstr_to_str(ctx->dc_name, dc_str,   sizeof(dc_str));
        phantom_wstr_to_str(ctx->base_dn, base_str,  sizeof(base_str));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PhantomLDAP v" PHANTOM_VERSION_STR
            " | Connected to: %s | Base DN: %s | Port: %lu | SSL: %s\n",
            dc_str, base_str, ctx->ldap_port,
            use_ssl ? "YES" : "NO");
    }

    success = TRUE;

cleanup:
    if (dn_vals)        ctx->api.ldap_value_free(dn_vals);
    if (host_vals)      ctx->api.ldap_value_free(host_vals);
    if (rootdse_result) ctx->api.ldap_msgfree(rootdse_result);

    if (!success && ctx->ldap_handle) {
        ctx->api.ldap_unbind(ctx->ldap_handle);
        ctx->ldap_handle = NULL;
    }

    return success;
}

/* =========================================================================
 * phantom_ldap_cleanup
 * ========================================================================= */

/**
 * @brief Release all resources held by a PHANTOM_CONTEXT and zero it.
 *
 * Safe to call at any point, including on a partially-initialized context.
 * The volatile-barrier memzero ensures that the compiler does not optimise
 * away the zero-fill of the context's sensitive fields (e.g., LDAP handle,
 * dc_name, base_dn) even when the compiler detects they are "dead" after
 * the call returns.
 *
 * @param ctx   Context to clean up; may be partially initialized or zeroed
 */
void phantom_ldap_cleanup(PPHANTOM_CONTEXT ctx)
{
    if (!ctx) return;

    if (ctx->ldap_handle && ctx->connected && ctx->api.ldap_unbind) {
        ctx->api.ldap_unbind(ctx->ldap_handle);
    }

    /* Volatile zero wipes all fields including ldap_handle, dc_name, base_dn */
    phantom_memzero(ctx, sizeof(PHANTOM_CONTEXT));
}

/* =========================================================================
 * phantom_ldap_paged_search — RFC 2696 Paged Search Engine
 * ========================================================================= */

/**
 * @brief Execute a paged LDAP search and invoke a callback for every entry.
 *
 * This is the single search engine used by every enumeration module.
 * It implements the LDAP Simple Paged Results control (RFC 2696 /
 * OID 1.2.840.113556.1.4.319), transparently fetching multiple pages of
 * up to ctx->page_size entries each until the server signals completion via
 * an empty cookie.
 *
 * ### Protocol Detail
 *
 * The paging state machine uses a BER-encoded cookie that the server uses
 * to track cursor position between requests:
 *
 *   Request 1:  ldap_create_page_control(cookie={bv_len=0})
 *   Response 1: result + server control (cookie = <opaque bytes>)
 *   Request 2:  ldap_create_page_control(cookie = <from response 1>)
 *   Response 2: result + server control (cookie = <opaque bytes or empty>)
 *   ...
 *   When cookie.bv_len == 0 in response: no more pages.
 *
 * ### Callback Contract
 * - Called once per search result entry.
 * - The PLDAPMessage entry pointer is only valid during the callback.
 * - Return FALSE to abort enumeration (remaining entries on this page and
 *   subsequent pages are not processed).
 * - Return TRUE to continue.
 *
 * ### Error Handling
 * - LDAP_SIZELIMIT_EXCEEDED on the last page is non-fatal (common with AD).
 * - ldap_parse_result / ldap_parse_page_control failures are fatal and break
 *   the loop after incrementing ctx->error_count.
 * - ldap_controls_free is called in every code path to prevent leaks.
 *
 * @param ctx       Connected, initialized PHANTOM_CONTEXT
 * @param base      Search base DN (NULL => ctx->base_dn)
 * @param scope     LDAP_SCOPE_BASE / LDAP_SCOPE_ONELEVEL / LDAP_SCOPE_SUBTREE
 * @param filter    LDAP search filter string
 * @param attrs     NULL-terminated attribute list (NULL => all attributes)
 * @param callback  Per-entry callback (must not be NULL)
 * @param user_data Opaque value passed unchanged to each callback invocation
 * @return          Total number of entries passed to the callback
 */
DWORD phantom_ldap_paged_search(
    PPHANTOM_CONTEXT ctx,
    PWSTR            base,
    ULONG            scope,
    PWSTR            filter,
    PWSTR           *attrs,
    BOOL           (*callback)(PPHANTOM_CONTEXT, PLDAPMessage, PVOID),
    PVOID            user_data)
{
    PLDAPControl    page_ctrl      = NULL;
    PLDAPControl    srv_ctrls[2];            /* [page_ctrl, NULL] */
    PLDAPControl   *ret_ctrls      = NULL;
    PLDAPMessage    result         = NULL;
    PLDAPMessage    entry          = NULL;
    PLDAP_BERVAL    cookie         = NULL;
    LDAP_BERVAL     empty_cookie;
    ULONG           srv_total      = 0;      /* Server's total estimate (informational) */
    ULONG           rc             = LDAP_SUCCESS;
    DWORD           total          = 0;
    BOOL            done           = FALSE;
    BOOL            abort_early    = FALSE;
    PWSTR           effective_base;

    LDAP_TIMEVAL tv;
    tv.tv_sec  = (LONG)ctx->search_timeout;
    tv.tv_usec = 0;

    /* Validate prerequisites */
    if (!ctx || !ctx->connected || !ctx->ldap_handle) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: paged_search on disconnected context\n");
        return 0;
    }
    if (!filter) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: paged_search called with NULL filter\n");
        return 0;
    }
    if (!callback) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: paged_search called with NULL callback\n");
        return 0;
    }

    effective_base = base ? base : ctx->base_dn;

    /* Empty cookie signals start-of-enumeration to the server */
    empty_cookie.bv_len = 0;
    empty_cookie.bv_val = NULL;

    /* Create the initial paging control */
    rc = ctx->api.ldap_create_page_control(
        ctx->ldap_handle,
        ctx->page_size,
        &empty_cookie,
        (UCHAR)1,   /* isCritical = TRUE */
        &page_ctrl
    );
    if (rc != LDAP_SUCCESS || !page_ctrl) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] PhantomLDAP: ldap_create_page_control (initial) failed (rc=0x%02lX)\n", rc);
        return 0;
    }

    /* ------------------------------------------------------------------ *
     * Main paging loop                                                     *
     * ------------------------------------------------------------------ */
    while (!done) {

        srv_ctrls[0] = page_ctrl;
        srv_ctrls[1] = NULL;

        /* Issue the search for this page */
        rc = ctx->api.ldap_search_ext_s(
            ctx->ldap_handle,
            effective_base,
            scope,
            filter,
            attrs,
            0,          /* attrsonly = FALSE */
            srv_ctrls,  /* server controls: paging */
            NULL,       /* client controls: none   */
            &tv,
            0,          /* sizelimit = 0 (honour page_size from control) */
            &result
        );

        /*
         * AD may return LDAP_SIZELIMIT_EXCEEDED on the final page when the
         * total count is not a multiple of page_size. The partial result is
         * still valid and must be processed. Any other error is fatal.
         */
        if (rc != LDAP_SUCCESS && rc != (ULONG)LDAP_SIZELIMIT_EXCEEDED) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: ldap_search_ext_s failed (rc=0x%02lX) "
                "filter=%S base=%S\n",
                rc, filter, effective_base);
            ctx->error_count++;
            done = TRUE;
            goto free_result;
        }

        if (!result) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: ldap_search_ext_s returned NULL result\n");
            ctx->error_count++;
            done = TRUE;
            goto free_result;
        }

        ctx->page_count++;

        /* Invoke callback for each entry in this page */
        entry = ctx->api.ldap_first_entry(ctx->ldap_handle, result);
        while (entry && !abort_early) {
            total++;
            if (!callback(ctx, entry, user_data)) {
                abort_early = TRUE;
                done        = TRUE;
                break;
            }
            entry = ctx->api.ldap_next_entry(ctx->ldap_handle, entry);
        }

        /* Parse the result to extract server-side controls (including cookie) */
        ret_ctrls = NULL;
        rc = ctx->api.ldap_parse_result(
            ctx->ldap_handle,
            result,
            NULL,   /* ReturnCode */
            NULL,   /* MatchedDNs */
            NULL,   /* ErrorMessage */
            NULL,   /* Referrals */
            &ret_ctrls,
            (BOOL)FALSE   /* Freeit — we will free 'result' below */
        );
        if (rc != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: ldap_parse_result failed (rc=0x%02lX)\n", rc);
            ctx->error_count++;
            done = TRUE;
            goto free_ret_ctrls;
        }

        if (!ret_ctrls) {
            /* Server returned no controls — either done or doesn't support paging */
            done = TRUE;
            goto free_ret_ctrls;
        }

        /* Extract the next-page cookie */
        cookie = NULL;
        rc = ctx->api.ldap_parse_page_control(
            ctx->ldap_handle,
            ret_ctrls,
            &srv_total,
            &cookie
        );
        if (rc != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] PhantomLDAP: ldap_parse_page_control failed (rc=0x%02lX)\n", rc);
            ctx->error_count++;
            done = TRUE;
            goto free_ret_ctrls;
        }

        /* Discard old client-side page control */
        if (page_ctrl) {
            ctx->api.ldap_controls_free((LDAPControl **)&page_ctrl);
            page_ctrl = NULL;
        }

        /* Determine whether there are more pages */
        if (!cookie || cookie->bv_len == 0) {
            done = TRUE;
        } else if (!abort_early) {
            /* Build next-page control with updated cookie */
            rc = ctx->api.ldap_create_page_control(
                ctx->ldap_handle,
                ctx->page_size,
                cookie,
                (UCHAR)1,
                &page_ctrl
            );
            if (rc != LDAP_SUCCESS || !page_ctrl) {
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] PhantomLDAP: ldap_create_page_control (next page) "
                    "failed (rc=0x%02lX)\n", rc);
                done = TRUE;
            }
        } else {
            done = TRUE;
        }

free_ret_ctrls:
        if (ret_ctrls) {
            ctx->api.ldap_controls_free(ret_ctrls);
            ret_ctrls = NULL;
        }

free_result:
        if (result) {
            ctx->api.ldap_msgfree(result);
            result = NULL;
        }

    } /* end while (!done) */

    /* Final cleanup — in case loop exited via break before freeing */
    if (page_ctrl) {
        ctx->api.ldap_controls_free((LDAPControl **)&page_ctrl);
    }
    if (ret_ctrls) {
        ctx->api.ldap_controls_free(ret_ctrls);
    }
    if (result) {
        ctx->api.ldap_msgfree(result);
    }

    ctx->total_found = total;
    return total;
}
