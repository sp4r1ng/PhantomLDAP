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
static SIZE_T   phantom_wcslen(const WCHAR *s);
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
 * @brief Return the number of WCHARs in a NUL-terminated wide string (no CRT).
 *
 * @param s  Source wide string (may be NULL — returns 0)
 * @return   Character count excluding NUL
 */
static SIZE_T phantom_wcslen(const WCHAR *s)
{
    SIZE_T n = 0;
    if (!s) return 0;
    while (s[n] != L'\0') n++;
    return n;
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
 * Public Utility Functions
 * ========================================================================= */

/**
 * @brief Convert a wide string to narrow ASCII by direct byte cast.
 *
 * This is an intentionally lossy conversion covering only the 7-bit ASCII
 * subset. It is sufficient for all practical AD attribute values:
 * SAMAccountNames, DNs, hostnames, SPN strings — all of which use only
 * printable ASCII characters. For GUID strings and binary data, the caller
 * should use phantom_guid_to_string() or phantom_sid_to_string() instead.
 *
 * @param wstr      Source wide string (NUL-terminated)
 * @param buf       Destination narrow buffer
 * @param buf_size  Destination buffer capacity in bytes
 */
void phantom_wstr_to_str(const WCHAR *wstr, char *buf, SIZE_T buf_size)
{
    SIZE_T i;
    if (!wstr || !buf || buf_size == 0) return;
    for (i = 0; i < buf_size - 1 && wstr[i] != L'\0'; i++) {
        /* Mask to low byte; codepoints > 127 become garbage — acceptable for AD names */
        buf[i] = (char)(wstr[i] & 0xFF);
    }
    buf[i] = '\0';
}

/**
 * @brief Convert a narrow ASCII string to wide by zero-extending each byte.
 *
 * @param str       Source narrow string (NUL-terminated)
 * @param wbuf      Destination wide buffer
 * @param wbuf_len  Destination capacity in WCHARs (including NUL)
 */
void phantom_str_to_wstr(const char *str, WCHAR *wbuf, SIZE_T wbuf_len)
{
    SIZE_T i;
    if (!str || !wbuf || wbuf_len == 0) return;
    for (i = 0; i < wbuf_len - 1 && str[i] != '\0'; i++) {
        wbuf[i] = (WCHAR)(unsigned char)str[i];
    }
    wbuf[i] = L'\0';
}

/**
 * @brief Convert a binary objectSid to its canonical string form "S-R-A-SA1-SA2-...".
 *
 * The SID wire format is:
 *   Byte 0:      Revision (always 1)
 *   Byte 1:      SubAuthorityCount (N)
 *   Bytes 2-7:   IdentifierAuthority (6 bytes, big-endian)
 *   Bytes 8+:    N x 4-byte SubAuthority values (little-endian DWORDs)
 *
 * The authority field is printed as decimal when bytes 2-5 are all zero
 * (fits in 16 bits — all standard Windows SID authorities), otherwise as
 * a "0x" prefixed hex string.
 *
 * @param sid_bytes Raw SID bytes from LDAP objectSid binary attribute
 * @param sid_len   Total byte count of sid_bytes
 * @param out_buf   Output buffer (recommended minimum: 185 bytes)
 * @param buf_size  Size of out_buf in bytes
 * @return          TRUE on success, FALSE if input is NULL or malformed
 */
BOOL phantom_sid_to_string(const BYTE *sid_bytes, DWORD sid_len,
                           char *out_buf, SIZE_T buf_size)
{
    BYTE   revision;
    BYTE   sub_count;
    ULONG  authority;
    DWORD  sub_auth;
    SIZE_T pos;
    BYTE   i;
    BOOL   auth_high_bytes_set;

    /* Minimum valid SID: 8-byte header with zero sub-authorities */
    if (!sid_bytes || !out_buf || buf_size < 8 || sid_len < 8) {
        return FALSE;
    }

    revision  = sid_bytes[0];
    sub_count = sid_bytes[1];

    /* Validate total buffer covers all declared sub-authorities */
    if (sid_len < (DWORD)(8 + (DWORD)sub_count * 4)) {
        return FALSE;
    }

    pos        = 0;
    out_buf[0] = '\0';

    /* "S-" prefix */
    phantom_buf_append_str(out_buf, buf_size, &pos, "S-");

    /* Revision field */
    phantom_buf_append_u32(out_buf, buf_size, &pos, (ULONG)revision);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '-');

    /*
     * IdentifierAuthority: bytes 2..7, big-endian.
     * Standard authorities (NT, WORLD, etc.) have zero in bytes 2..5 and
     * use only the low 2 bytes. Exotic authorities need full hex representation.
     */
    auth_high_bytes_set = FALSE;
    for (i = 2; i <= 5; i++) {
        if (sid_bytes[i] != 0) {
            auth_high_bytes_set = TRUE;
            break;
        }
    }

    if (auth_high_bytes_set) {
        phantom_buf_append_str(out_buf, buf_size, &pos, "0x");
        for (i = 2; i <= 7; i++) {
            phantom_buf_append_hex_byte(out_buf, buf_size, &pos, sid_bytes[i]);
        }
    } else {
        /* Decimal from bytes 6..7 (big-endian) */
        authority = ((ULONG)sid_bytes[6] << 8) | (ULONG)sid_bytes[7];
        phantom_buf_append_u32(out_buf, buf_size, &pos, authority);
    }

    /* Sub-authorities: little-endian DWORDs starting at offset 8 */
    for (i = 0; i < sub_count; i++) {
        DWORD offset = 8 + (DWORD)i * 4;
        sub_auth = (DWORD) sid_bytes[offset    ]         |
                   (DWORD)(sid_bytes[offset + 1] <<  8)  |
                   (DWORD)(sid_bytes[offset + 2] << 16)  |
                   (DWORD)(sid_bytes[offset + 3] << 24);
        phantom_buf_append_ch(out_buf, buf_size, &pos, '-');
        phantom_buf_append_u32(out_buf, buf_size, &pos, sub_auth);
    }

    return TRUE;
}

/**
 * @brief Convert a raw 16-byte GUID to its canonical string form.
 *
 * Windows GUID wire format (as stored in AD binary attributes):
 *   Data1  (4 bytes, little-endian) -> "XXXXXXXX"
 *   Data2  (2 bytes, little-endian) -> "XXXX"
 *   Data3  (2 bytes, little-endian) -> "XXXX"
 *   Data4  (8 bytes, big-endian)   -> "XXXX-XXXXXXXXXXXX"
 *
 * Total output: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" (38 chars + NUL = 39)
 *
 * @param guid      Pointer to 16-byte GUID (wire format)
 * @param out_buf   Output buffer (minimum 39 bytes)
 * @param buf_size  Size of out_buf in bytes
 */
void phantom_guid_to_string(const BYTE *guid, char *out_buf, SIZE_T buf_size)
{
    DWORD  data1;
    WORD   data2;
    WORD   data3;
    SIZE_T pos;

    if (!guid || !out_buf || buf_size < 39) {
        if (out_buf && buf_size > 0) out_buf[0] = '\0';
        return;
    }

    pos        = 0;
    out_buf[0] = '\0';

    /* Data1: bytes 0-3, little-endian */
    data1 = (DWORD) guid[0]          |
             (DWORD)(guid[1] <<  8)   |
             (DWORD)(guid[2] << 16)   |
             (DWORD)(guid[3] << 24);

    /* Data2: bytes 4-5, little-endian */
    data2 = (WORD)guid[4] | (WORD)((WORD)guid[5] << 8);

    /* Data3: bytes 6-7, little-endian */
    data3 = (WORD)guid[6] | (WORD)((WORD)guid[7] << 8);

    phantom_buf_append_ch(out_buf, buf_size, &pos, '{');
    phantom_buf_append_hex32(out_buf, buf_size, &pos, data1);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '-');
    phantom_buf_append_hex16(out_buf, buf_size, &pos, data2);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '-');
    phantom_buf_append_hex16(out_buf, buf_size, &pos, data3);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '-');

    /* Data4 bytes 0-1 (big-endian, first half of last group) */
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[8]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[9]);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '-');

    /* Data4 bytes 2-7 (big-endian, 6 bytes = 12 hex chars) */
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[10]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[11]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[12]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[13]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[14]);
    phantom_buf_append_hex_byte(out_buf, buf_size, &pos, guid[15]);
    phantom_buf_append_ch(out_buf, buf_size, &pos, '}');
}

/**
 * @brief Convert a Windows FILETIME value to a human-readable UTC date-time string.
 *
 * Conversion algorithm (no CRT dependency):
 *   1. Subtract 116444736000000000 (100-ns ticks from 1601-01-01 to 1970-01-01)
 *      to get Unix epoch in 100-ns ticks.
 *   2. Divide by 10000000 to get Unix epoch in whole seconds.
 *   3. Split into days-since-epoch and time-of-day seconds.
 *   4. Apply the Proleptic Gregorian calendar algorithm (civil_from_days,
 *      Howard Hinnant, public domain) to compute year/month/day without
 *      lookup tables. The algorithm shifts the epoch to 0000-03-01 to
 *      simplify leap-year arithmetic.
 *   5. Format the result as "YYYY-MM-DD HH:MM:SS UTC".
 *
 * Special values handled:
 *   - ft == 0: "Never" (attribute not set)
 *   - ft == 0x7FFFFFFFFFFFFFFF: "Never" (AD "never expires" sentinel)
 *   - ft < FILETIME_TO_UNIX_OFFSET: "Pre-1970" (guard against bogus input)
 *
 * @param ft        64-bit FILETIME value (100-ns intervals since Jan 1, 1601)
 * @param buf       Output buffer
 * @param buf_size  Output buffer size in chars (minimum 24 for full string)
 */
void phantom_filetime_to_str(LONGLONG ft, char *buf, SIZE_T buf_size)
{
    ULONGLONG unix_sec;
    ULONGLONG days;
    ULONGLONG rem_sec;
    ULONGLONG hour, minute, second;
    ULONGLONG y400, y100, y4, y1;
    ULONGLONG n, m, day_of_month;
    ULONGLONG month, year;
    ULONGLONG tmp;
    SIZE_T    pos;

    if (!buf || buf_size == 0) return;
    buf[0] = '\0';
    pos    = 0;

    /* AD "never" sentinels — attribute not set or explicitly infinite */
    if (ft == 0LL || ft == (LONGLONG)0x7FFFFFFFFFFFFFFFLL) {
        phantom_buf_append_str(buf, buf_size, &pos, "Never");
        return;
    }

    /* Guard: reject timestamps before Unix epoch (very unlikely in AD) */
    if ((ULONGLONG)ft < FILETIME_TO_UNIX_OFFSET) {
        phantom_buf_append_str(buf, buf_size, &pos, "Pre-1970");
        return;
    }

    /* Convert to Unix seconds */
    unix_sec = ((ULONGLONG)ft - FILETIME_TO_UNIX_OFFSET) / FILETIME_TICKS_PER_SEC;

    /* Split into days and intra-day seconds */
    days    = unix_sec / 86400ULL;
    rem_sec = unix_sec % 86400ULL;

    hour    = rem_sec / 3600ULL;
    rem_sec %= 3600ULL;
    minute  = rem_sec / 60ULL;
    second  = rem_sec % 60ULL;

    /*
     * Proleptic Gregorian calendar decomposition from day count.
     * Reference: "chrono-Compatible Low-Level Date Algorithms"
     *            by Howard Hinnant (https://howardhinnant.github.io/date_algorithms.html)
     *
     * The algorithm shifts the calendar epoch to March 1 (day 0 of a
     * 400-year cycle) so that leap days always fall at the end of each
     * 4-year group, making the modular arithmetic clean.
     */
    n    = days + 719468ULL;               /* shift to 0000-03-01 epoch */
    y400 = n / 146097ULL;                  /* 400-year groups */
    n   %= 146097ULL;
    y100 = n / 36524ULL;                   /* 100-year groups */
    if (y100 == 4) y100 = 3;              /* clamp for last day of 400-yr period */
    n   -= y100 * 36524ULL;
    y4   = n / 1461ULL;                    /* 4-year groups */
    n   %= 1461ULL;
    y1   = n / 365ULL;                     /* remaining years */
    if (y1 == 4) y1 = 3;                  /* clamp for last day of 4-yr period */

    year         = y400 * 400ULL + y100 * 100ULL + y4 * 4ULL + y1;
    tmp          = n - y1 * 365ULL;        /* day-of-year (March = day 0) */
    m            = (5ULL * tmp + 2ULL) / 153ULL; /* month index (March = 0) */
    day_of_month = tmp - (153ULL * m + 2ULL) / 5ULL + 1ULL;

    /* Convert month index back to January = 1 */
    month = (m < 10ULL) ? (m + 3ULL) : (m - 9ULL);
    if (m >= 10ULL) year++;   /* January/February belong to the next year */

    /* ---- Format: YYYY-MM-DD HH:MM:SS UTC ---- */

    /* Year (4 digits minimum) */
    phantom_buf_append_u64(buf, buf_size, &pos, year);
    phantom_buf_append_ch(buf, buf_size, &pos, '-');

    /* Month (zero-padded) */
    if (month < 10) phantom_buf_append_ch(buf, buf_size, &pos, '0');
    phantom_buf_append_u64(buf, buf_size, &pos, month);
    phantom_buf_append_ch(buf, buf_size, &pos, '-');

    /* Day (zero-padded) */
    if (day_of_month < 10) phantom_buf_append_ch(buf, buf_size, &pos, '0');
    phantom_buf_append_u64(buf, buf_size, &pos, day_of_month);
    phantom_buf_append_ch(buf, buf_size, &pos, ' ');

    /* Hour (zero-padded) */
    if (hour < 10) phantom_buf_append_ch(buf, buf_size, &pos, '0');
    phantom_buf_append_u64(buf, buf_size, &pos, hour);
    phantom_buf_append_ch(buf, buf_size, &pos, ':');

    /* Minute (zero-padded) */
    if (minute < 10) phantom_buf_append_ch(buf, buf_size, &pos, '0');
    phantom_buf_append_u64(buf, buf_size, &pos, minute);
    phantom_buf_append_ch(buf, buf_size, &pos, ':');

    /* Second (zero-padded) */
    if (second < 10) phantom_buf_append_ch(buf, buf_size, &pos, '0');
    phantom_buf_append_u64(buf, buf_size, &pos, second);

    phantom_buf_append_str(buf, buf_size, &pos, " UTC");
}

/**
 * @brief Convert a FILETIME to a relative "X days ago" string.
 *
 * Dynamically resolves kernel32!GetSystemTimeAsFileTime via phantom_resolve()
 * using the pre-computed DJB2 hash to avoid a static IAT entry.
 *
 * Output forms:
 *   - "Never"                 — ft is 0 or 0x7FFFFFFFFFFFFFFF
 *   - "Today"                 — ft is within the current calendar day
 *   - "X days ago"            — for 1 <= age <= 999 days
 *   - ">999 days ago"         — for age > 999 days
 *   - "In the future"         — ft is greater than current time (bogus data guard)
 *   - "Unknown (resolve failed)" — kernel32 not available (should never happen)
 *
 * @param ft        64-bit FILETIME value to age
 * @param buf       Output buffer
 * @param buf_size  Output buffer size in chars
 */
void phantom_filetime_to_age(LONGLONG ft, char *buf, SIZE_T buf_size)
{
    fn_GetSystemTimeAsFileTime_t pfnGetSystemTime;
    FILETIME  now_ft;
    LONGLONG  now_ll;
    LONGLONG  age_days;
    SIZE_T    pos;

    if (!buf || buf_size == 0) return;
    buf[0] = '\0';
    pos    = 0;

    /* Handle sentinel values */
    if (ft == 0LL || ft == (LONGLONG)0x7FFFFFFFFFFFFFFFLL) {
        phantom_buf_append_str(buf, buf_size, &pos, "Never");
        return;
    }

    /* Dynamically resolve GetSystemTimeAsFileTime — avoids static kernel32 import */
    pfnGetSystemTime = (fn_GetSystemTimeAsFileTime_t)phantom_resolve(
        PHANTOM_HASH_KERNEL32,
        PHANTOM_HASH_GetSystemTimeAsFileTime);

    if (!pfnGetSystemTime) {
        phantom_buf_append_str(buf, buf_size, &pos, "Unknown (resolve failed)");
        return;
    }

    pfnGetSystemTime(&now_ft);

    /* Combine FILETIME halves into a single LONGLONG */
    now_ll = ((LONGLONG)now_ft.dwHighDateTime << 32) |
              (LONGLONG)(DWORD)now_ft.dwLowDateTime;

    age_days = phantom_filetime_diff_days(ft, now_ll);

    if (age_days < 0) {
        phantom_buf_append_str(buf, buf_size, &pos, "In the future");
    } else if (age_days == 0) {
        phantom_buf_append_str(buf, buf_size, &pos, "Today");
    } else if (age_days > 999) {
        phantom_buf_append_str(buf, buf_size, &pos, ">999 days ago");
    } else {
        phantom_buf_append_u64(buf, buf_size, &pos, (ULONGLONG)age_days);
        phantom_buf_append_str(buf, buf_size, &pos, " days ago");
    }
}

/* =========================================================================
 * Extended Rights GUID Lookup Table
 * ========================================================================= */

/**
 * @brief Single entry in the static extended-rights GUID-to-name table.
 *
 * GUIDs are stored as 16 raw bytes in the Windows GUID wire format:
 *   bytes 0-3:  Data1 (little-endian)
 *   bytes 4-5:  Data2 (little-endian)
 *   bytes 6-7:  Data3 (little-endian)
 *   bytes 8-15: Data4 (big-endian)
 *
 * This matches how wldap32 returns ObjectType bytes from OBJECT_ACEs.
 */
typedef struct {
    BYTE        guid[16]; /**< Raw GUID bytes (wire format, matches OBJECT_ACE ObjectType) */
    const char *name;     /**< Human-readable name for Beacon output                       */
} GUID_NAME_ENTRY;

/**
 * @brief Static table of well-known Active Directory GUIDs.
 *
 * These GUIDs correspond to extended rights, validated writes, and schema
 * attributes that are most commonly abused during AD privilege escalation.
 *
 * The lookup is used by the ACL parser to annotate object ACEs with meaningful
 * right names rather than raw GUID strings, making output immediately actionable.
 *
 * Sources:
 *   - MS-ADTS: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
 *   - LAPS, BloodHound, and Impacket reference implementations
 */
static const GUID_NAME_ENTRY g_known_guids[] = {

    /*
     * User-Force-Change-Password
     * GUID: {00299570-246d-11d0-a768-00aa006e0529}
     * Risk: Allows password reset WITHOUT knowing the current password. Direct
     *       account takeover. Commonly the target of ACL-based attacks.
     */
    {
        { 0x70,0x95,0x29,0x00,  0x6d,0x24,  0xd0,0x11,
          0xa7,0x68,  0x00,0xaa,0x00,0x6e,0x05,0x29 },
        "User-Force-Change-Password [CRITICAL]"
    },

    /*
     * DS-Replication-Get-Changes-All
     * GUID: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
     * Risk: Enables DCSync — replicate all domain secrets including krbtgt hash.
     */
    {
        { 0xad,0xf6,0x31,0x11,  0x07,0x9c,  0xd1,0x11,
          0xf7,0x9f,  0x00,0xc0,0x4f,0xc2,0xdc,0xd2 },
        "DS-Replication-Get-Changes-All (DCSync) [CRITICAL]"
    },

    /*
     * DS-Replication-Get-Changes
     * GUID: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
     * Risk: First half of DCSync. Required alongside Get-Changes-All.
     */
    {
        { 0xaa,0xf6,0x31,0x11,  0x07,0x9c,  0xd1,0x11,
          0xf7,0x9f,  0x00,0xc0,0x4f,0xc2,0xdc,0xd2 },
        "DS-Replication-Get-Changes [HIGH]"
    },

    /*
     * DS-Replication-Synchronize
     * GUID: {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}
     * Risk: Replication synchronization — part of DCSync privilege set.
     */
    {
        { 0xab,0xf6,0x31,0x11,  0x07,0x9c,  0xd1,0x11,
          0xf7,0x9f,  0x00,0xc0,0x4f,0xc2,0xdc,0xd2 },
        "DS-Replication-Synchronize [HIGH]"
    },

    /*
     * Allowed-To-Act-On-Behalf-Of-Other-Identity (msDS-AllowedToActOnBehalfOfOtherIdentity)
     * GUID: {3f78c3e5-f79a-46bd-a0b8-9d18116ddc79}
     * Risk: Write access enables Resource-Based Constrained Delegation (RBCD) attack.
     */
    {
        { 0xe5,0xc3,0x78,0x3f,  0x9a,0xf7,  0xbd,0x46,
          0xa0,0xb8,  0x9d,0x18,0x11,0x6d,0xdc,0x79 },
        "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) [HIGH]"
    },

    /*
     * Member attribute (group membership)
     * GUID: {bf9679c0-0de6-11d0-a285-00aa003049e2}
     * Risk: Write access allows adding arbitrary accounts to groups.
     */
    {
        { 0xc0,0x79,0x96,0xbf,  0xe6,0x0d,  0xd0,0x11,
          0xa2,0x85,  0x00,0xaa,0x00,0x30,0x49,0xe2 },
        "Member (Group Membership Write) [HIGH]"
    },

    /*
     * ServicePrincipalName attribute
     * GUID: {f3a64788-5306-11d1-a9c5-0000f8031627}
     * Risk: Write access allows adding SPNs -> enables Kerberoasting of victim account.
     */
    {
        { 0x88,0x47,0xa6,0xf3,  0x06,0x53,  0xd1,0x11,
          0xa9,0xc5,  0x00,0x00,0xf8,0x03,0x16,0x27 },
        "ServicePrincipalName (SPN Write) [MEDIUM]"
    },

    /*
     * Script-Path attribute (login script path)
     * GUID: {bf9679a8-0de6-11d0-a285-00aa003049e2}
     * Risk: Write access allows setting a malicious logon script path (persistence).
     */
    {
        { 0xa8,0x79,0x96,0xbf,  0xe6,0x0d,  0xd0,0x11,
          0xa2,0x85,  0x00,0xaa,0x00,0x30,0x49,0xe2 },
        "Script-Path (Login Script Write) [MEDIUM]"
    },

    /*
     * userAccountControl attribute
     * GUID: {bf967a68-0de6-11d0-a285-00aa003049e2}
     * Risk: Write access allows modifying UAC flags (e.g., disabling preauth for
     *       AS-REP roasting, enabling unconstrained delegation).
     */
    {
        { 0x68,0x7a,0x96,0xbf,  0xe6,0x0d,  0xd0,0x11,
          0xa2,0x85,  0x00,0xaa,0x00,0x30,0x49,0xe2 },
        "userAccountControl (UAC Write) [MEDIUM]"
    },

    /*
     * msDS-KeyCredentialLink (Windows Hello for Business / Shadow Credentials)
     * GUID: {5b47d60f-6090-40b2-9f37-2a4de88f3063}
     * Risk: Write access enables Shadow Credentials attack (certificate-based auth bypass).
     */
    {
        { 0x0f,0xd6,0x47,0x5b,  0x90,0x60,  0xb2,0x40,
          0x9f,0x37,  0x2a,0x4d,0xe8,0x8f,0x30,0x63 },
        "msDS-KeyCredentialLink (Shadow Credentials) [CRITICAL]"
    },

    /*
     * msDS-GroupMSAMembership (Group Managed Service Account membership)
     * GUID: {488aec39-e00b-47b4-9ef7-8c3e71a76c3d}
     * Risk: Controls which principals can retrieve GMSA passwords.
     */
    {
        { 0x39,0xec,0x8a,0x48,  0x0b,0xe0,  0xb4,0x47,
          0x9e,0xf7,  0x8c,0x3e,0x71,0xa7,0x6c,0x3d },
        "msDS-GroupMSAMembership (GMSA Read) [HIGH]"
    }
};

/** Number of entries in the g_known_guids table */
#define PHANTOM_KNOWN_GUID_COUNT \
    ( sizeof(g_known_guids) / sizeof(g_known_guids[0]) )

/**
 * @brief Lookup a 16-byte GUID in the known AD extended rights table.
 *
 * Performs a linear scan using phantom_memcmp(). The table is small enough
 * (~10 entries) that a hash map would add unnecessary complexity.
 *
 * @param guid  Pointer to 16-byte GUID in wire format (same byte order as
 *              returned by ldap_get_values_len() for binary attributes)
 * @return      Pointer to static string name, or NULL if GUID is not known
 */
const char *phantom_lookup_extended_right(const BYTE *guid)
{
    SIZE_T i;
    if (!guid) return NULL;
    for (i = 0; i < PHANTOM_KNOWN_GUID_COUNT; i++) {
        if (phantom_memcmp(g_known_guids[i].guid, guid, 16) == 0) {
            return g_known_guids[i].name;
        }
    }
    return NULL;
}

/* =========================================================================
 * UAC and Access Mask Decoders
 * ========================================================================= */

/**
 * @brief Decode a userAccountControl DWORD into a comma-separated flag string.
 *
 * Iterates all defined UAC_* constants from phantom_ldap.h. Flags related to
 * attack-relevant conditions (delegation, AS-REP roasting) are annotated with
 * "[!]" to draw the operator's attention in Beacon output.
 *
 * @param uac       userAccountControl value
 * @param buf       Output buffer
 * @param buf_size  Buffer size in bytes
 */
void phantom_decode_uac(DWORD uac, char *buf, SIZE_T buf_size)
{
    SIZE_T pos;
    BOOL   first;

    if (!buf || buf_size == 0) return;
    buf[0] = '\0';
    pos    = 0;
    first  = TRUE;

    if (uac & UAC_ACCOUNTDISABLE)
        phantom_append_flag(buf, buf_size, &pos, &first, "DISABLED");
    if (uac & UAC_HOMEDIR_REQUIRED)
        phantom_append_flag(buf, buf_size, &pos, &first, "HOMEDIR_REQUIRED");
    if (uac & UAC_LOCKOUT)
        phantom_append_flag(buf, buf_size, &pos, &first, "LOCKED_OUT");
    if (uac & UAC_PASSWD_NOTREQD)
        phantom_append_flag(buf, buf_size, &pos, &first, "PASSWORD_NOT_REQUIRED");
    if (uac & UAC_PASSWD_CANT_CHANGE)
        phantom_append_flag(buf, buf_size, &pos, &first, "PASSWORD_CANT_CHANGE");
    if (uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED)
        phantom_append_flag(buf, buf_size, &pos, &first, "ENCRYPTED_TEXT_PWD_ALLOWED");
    if (uac & UAC_NORMAL_ACCOUNT)
        phantom_append_flag(buf, buf_size, &pos, &first, "NORMAL_ACCOUNT");
    if (uac & UAC_INTERDOMAIN_TRUST_ACCOUNT)
        phantom_append_flag(buf, buf_size, &pos, &first, "INTERDOMAIN_TRUST");
    if (uac & UAC_WORKSTATION_TRUST_ACCOUNT)
        phantom_append_flag(buf, buf_size, &pos, &first, "WORKSTATION_TRUST");
    if (uac & UAC_SERVER_TRUST_ACCOUNT)
        phantom_append_flag(buf, buf_size, &pos, &first, "SERVER_TRUST");
    if (uac & UAC_DONT_EXPIRE_PASSWORD)
        phantom_append_flag(buf, buf_size, &pos, &first, "DONT_EXPIRE_PASSWORD");
    if (uac & UAC_SMARTCARD_REQUIRED)
        phantom_append_flag(buf, buf_size, &pos, &first, "SMARTCARD_REQUIRED");
    if (uac & UAC_TRUSTED_FOR_DELEGATION)
        phantom_append_flag(buf, buf_size, &pos, &first, "TRUSTED_FOR_DELEGATION [!UNCONSTRAINED]");
    if (uac & UAC_NOT_DELEGATED)
        phantom_append_flag(buf, buf_size, &pos, &first, "NOT_DELEGATED");
    if (uac & UAC_USE_DES_KEY_ONLY)
        phantom_append_flag(buf, buf_size, &pos, &first, "USE_DES_KEY_ONLY");
    if (uac & UAC_DONT_REQUIRE_PREAUTH)
        phantom_append_flag(buf, buf_size, &pos, &first, "DONT_REQUIRE_PREAUTH [!AS-REP ROASTABLE]");
    if (uac & UAC_PASSWORD_EXPIRED)
        phantom_append_flag(buf, buf_size, &pos, &first, "PASSWORD_EXPIRED");
    if (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        phantom_append_flag(buf, buf_size, &pos, &first, "TRUSTED_TO_AUTH_FOR_DELEGATION [!CONSTRAINED S4U]");
    if (uac & UAC_NO_AUTH_DATA_REQUIRED)
        phantom_append_flag(buf, buf_size, &pos, &first, "NO_AUTH_DATA_REQUIRED");
    if (uac & UAC_PARTIAL_SECRETS_ACCOUNT)
        phantom_append_flag(buf, buf_size, &pos, &first, "PARTIAL_SECRETS (RODC)");

    if (first) {
        /* No recognized flags — print the raw hex value */
        phantom_buf_append_str(buf, buf_size, &pos, "0x");
        phantom_buf_append_hex32(buf, buf_size, &pos, uac);
    }
}

/**
 * @brief Decode an AD ACCESS_MASK into a human-readable comma-separated string.
 *
 * Covers all Active Directory-specific rights (ADS_RIGHT_DS_*) and the
 * standard object rights (WriteDACL, WriteOwner, GenericAll) that are most
 * relevant for attack path identification. Flags with high-privilege
 * implications are annotated with "[!]".
 *
 * @param mask      Raw ACCESS_MASK value (DWORD)
 * @param buf       Output buffer
 * @param buf_size  Buffer size in bytes
 */
void phantom_decode_access_mask(DWORD mask, char *buf, SIZE_T buf_size)
{
    SIZE_T pos;
    BOOL   first;

    if (!buf || buf_size == 0) return;
    buf[0] = '\0';
    pos    = 0;
    first  = TRUE;

    /* === AD-specific rights (low 16 bits of mask) === */
    if (mask & ADS_RIGHT_DS_CREATE_CHILD)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_CREATE_CHILD");
    if (mask & ADS_RIGHT_DS_DELETE_CHILD)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_DELETE_CHILD");
    if (mask & ADS_RIGHT_ACTRL_DS_LIST)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_LIST");
    if (mask & ADS_RIGHT_DS_SELF)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_SELF (Validated Write)");
    if (mask & ADS_RIGHT_DS_READ_PROP)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_READ_PROP");
    if (mask & ADS_RIGHT_DS_WRITE_PROP)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_WRITE_PROP [!]");
    if (mask & ADS_RIGHT_DS_DELETE_TREE)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_DELETE_TREE");
    if (mask & ADS_RIGHT_DS_LIST_OBJECT)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_LIST_OBJECT");
    if (mask & ADS_RIGHT_DS_CONTROL_ACCESS)
        phantom_append_flag(buf, buf_size, &pos, &first, "DS_CONTROL_ACCESS (AllExtendedRights) [!]");

    /* === Standard object rights (upper 16 bits) === */
    if (mask & RIGHT_DELETE)
        phantom_append_flag(buf, buf_size, &pos, &first, "DELETE");
    if (mask & RIGHT_READ_CONTROL)
        phantom_append_flag(buf, buf_size, &pos, &first, "READ_CONTROL");
    if (mask & RIGHT_WRITE_DAC)
        phantom_append_flag(buf, buf_size, &pos, &first, "WRITE_DAC [!WriteDACL]");
    if (mask & RIGHT_WRITE_OWNER)
        phantom_append_flag(buf, buf_size, &pos, &first, "WRITE_OWNER [!]");
    if (mask & RIGHT_GENERIC_READ)
        phantom_append_flag(buf, buf_size, &pos, &first, "GENERIC_READ");
    if (mask & RIGHT_GENERIC_WRITE)
        phantom_append_flag(buf, buf_size, &pos, &first, "GENERIC_WRITE [!]");
    if (mask & RIGHT_GENERIC_EXECUTE)
        phantom_append_flag(buf, buf_size, &pos, &first, "GENERIC_EXECUTE");
    if (mask & RIGHT_GENERIC_ALL)
        phantom_append_flag(buf, buf_size, &pos, &first, "GENERIC_ALL [!GenericAll]");

    if (first) {
        /* Unrecognized mask — print raw hex */
        phantom_buf_append_str(buf, buf_size, &pos, "0x");
        phantom_buf_append_hex32(buf, buf_size, &pos, mask);
    }
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
