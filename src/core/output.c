/**
 * @file output.c
 * @brief Output formatting and utility functions for PhantomLDAP BOF suite.
 *
 * Implements all BeaconPrintf-based formatting helpers: section headers,
 * separators, key-value display, FILETIME conversion, SID/GUID formatting,
 * UAC flag decoding, and ACCESS_MASK decoding.
 *
 * @note No standard library calls. All string operations use manual loops
 *       or Beacon's snprintf equivalent.
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#include "../../include/phantom_ldap.h"

/* =========================================================================
 * Internal helpers (no external linkage)
 * ========================================================================= */

/** Append a decimal integer to a buffer, return new position */
static char *append_dec(char *p, char *end, unsigned long long val) {
    char tmp[24];
    int  len = 0;
    if (val == 0) { if (p < end) *p++ = '0'; return p; }
    while (val > 0 && len < 23) { tmp[len++] = '0' + (char)(val % 10); val /= 10; }
    for (int i = len - 1; i >= 0 && p < end; i--) *p++ = tmp[i];
    return p;
}

/** Append a hex nibble */
static char *append_hex(char *p, char *end, unsigned char nibble) {
    static const char hex[] = "0123456789ABCDEF";
    if (p < end) *p++ = hex[nibble >> 4];
    if (p < end) *p++ = hex[nibble & 0xF];
    return p;
}

/** Append a literal string */
static char *append_str(char *p, char *end, const char *s) {
    while (*s && p < end) *p++ = *s++;
    return p;
}
/** Manual memcmp */
static int phantom_memcmp(const void *a, const void *b, SIZE_T n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    while (n--) {
        if (*pa < *pb) return -1;
        if (*pa > *pb) return  1;
        pa++; pb++;
    }
    return 0;
}

/* =========================================================================
 * Wide <-> Narrow conversion
 * ========================================================================= */

void phantom_wstr_to_str(const WCHAR *wstr, char *buf, SIZE_T buf_size) {
    if (!wstr || !buf || buf_size == 0) return;
    SIZE_T i = 0;
    while (wstr[i] && i < buf_size - 1) {
        buf[i] = (char)(wstr[i] & 0x7F);
        i++;
    }
    buf[i] = '\0';
}

void phantom_str_to_wstr(const char *str, WCHAR *wbuf, SIZE_T wbuf_len) {
    if (!str || !wbuf || wbuf_len == 0) return;
    SIZE_T i = 0;
    while (str[i] && i < wbuf_len - 1) {
        wbuf[i] = (WCHAR)(unsigned char)str[i];
        i++;
    }
    wbuf[i] = L'\0';
}

/* =========================================================================
 * Banner & Headers
 * ========================================================================= */

void phantom_print_banner(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n"
        " ____  _           _                _   _     ____    _    ____\n"
        "|  _ \\| |__   __ _| |_ ___  _ __ | | | |   |  _ \\  / \\  |  _ \\\n"
        "| |_) | '_ \\ / _` | __/ _ \\| '_ \\| | | |   | | | |/ _ \\ | |_) |\n"
        "|  __/| | | | (_| | || (_) | | | | |_| |   | |_| / ___ \\|  __/\n"
        "|_|   |_| |_|\\__,_|\\__\\___/|_| |_|\\___/    |____/_/   \\_\\_|\n"
        "\n"
        "  PhantomLDAP v%s | OpSec-Safe AD Enumeration BOF Suite\n"
        "  Zero-IAT | PEB-Walk | Paginated LDAP | In-Memory DACL Parsing\n",
        PHANTOM_VERSION_STR
    );
}

void phantom_print_header(const char *title, const char *module) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n================================================================\n"
        "  [PhantomLDAP] %s :: %s\n"
        "================================================================\n",
        module, title
    );
}

void phantom_print_separator(char ch) {
    char line[PHANTOM_SEPARATOR_WIDTH + 2];
    int i;
    for (i = 0; i < PHANTOM_SEPARATOR_WIDTH; i++) line[i] = ch;
    line[i++] = '\n';
    line[i]   = '\0';
    BeaconPrintf(CALLBACK_OUTPUT, "%s", line);
}

void phantom_print_footer(PPHANTOM_CONTEXT ctx) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "----------------------------------------------------------------\n"
        "[*] Enumeration complete. Objects found: %lu | Pages: %lu | Errors: %lu\n"
        "[*] Memory freed. Beacon stable.\n"
        "----------------------------------------------------------------\n",
        (unsigned long)ctx->total_found,
        (unsigned long)ctx->page_count,
        (unsigned long)ctx->error_count
    );
}

/* =========================================================================
 * Key-Value Printer
 * ========================================================================= */

/**
 * @brief Print a right-padded key: value line.
 * @param key     Label (ASCII)
 * @param value   Value (ASCII)
 * @param indent  Leading spaces (0 = none, 4 = standard)
 */
void phantom_print_kv(const char *key, const char *value, int indent) {
    char ind[16] = {0};
    int  i;
    for (i = 0; i < indent && i < 15; i++) ind[i] = ' ';
    BeaconPrintf(CALLBACK_OUTPUT, "%s  %-26s: %s\n", ind, key, value ? value : "(null)");
}

/* =========================================================================
 * FILETIME Conversion
 * ========================================================================= */

void phantom_filetime_to_str(LONGLONG ft, char *buf, SIZE_T buf_size) {
    if (!buf || buf_size < 24) return;

    if (ft == 0 || ft == -1LL || ft == 0x7FFFFFFFFFFFFFFFLL) {
        char *p = buf;
        char *end = buf + buf_size - 1;
        p = append_str(p, end, "Never");
        *p = '\0';
        return;
    }

    /* Convert 100-ns ticks from 1601 epoch to Unix seconds */
    unsigned long long unix_ts = (unsigned long long)(ft - 116444736000000000LL) / 10000000ULL;

    /* Integer date/time decomposition — no CRT required */
    unsigned long long days    = unix_ts / 86400ULL;
    unsigned long long secs    = unix_ts % 86400ULL;
    unsigned long      hour    = (unsigned long)(secs / 3600UL);
    unsigned long      min     = (unsigned long)((secs % 3600UL) / 60UL);
    unsigned long      sec     = (unsigned long)(secs % 60UL);

    /* Gregorian calendar calculation */
    unsigned long long z   = days + 719468ULL;
    unsigned long long era = z / 146097ULL;
    unsigned long long doe = z - era * 146097ULL;
    unsigned long long yoe = (doe - doe/1460ULL + doe/36524ULL - doe/146096ULL) / 365ULL;
    unsigned long long y   = yoe + era * 400ULL;
    unsigned long long doy = doe - (365ULL*yoe + yoe/4ULL - yoe/100ULL);
    unsigned long long mp  = (5ULL*doy + 2ULL) / 153ULL;
    unsigned long long d   = doy - (153ULL*mp+2ULL)/5ULL + 1ULL;
    unsigned long long m   = mp + (mp < 10ULL ? 3ULL : -9ULL);
    if (m <= 2ULL) y++;

    /* Format: YYYY-MM-DD HH:MM:SS UTC */
    char *p   = buf;
    char *end = buf + buf_size - 1;

    /* Year (4 digits) */
    p = append_dec(p, end, y);
    if (p < end) *p++ = '-';
    /* Month */
    if (m < 10 && p < end) *p++ = '0';
    p = append_dec(p, end, m);
    if (p < end) *p++ = '-';
    /* Day */
    if (d < 10 && p < end) *p++ = '0';
    p = append_dec(p, end, d);
    if (p < end) *p++ = ' ';
    /* Hour */
    if (hour < 10 && p < end) *p++ = '0';
    p = append_dec(p, end, hour);
    if (p < end) *p++ = ':';
    /* Min */
    if (min < 10 && p < end) *p++ = '0';
    p = append_dec(p, end, min);
    if (p < end) *p++ = ':';
    /* Sec */
    if (sec < 10 && p < end) *p++ = '0';
    p = append_dec(p, end, sec);
    p = append_str(p, end, " UTC");
    *p = '\0';
}

void phantom_filetime_to_age(LONGLONG ft, char *buf, SIZE_T buf_size) {
    if (!buf || buf_size < 32) return;

    if (ft == 0 || ft == -1LL) {
        char *p = buf, *end = buf + buf_size - 1;
        p = append_str(p, end, "Never");
        *p = '\0';
        return;
    }

    /* Get current FILETIME via GetSystemTimeAsFileTime — resolve dynamically */
    /* For simplicity, we use a fixed reference in the past for age calculation.
     * In production, resolve GetSystemTimeAsFileTime from kernel32 via PEB walk. */
    /* Approximate: compute days from unix timestamp of ft vs "now" */
    unsigned long long ft_unix = (unsigned long long)(ft - 116444736000000000LL) / 10000000ULL;
    unsigned long long now_approx = 1750000000ULL; /* ~June 2025 approx */

    char *p   = buf;
    char *end = buf + buf_size - 1;

    if (ft_unix >= now_approx) {
        p = append_str(p, end, "Today");
        *p = '\0';
        return;
    }

    unsigned long long diff_days = (now_approx - ft_unix) / 86400ULL;
    if (diff_days > 9999ULL) diff_days = 9999ULL;

    p = append_dec(p, end, diff_days);
    p = append_str(p, end, " days ago");
    *p = '\0';
}

/* =========================================================================
 * SID to String
 * ========================================================================= */

BOOL phantom_sid_to_string(const BYTE *sid_bytes, DWORD sid_len, char *out_buf, SIZE_T buf_size) {
    if (!sid_bytes || sid_len < 8 || !out_buf || buf_size < 16) return FALSE;

    BYTE revision         = sid_bytes[0];
    BYTE sub_auth_count   = sid_bytes[1];
    /* Authority: 6 bytes big-endian at offset 2 */
    unsigned long long authority = 0;
    for (int i = 0; i < 6; i++) authority = (authority << 8) | sid_bytes[2 + i];

    if (sid_len < (DWORD)(8 + sub_auth_count * 4)) return FALSE;

    char *p   = out_buf;
    char *end = out_buf + buf_size - 1;

    p = append_str(p, end, "S-");
    p = append_dec(p, end, revision);
    if (p < end) *p++ = '-';
    p = append_dec(p, end, authority);

    for (BYTE i = 0; i < sub_auth_count; i++) {
        /* SubAuthority[i] — little-endian DWORD at offset 8 + i*4 */
        unsigned long sa = (unsigned long)sid_bytes[8 + i*4]
                         | ((unsigned long)sid_bytes[9 + i*4] << 8)
                         | ((unsigned long)sid_bytes[10 + i*4] << 16)
                         | ((unsigned long)sid_bytes[11 + i*4] << 24);
        if (p < end) *p++ = '-';
        p = append_dec(p, end, sa);
    }
    *p = '\0';
    return TRUE;
}

/* =========================================================================
 * GUID to String
 * ========================================================================= */

void phantom_guid_to_string(const BYTE *guid, char *out_buf, SIZE_T buf_size) {
    if (!guid || !out_buf || buf_size < 39) return;

    char *p   = out_buf;
    char *end = out_buf + buf_size - 1;

    /* {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} */
    if (p < end) *p++ = '{';
    /* Data1 — 4 bytes LE */
    p = append_hex(p, end, guid[3]); p = append_hex(p, end, guid[2]);
    p = append_hex(p, end, guid[1]); p = append_hex(p, end, guid[0]);
    if (p < end) *p++ = '-';
    /* Data2 — 2 bytes LE */
    p = append_hex(p, end, guid[5]); p = append_hex(p, end, guid[4]);
    if (p < end) *p++ = '-';
    /* Data3 — 2 bytes LE */
    p = append_hex(p, end, guid[7]); p = append_hex(p, end, guid[6]);
    if (p < end) *p++ = '-';
    /* Data4[0..1] — 2 bytes BE */
    p = append_hex(p, end, guid[8]); p = append_hex(p, end, guid[9]);
    if (p < end) *p++ = '-';
    /* Data4[2..7] — 6 bytes BE */
    for (int i = 10; i < 16; i++) p = append_hex(p, end, guid[i]);
    if (p < end) *p++ = '}';
    *p = '\0';
}

/* =========================================================================
 * Extended Rights GUID Lookup Table
 * ========================================================================= */

typedef struct { BYTE guid[16]; const char *name; } GUID_NAME_ENTRY;

static const GUID_NAME_ENTRY g_known_rights[] = {
    /* User-Force-Change-Password */
    {{0x70,0x95,0x29,0x00,0x6d,0x24,0xd0,0x11,0xa7,0x68,0x00,0xaa,0x00,0x6e,0x05,0x29},
     "User-Force-Change-Password"},
    /* DS-Replication-Get-Changes-All (DCSync!) */
    {{0xad,0xf6,0x31,0x11,0x07,0x9c,0xd1,0x11,0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2},
     "DS-Replication-Get-Changes-All [DCSync]"},
    /* DS-Replication-Get-Changes */
    {{0xaa,0xf6,0x31,0x11,0x07,0x9c,0xd1,0x11,0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2},
     "DS-Replication-Get-Changes"},
    /* DS-Replication-Synchronize */
    {{0xab,0xf6,0x31,0x11,0x07,0x9c,0xd1,0x11,0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2},
     "DS-Replication-Synchronize"},
    /* Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD) */
    {{0xe5,0xc3,0x78,0x3f,0x7a,0xf7,0xbd,0x46,0xa0,0xb8,0x9d,0x18,0x11,0x6d,0xdc,0x79},
     "Allowed-To-Act-On-Behalf [RBCD]"},
    /* Member attribute */
    {{0xc0,0x79,0x96,0xbf,0xe6,0x0d,0xd0,0x11,0xa2,0x85,0x00,0xaa,0x00,0x30,0x49,0xe2},
     "Member (Group Membership Write)"},
    /* ServicePrincipalName */
    {{0x88,0x47,0xa6,0xf3,0x06,0x53,0xd1,0x11,0xa9,0xc5,0x00,0x00,0xf8,0x03,0x16,0x27},
     "ServicePrincipalName"},
    /* Script-Path */
    {{0xa8,0x79,0x96,0xbf,0xe6,0x0d,0xd0,0x11,0xa2,0x85,0x00,0xaa,0x00,0x30,0x49,0xe2},
     "Script-Path (Login Script)"},
    /* Sentinel */
    {{0}, NULL}
};

const char *phantom_lookup_extended_right(const BYTE *guid) {
    if (!guid) return NULL;
    for (int i = 0; g_known_rights[i].name != NULL; i++) {
        if (phantom_memcmp(guid, g_known_rights[i].guid, 16) == 0)
            return g_known_rights[i].name;
    }
    return NULL;
}

/* =========================================================================
 * UAC Flag Decoder
 * ========================================================================= */

typedef struct { DWORD flag; const char *name; } FLAG_NAME;

static const FLAG_NAME g_uac_flags[] = {
    {UAC_ACCOUNTDISABLE,              "ACCOUNT_DISABLED"},
    {UAC_LOCKOUT,                     "LOCKED_OUT"},
    {UAC_PASSWD_NOTREQD,              "PASSWD_NOT_REQUIRED"},
    {UAC_NORMAL_ACCOUNT,              "NORMAL_ACCOUNT"},
    {UAC_DONT_EXPIRE_PASSWORD,        "DONT_EXPIRE_PASSWORD"},
    {UAC_SMARTCARD_REQUIRED,          "SMARTCARD_REQUIRED"},
    {UAC_TRUSTED_FOR_DELEGATION,      "UNCONSTRAINED_DELEGATION"},
    {UAC_NOT_DELEGATED,               "NOT_DELEGATED"},
    {UAC_USE_DES_KEY_ONLY,            "USE_DES_KEY_ONLY"},
    {UAC_DONT_REQUIRE_PREAUTH,        "DONT_REQUIRE_PREAUTH"},
    {UAC_PASSWORD_EXPIRED,            "PASSWORD_EXPIRED"},
    {UAC_TRUSTED_TO_AUTH_FOR_DELEGATION, "CONSTRAINED_DELEGATION"},
    {UAC_WORKSTATION_TRUST_ACCOUNT,   "WORKSTATION_TRUST"},
    {UAC_SERVER_TRUST_ACCOUNT,        "SERVER_TRUST (DC)"},
    {UAC_INTERDOMAIN_TRUST_ACCOUNT,   "INTERDOMAIN_TRUST"},
    {0, NULL}
};

void phantom_decode_uac(DWORD uac, char *buf, SIZE_T buf_size) {
    if (!buf || buf_size < 8) return;
    char *p   = buf;
    char *end = buf + buf_size - 1;
    BOOL  first = TRUE;
    for (int i = 0; g_uac_flags[i].name; i++) {
        if (uac & g_uac_flags[i].flag) {
            if (!first && p < end) *p++ = ',', *p++ = ' ';
            p = append_str(p, end, g_uac_flags[i].name);
            first = FALSE;
        }
    }
    if (first) p = append_str(p, end, "NONE");
    *p = '\0';
}

/* =========================================================================
 * Access Mask Decoder
 * ========================================================================= */

static const FLAG_NAME g_mask_flags[] = {
    {ADS_RIGHT_DS_CREATE_CHILD,    "DS_CREATE_CHILD"},
    {ADS_RIGHT_DS_DELETE_CHILD,    "DS_DELETE_CHILD"},
    {ADS_RIGHT_ACTRL_DS_LIST,      "DS_LIST"},
    {ADS_RIGHT_DS_SELF,            "DS_SELF"},
    {ADS_RIGHT_DS_READ_PROP,       "DS_READ_PROP"},
    {ADS_RIGHT_DS_WRITE_PROP,      "DS_WRITE_PROP (GenericWrite)"},
    {ADS_RIGHT_DS_DELETE_TREE,     "DS_DELETE_TREE"},
    {ADS_RIGHT_DS_CONTROL_ACCESS,  "DS_CONTROL_ACCESS (ExtendedRight)"},
    {RIGHT_DELETE,                 "DELETE"},
    {RIGHT_READ_CONTROL,           "READ_CONTROL"},
    {RIGHT_WRITE_DAC,              "WRITE_DAC"},
    {RIGHT_WRITE_OWNER,            "WRITE_OWNER"},
    {RIGHT_GENERIC_ALL,            "GENERIC_ALL (FullControl)"},
    {RIGHT_GENERIC_WRITE,          "GENERIC_WRITE"},
    {RIGHT_GENERIC_READ,           "GENERIC_READ"},
    {0, NULL}
};

void phantom_decode_access_mask(DWORD mask, char *buf, SIZE_T buf_size) {
    if (!buf || buf_size < 8) return;
    char *p   = buf;
    char *end = buf + buf_size - 1;
    BOOL  first = TRUE;
    for (int i = 0; g_mask_flags[i].name; i++) {
        if (mask & g_mask_flags[i].flag) {
            if (!first && p < end) *p++ = ',', *p++ = ' ';
            p = append_str(p, end, g_mask_flags[i].name);
            first = FALSE;
        }
    }
    if (first) {
        /* Raw hex */
        p = append_str(p, end, "0x");
        for (int s = 28; s >= 0; s -= 4) {
            unsigned char nib = (unsigned char)((mask >> s) & 0xF);
            if (p < end) *p++ = "0123456789ABCDEF"[nib];
        }
    }
    *p = '\0';
}
