/**
 * @file enum_acl.c
 * @brief PhantomLDAP BOF module — Active Directory DACL Analysis
 *
 * Fetches the nTSecurityDescriptor (binary) of a specific AD object by DN
 * and performs a complete in-process DACL parse without any Windows security
 * API calls (no LookupAccountSid, no ConvertSecurityDescriptorToStringSecurityDescriptor).
 *
 * The module:
 *  1. Searches LDAP_SCOPE_BASE for the target DN and requests the
 *     nTSecurityDescriptor attribute (requires LDAP_SERVER_SD_FLAGS_OID control
 *     or sufficient rights; here we rely on the calling context's Kerberos token).
 *  2. Parses the SELF_RELATIVE SECURITY_DESCRIPTOR binary from the BER value.
 *  3. Iterates all ACEs in the DACL, decodes each one, and classifies it
 *     by interest level (NORMAL / MEDIUM / HIGH / CRITICAL).
 *  4. Prints a structured operator report, highlighting dangerous ACEs with
 *     actionable guidance.
 *
 * Interest classification:
 *   CRITICAL : ForceChangePassword, DS-Replication-Get-Changes-All (DCSync),
 *              RIGHT_GENERIC_ALL on the object
 *   HIGH     : WriteDACL (RIGHT_WRITE_DAC), WriteOwner (RIGHT_WRITE_OWNER),
 *              AllExtendedRights (ADS_RIGHT_DS_CONTROL_ACCESS with null GUID)
 *   MEDIUM   : GenericWrite (ADS_RIGHT_DS_WRITE_PROP), CreateChild,
 *              DS-Replication-Get-Changes, WriteSPN, WriteScriptPath
 *   NORMAL   : Everything else (read, list, etc.)
 *
 * Usage (from CNA bof_pack):
 *   z  target_dn   — Distinguished name of the object to analyse
 *   z  dc_name     — Optional DC hostname (empty = auto-discover)
 *
 * Compilation:
 *   x86_64-w64-mingw32-gcc -o enum_acl.o -c enum_acl.c \
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

#define ACL_SEPARATOR \
    "----------------------------------------------------------------"

/**
 * @brief Statistics counters for a single DACL parse pass.
 */
typedef struct _DACL_STATS {
    DWORD num_interesting;  /**< ACEs classified MEDIUM or above               */
    DWORD num_critical;     /**< ACEs classified CRITICAL                      */
    DWORD total_aces;       /**< Total ACEs iterated                           */
} DACL_STATS;

/* =========================================================================
 * Helpers — no-CRT string utilities
 * ========================================================================= */

/**
 * @brief Return length of a narrow string without CRT strlen.
 */
static SIZE_T acl_strlen(const char *s)
{
    SIZE_T n = 0;
    while (s && s[n]) n++;
    return n;
}

/**
 * @brief Append a literal token to a narrow buffer without strcat.
 *
 * @param buf       Destination (null-terminated)
 * @param buf_size  Total capacity of buf
 * @param tok       Token to append
 */
static void acl_append(char *buf, SIZE_T buf_size, const char *tok)
{
    SIZE_T cur = acl_strlen(buf);
    SIZE_T ti  = 0;
    while (tok && tok[ti] && cur + ti + 1 < buf_size) {
        buf[cur + ti] = tok[ti];
        ti++;
    }
    buf[cur + ti] = '\0';
}

/**
 * @brief Append a comma-separated token only if the buffer is non-empty.
 *
 * @param buf       Destination (null-terminated)
 * @param buf_size  Total capacity of buf
 * @param tok       Token to append
 */
static void acl_append_flag(char *buf, SIZE_T buf_size, const char *tok)
{
    if (buf[0]) {
        acl_append(buf, buf_size, ", ");
    }
    acl_append(buf, buf_size, tok);
}

/**
 * @brief Append a hex DWORD (0xNNNNNNNN) to a buffer.
 *
 * Used for unknown GUIDs and unrecognised access mask bits.
 *
 * @param buf       Destination
 * @param buf_size  Capacity
 * @param val       Value to format
 */
static void acl_append_hex(char *buf, SIZE_T buf_size, DWORD val)
{
    /* Build hex string in reverse without sprintf/CRT. */
    char   tmp[12]; /* "0x" + 8 hex digits + '\0' */
    static const char hex[] = "0123456789ABCDEF";
    int    i;

    tmp[0]  = '0';
    tmp[1]  = 'x';
    tmp[10] = '\0';
    for (i = 0; i < 8; i++) {
        tmp[9 - i] = hex[val & 0xF];
        val >>= 4;
    }
    acl_append(buf, buf_size, tmp);
}

/**
 * @brief Compare two 16-byte GUIDs for equality.
 *
 * @param a  First GUID bytes
 * @param b  Second GUID bytes
 * @return   TRUE if identical
 */
static BOOL guid_eq(const BYTE *a, const BYTE *b)
{
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != b[i]) return FALSE;
    }
    return TRUE;
}

/* =========================================================================
 * Helpers — access mask decoder
 * ========================================================================= */

/**
 * @brief Decode an AD ACCESS_MASK into a human-readable string.
 *
 * Appends named right tokens for each known bit.  Unknown bits are
 * appended as hex literals so no information is lost.
 *
 * @param mask      Raw access mask value
 * @param buf       Output buffer (at least 512 bytes)
 * @param buf_size  Size of buf
 */
static void decode_access_mask(DWORD mask, char *buf, SIZE_T buf_size)
{
    DWORD remaining;
    buf[0] = '\0';

#define EMIT(bit, name) \
    if ((mask) & (bit)) { acl_append_flag(buf, buf_size, (name)); }

    EMIT(RIGHT_GENERIC_ALL,               "GENERIC_ALL")
    EMIT(RIGHT_GENERIC_WRITE,             "GENERIC_WRITE")
    EMIT(RIGHT_GENERIC_READ,              "GENERIC_READ")
    EMIT(RIGHT_GENERIC_EXECUTE,           "GENERIC_EXECUTE")
    EMIT(RIGHT_WRITE_OWNER,               "WRITE_OWNER")
    EMIT(RIGHT_WRITE_DAC,                 "WRITE_DAC")
    EMIT(RIGHT_READ_CONTROL,              "READ_CONTROL")
    EMIT(RIGHT_DELETE,                    "DELETE")
    EMIT(ADS_RIGHT_DS_CONTROL_ACCESS,     "DS_CONTROL_ACCESS")
    EMIT(ADS_RIGHT_DS_CREATE_CHILD,       "DS_CREATE_CHILD")
    EMIT(ADS_RIGHT_DS_DELETE_CHILD,       "DS_DELETE_CHILD")
    EMIT(ADS_RIGHT_DS_LIST_OBJECT,        "DS_LIST_OBJECT")
    EMIT(ADS_RIGHT_DS_DELETE_TREE,        "DS_DELETE_TREE")
    EMIT(ADS_RIGHT_DS_WRITE_PROP,         "DS_WRITE_PROP")
    EMIT(ADS_RIGHT_DS_READ_PROP,          "DS_READ_PROP")
    EMIT(ADS_RIGHT_DS_SELF,               "DS_SELF")
    EMIT(ADS_RIGHT_ACTRL_DS_LIST,         "DS_LIST")
#undef EMIT

    /* Mask out all known bits and report residual. */
    remaining = mask & ~(
        RIGHT_GENERIC_ALL | RIGHT_GENERIC_WRITE | RIGHT_GENERIC_READ |
        RIGHT_GENERIC_EXECUTE | RIGHT_WRITE_OWNER | RIGHT_WRITE_DAC |
        RIGHT_READ_CONTROL | RIGHT_DELETE |
        ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_CREATE_CHILD |
        ADS_RIGHT_DS_DELETE_CHILD | ADS_RIGHT_DS_LIST_OBJECT |
        ADS_RIGHT_DS_DELETE_TREE | ADS_RIGHT_DS_WRITE_PROP |
        ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_DS_SELF | ADS_RIGHT_ACTRL_DS_LIST);

    if (remaining) {
        acl_append_flag(buf, buf_size, "UNKNOWN:");
        acl_append_hex(buf, buf_size, remaining);
    }

    if (!buf[0]) {
        acl_append(buf, buf_size, "(none)");
    }
}

/* =========================================================================
 * Helpers — ACE flag decoder
 * ========================================================================= */

/**
 * @brief Decode ACE inheritance flags into a readable string.
 *
 * @param flags     AceFlags byte from ACE_HEADER
 * @param buf       Output buffer
 * @param buf_size  Buffer capacity
 */
static void decode_ace_flags(BYTE flags, char *buf, SIZE_T buf_size)
{
    buf[0] = '\0';
#define EFLAG(bit, name) \
    if ((flags) & (bit)) { acl_append_flag(buf, buf_size, (name)); }

    EFLAG(OBJECT_INHERIT_ACE,         "OBJECT_INHERIT")
    EFLAG(CONTAINER_INHERIT_ACE,      "CONTAINER_INHERIT")
    EFLAG(NO_PROPAGATE_INHERIT_ACE,   "NO_PROPAGATE_INHERIT")
    EFLAG(INHERIT_ONLY_ACE,           "INHERIT_ONLY")
    EFLAG(INHERITED_ACE,              "INHERITED")
    EFLAG(SUCCESSFUL_ACCESS_ACE_FLAG, "AUDIT_SUCCESS")
    EFLAG(FAILED_ACCESS_ACE_FLAG,     "AUDIT_FAILURE")
#undef EFLAG

    if (!buf[0]) {
        acl_append(buf, buf_size, "NONE");
    }
}

/* =========================================================================
 * Helpers — SID to string conversion
 * ========================================================================= */

/**
 * @brief Convert a raw binary SID to its string representation S-1-5-...
 *
 * Implements the conversion inline to avoid any OS API dependency.
 * The format is: S-<revision>-<authority>-<sub1>-<sub2>-...-<subN>
 *
 * @param sid_data  Pointer to the binary SID (PBYTE)
 * @param out_buf   Output buffer (at least 185 bytes per PHANTOM_ACE_INFO)
 * @param buf_size  Capacity of out_buf
 */
static void sid_to_string_local(const BYTE *sid_data, char *out_buf, SIZE_T buf_size)
{
    const SID *sid = (const SID *)sid_data;
    ULONG      authority;
    int        i;

    out_buf[0] = '\0';

    if (!sid || sid->Revision != 1) {
        acl_append(out_buf, buf_size, "S-?-?");
        return;
    }

    /* Build authority value from the 6-byte big-endian field. */
    authority = ((ULONG)sid->IdentifierAuthority.Value[5]) |
                ((ULONG)sid->IdentifierAuthority.Value[4] << 8)  |
                ((ULONG)sid->IdentifierAuthority.Value[3] << 16) |
                ((ULONG)sid->IdentifierAuthority.Value[2] << 24);

    /* Manual decimal formatting without sprintf. */
    {
        /* Format: "S-1-" then authority, then sub-authorities. */
        char     tmp[12];
        ULONG    v;
        int      pos;

        acl_append(out_buf, buf_size, "S-1-");

        /* Append authority. */
        v = authority; pos = 10; tmp[11] = '\0';
        if (v == 0) { tmp[10] = '0'; pos = 10; }
        else {
            pos = 11;
            while (v > 0 && pos > 0) { tmp[--pos] = (char)('0' + (v % 10)); v /= 10; }
        }
        acl_append(out_buf, buf_size, tmp + pos);

        /* Append each sub-authority. */
        for (i = 0; i < (int)sid->SubAuthorityCount && i < 15; i++) {
            DWORD sa = sid->SubAuthority[i];
            acl_append(out_buf, buf_size, "-");
            pos = 11; tmp[11] = '\0';
            if (sa == 0) { tmp[10] = '0'; pos = 10; }
            else {
                pos = 11;
                while (sa > 0 && pos > 0) { tmp[--pos] = (char)('0' + (sa % 10)); sa /= 10; }
            }
            acl_append(out_buf, buf_size, tmp + pos);
        }
    }
}

/* =========================================================================
 * ACE classification logic
 * ========================================================================= */

/**
 * @brief Classify interest level from ACE type, mask, and optional GUID.
 *
 * Also fills info->right_name with a human-readable label when relevant.
 *
 * @param mask          Raw ACCESS_MASK
 * @param ace_type      ACE_HEADER.AceType
 * @param is_object_ace TRUE if an object ACE (has GUID)
 * @param object_guid   16-byte GUID bytes (may be NULL for non-object ACEs)
 * @param info          Output: right_name and is_dangerous are set here
 * @return              Classified ACE_INTEREST_LEVEL
 */
static ACE_INTEREST_LEVEL classify_ace(
    DWORD            mask,
    BYTE             ace_type,
    BOOL             is_object_ace,
    const BYTE      *object_guid,
    PHANTOM_ACE_INFO *info)
{
    /* Static GUID bytes for well-known extended rights. */
    static const BYTE GUID_FORCE_CHANGE_PWD[16] = {
        0x70,0x95,0x29,0x00, 0x6d,0x24, 0xd0,0x11,
        0xa7,0x68, 0x00,0xaa,0x00,0x6e,0x05,0x29
    };
    static const BYTE GUID_DCSYNC_ALL[16] = {
        0xad,0xf6,0x31,0x11, 0x07,0x9c, 0xd1,0x11,
        0xf7,0x9f, 0x00,0xc0,0x4f,0xc2,0xdc,0xd2
    };
    static const BYTE GUID_DCSYNC_CHANGES[16] = {
        0xaa,0xf6,0x31,0x11, 0x07,0x9c, 0xd1,0x11,
        0xf7,0x9f, 0x00,0xc0,0x4f,0xc2,0xdc,0xd2
    };
    static const BYTE GUID_DCSYNC_SYNC[16] = {
        0xab,0xf6,0x31,0x11, 0x07,0x9c, 0xd1,0x11,
        0xf7,0x9f, 0x00,0xc0,0x4f,0xc2,0xdc,0xd2
    };
    static const BYTE GUID_RBCD[16] = {
        0xe5,0xc3,0x78,0x3f, 0x7a,0xf7, 0xbd,0x46,
        0xa0,0xb8, 0x9d,0x18,0x11,0x6d,0xdc,0x79
    };
    static const BYTE GUID_SPN[16] = {
        0x88,0x47,0xa6,0xf3, 0x06,0x53, 0xd1,0x11,
        0xa9,0xc5, 0x00,0x00,0xf8,0x03,0x16,0x27
    };
    static const BYTE GUID_SCRIPT_PATH_ATTR[16] = {
        0xa8,0x79,0x96,0xbf, 0xe6,0x0d, 0xd0,0x11,
        0xa2,0x85, 0x00,0xaa,0x00,0x30,0x49,0xe2
    };

    /* Deny ACEs reduce rights — interesting if they are broad denials. */
    if (ace_type == ACCESS_DENIED_ACE_TYPE || ace_type == ACCESS_DENIED_OBJECT_ACE_TYPE) {
        /* DENY on GenericAll means explicit block — note but don't escalate. */
        info->is_dangerous = FALSE;
        return ACE_INTEREST_NORMAL;
    }

    /* ------------------------------------------------------------------
     * CRITICAL checks
     * ------------------------------------------------------------------ */

    /* GENERIC_ALL on the object = full control — highest risk. */
    if (mask & RIGHT_GENERIC_ALL) {
        acl_append(info->right_name, sizeof(info->right_name), "GENERIC_ALL (Full Control)");
        info->is_dangerous = TRUE;
        return ACE_INTEREST_CRITICAL;
    }

    /* Object ACE extended rights classification. */
    if (is_object_ace && object_guid) {
        if (guid_eq(object_guid, GUID_FORCE_CHANGE_PWD)) {
            acl_append(info->right_name, sizeof(info->right_name),
                       "ForceChangePassword (password reset without current password)");
            info->is_dangerous = TRUE;
            return ACE_INTEREST_CRITICAL;
        }
        if (guid_eq(object_guid, GUID_DCSYNC_ALL)) {
            acl_append(info->right_name, sizeof(info->right_name),
                       "DS-Replication-Get-Changes-All (DCSync - replicates secrets!)");
            info->is_dangerous = TRUE;
            return ACE_INTEREST_CRITICAL;
        }
        if (guid_eq(object_guid, GUID_RBCD)) {
            acl_append(info->right_name, sizeof(info->right_name),
                       "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD write)");
            info->is_dangerous = TRUE;
            return ACE_INTEREST_CRITICAL;
        }
    }

    /* AllExtendedRights: DS_CONTROL_ACCESS without a specific GUID object constraint. */
    if ((mask & ADS_RIGHT_DS_CONTROL_ACCESS) && is_object_ace) {
        /* Check if GUID is all-zeros (meaning AllExtendedRights). */
        if (object_guid) {
            BOOL all_zero = TRUE;
            int  zi;
            for (zi = 0; zi < 16; zi++) {
                if (object_guid[zi] != 0) { all_zero = FALSE; break; }
            }
            if (all_zero) {
                acl_append(info->right_name, sizeof(info->right_name),
                           "AllExtendedRights (includes ForceChangePassword, DCSync, etc.)");
                info->is_dangerous = TRUE;
                return ACE_INTEREST_CRITICAL;
            }
        }
    }

    /* ------------------------------------------------------------------
     * HIGH checks
     * ------------------------------------------------------------------ */

    if (mask & RIGHT_WRITE_DAC) {
        acl_append(info->right_name, sizeof(info->right_name), "WriteDACL");
        info->is_dangerous = TRUE;
        if (mask & RIGHT_WRITE_OWNER) {
            acl_append(info->right_name, sizeof(info->right_name), " + WriteOwner");
        }
        return ACE_INTEREST_HIGH;
    }

    if (mask & RIGHT_WRITE_OWNER) {
        acl_append(info->right_name, sizeof(info->right_name), "WriteOwner");
        info->is_dangerous = TRUE;
        return ACE_INTEREST_HIGH;
    }

    if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) {
        acl_append(info->right_name, sizeof(info->right_name), "DS_CONTROL_ACCESS (ExtendedRight)");
        info->is_dangerous = TRUE;
        return ACE_INTEREST_HIGH;
    }

    /* ------------------------------------------------------------------
     * MEDIUM checks
     * ------------------------------------------------------------------ */

    if (mask & ADS_RIGHT_DS_WRITE_PROP) {
        acl_append(info->right_name, sizeof(info->right_name), "DS_WRITE_PROP (GenericWrite)");
        /* Specialise if we have a property GUID. */
        if (is_object_ace && object_guid) {
            if (guid_eq(object_guid, GUID_SPN)) {
                acl_append(info->right_name, sizeof(info->right_name), " -> WriteSPN (targeted Kerberoast!)");
                info->is_dangerous = TRUE;
                return ACE_INTEREST_HIGH;
            }
            if (guid_eq(object_guid, GUID_SCRIPT_PATH_ATTR)) {
                acl_append(info->right_name, sizeof(info->right_name), " -> WriteScriptPath (logon script persistence!)");
                info->is_dangerous = TRUE;
                return ACE_INTEREST_HIGH;
            }
        }
        info->is_dangerous = FALSE;
        return ACE_INTEREST_MEDIUM;
    }

    if (mask & ADS_RIGHT_DS_CREATE_CHILD) {
        acl_append(info->right_name, sizeof(info->right_name), "DS_CREATE_CHILD");
        return ACE_INTEREST_MEDIUM;
    }

    /* DCSync partial right (only Get-Changes without Get-Changes-All). */
    if (is_object_ace && object_guid) {
        if (guid_eq(object_guid, GUID_DCSYNC_CHANGES)) {
            acl_append(info->right_name, sizeof(info->right_name),
                       "DS-Replication-Get-Changes (partial DCSync -- needs Get-Changes-All too)");
            return ACE_INTEREST_MEDIUM;
        }
        if (guid_eq(object_guid, GUID_DCSYNC_SYNC)) {
            acl_append(info->right_name, sizeof(info->right_name),
                       "DS-Replication-Synchronize");
            return ACE_INTEREST_MEDIUM;
        }
    }

    return ACE_INTEREST_NORMAL;
}

/* =========================================================================
 * ACE parser
 * ========================================================================= */

/**
 * @brief Parse a single ACE and populate a PHANTOM_ACE_INFO structure.
 *
 * Handles both standard ACEs (ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE) and
 * object ACEs (ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE).
 *
 * For object ACEs, the optional ObjectType GUID is extracted when the
 * ACE_OBJECT_TYPE_PRESENT flag is set in the Flags field.
 *
 * @param ace_hdr   Pointer to the ACE_HEADER at the start of this ACE
 * @param info      Output structure to populate
 * @return          TRUE on success; FALSE if the ACE type is unrecognised
 */
static BOOL parse_ace(const PACE_HEADER ace_hdr, PHANTOM_ACE_INFO *info)
{
    DWORD       mask        = 0;
    const BYTE *sid_data    = NULL;
    BOOL        is_obj_ace  = FALSE;
    BYTE        obj_guid[16];
    int         i;

    /* Zero object GUID (used as all-zeros sentinel for AllExtendedRights). */
    for (i = 0; i < 16; i++) obj_guid[i] = 0;

    /* ------------------------------------------------------------------ */
    /* Determine ACE type and set type string.                              */
    /* ------------------------------------------------------------------ */
    switch (ace_hdr->AceType) {

    case ACCESS_ALLOWED_ACE_TYPE: {
        const ACCESS_ALLOWED_ACE *ace = (const ACCESS_ALLOWED_ACE *)ace_hdr;
        mask     = ace->Mask;
        sid_data = (const BYTE *)&ace->SidStart;
        acl_append(info->ace_type_str, sizeof(info->ace_type_str), "ALLOW");
        break;
    }

    case ACCESS_DENIED_ACE_TYPE: {
        const ACCESS_DENIED_ACE *ace = (const ACCESS_DENIED_ACE *)ace_hdr;
        mask     = ace->Mask;
        sid_data = (const BYTE *)&ace->SidStart;
        acl_append(info->ace_type_str, sizeof(info->ace_type_str), "DENY");
        break;
    }

    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE: {
        const ACCESS_ALLOWED_OBJECT_ACE *obj = (const ACCESS_ALLOWED_OBJECT_ACE *)ace_hdr;
        const BYTE *p = (const BYTE *)obj;

        mask        = obj->Mask;
        is_obj_ace  = TRUE;
        info->is_object_ace = TRUE;

        acl_append(info->ace_type_str, sizeof(info->ace_type_str),
                   (ace_hdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) ? "ALLOW_OBJ" : "DENY_OBJ");

        /* Flags field controls which optional GUID fields are present.
         * Layout after Mask + Flags:
         *   [optional ObjectType GUID   — 16 bytes if ACE_OBJECT_TYPE_PRESENT]
         *   [optional InheritedObjType  — 16 bytes if ACE_INHERITED_OBJECT_TYPE_PRESENT]
         *   [SID — variable]
         */
        p += sizeof(ACE_HEADER) + sizeof(DWORD) /* Mask */ + sizeof(DWORD) /* Flags */;

        if (obj->Flags & ACE_OBJECT_TYPE_PRESENT) {
            /* ObjectType GUID present — copy it and advance pointer. */
            for (i = 0; i < 16; i++) obj_guid[i] = p[i];
            /* Format GUID string for output. */
            phantom_guid_to_string(obj_guid,
                                   info->object_type_guid,
                                   sizeof(info->object_type_guid));
            p += 16;
        }

        if (obj->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            /* Skip the InheritedObjectType GUID — we don't display it. */
            p += 16;
        }

        sid_data = p;
        break;
    }

    default:
        /* Unknown or SACL audit ACE type — skip silently. */
        return FALSE;
    }

    /* ------------------------------------------------------------------ */
    /* Convert the SID to string form.                                      */
    /* ------------------------------------------------------------------ */
    if (sid_data) {
        sid_to_string_local(sid_data, info->sid_str, sizeof(info->sid_str));
        /* Use the shared utility to attempt a name lookup. */
        phantom_sid_to_string(
            sid_data,
            sizeof(SID) + (((const SID *)sid_data)->SubAuthorityCount) * sizeof(DWORD),
            info->sid_str,
            sizeof(info->sid_str));
    }

    /* ------------------------------------------------------------------ */
    /* Decode the access mask.                                              */
    /* ------------------------------------------------------------------ */
    info->raw_mask = mask;
    decode_access_mask(mask, info->access_mask_str, sizeof(info->access_mask_str));

    /* ------------------------------------------------------------------ */
    /* Decode ACE inheritance flags.                                        */
    /* ------------------------------------------------------------------ */
    info->ace_flags = ace_hdr->AceFlags;

    /* ------------------------------------------------------------------ */
    /* Also attempt named extended right lookup via shared utility.         */
    /* ------------------------------------------------------------------ */
    if (is_obj_ace) {
        const char *known = phantom_lookup_extended_right(obj_guid);
        if (known && !info->right_name[0]) {
            acl_append(info->right_name, sizeof(info->right_name), known);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Classify the interest level.                                         */
    /* ------------------------------------------------------------------ */
    info->interest = classify_ace(mask, ace_hdr->AceType, is_obj_ace,
                                  is_obj_ace ? obj_guid : NULL, info);

    return TRUE;
}

/* =========================================================================
 * Output — single ACE
 * ========================================================================= */

/**
 * @brief Emit a formatted report line for one PHANTOM_ACE_INFO entry.
 *
 * Only ACEs with interest level >= MEDIUM are printed by default; all ACEs
 * are counted regardless.
 *
 * @param info          Decoded ACE info (read-only)
 * @param ace_num       1-based ACE index within the DACL
 */
static void print_ace(const PHANTOM_ACE_INFO *info, DWORD ace_num)
{
    const char *level_tag;
    char        flags_str[128];

    switch (info->interest) {
    case ACE_INTEREST_CRITICAL: level_tag = "[CRITICAL]"; break;
    case ACE_INTEREST_HIGH:     level_tag = "[HIGH]    "; break;
    case ACE_INTEREST_MEDIUM:   level_tag = "[MEDIUM]  "; break;
    default:                    level_tag = "[NORMAL]  "; break;
    }

    decode_ace_flags(info->ace_flags, flags_str, sizeof(flags_str));

    BeaconPrintf(CALLBACK_OUTPUT,
        "    %s %s :: %s\n"
        "               Type   : %s\n"
        "               Mask   : %s\n"
        "               Flags  : %s\n",
        level_tag,
        info->ace_type_str,
        info->sid_str[0] ? info->sid_str : "(unknown SID)",
        info->ace_type_str,
        info->access_mask_str[0] ? info->access_mask_str : "(empty)",
        flags_str);

    if (info->is_object_ace && info->object_type_guid[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "               ObjGUID: %s\n",
            info->object_type_guid);
    }

    if (info->right_name[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "               Right  : %s\n",
            info->right_name);
    }

    if (info->interest == ACE_INTEREST_CRITICAL) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "               [!!!] CRITICAL — directly exploitable!\n");
    } else if (info->interest == ACE_INTEREST_HIGH) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "               [!]   HIGH RISK — may lead to privilege escalation.\n");
    }

    (void)ace_num; /* Suppress unused parameter warning — kept for future ref. */
}

/* =========================================================================
 * Core SD parser
 * ========================================================================= */

/**
 * @brief Parse a SELF_RELATIVE SECURITY_DESCRIPTOR binary blob and print
 *        all interesting ACEs from its DACL.
 *
 * The nTSecurityDescriptor returned by LDAP is always in self-relative format
 * (SE_SELF_RELATIVE bit set in the Control field).  Offsets within the blob
 * are byte offsets from the start of the blob, NOT absolute pointers.
 *
 * @param ctx       Active PHANTOM_CONTEXT (for BeaconPrintf context)
 * @param sd_bytes  Raw SD binary data from LDAP BER value
 * @param sd_len    Length of sd_bytes
 * @param target_dn The DN of the object (for output header)
 */
static void parse_security_descriptor(
    PPHANTOM_CONTEXT ctx,
    const BYTE      *sd_bytes,
    DWORD            sd_len,
    const char      *target_dn)
{
    /*
     * Self-relative SECURITY_DESCRIPTOR layout (documented in MS-DTYP §2.4.6):
     *
     *   Offset  Size  Field
     *   0       1     Revision  (always 1)
     *   1       1     Sbz1
     *   2       2     Control   (flags: SE_DACL_PRESENT etc.)
     *   4       4     OffsetOwner  (offset of owner SID, 0 = absent)
     *   8       4     OffsetGroup  (offset of group SID, 0 = absent)
     *   12      4     OffsetSacl   (offset of SACL, 0 = absent)
     *   16      4     OffsetDacl   (offset of DACL, 0 = absent)
     *
     * The Control word uses SE_SELF_RELATIVE (0x8000) when self-relative.
     * SE_DACL_PRESENT (0x0004) indicates a DACL is present.
     */

    WORD  control;
    DWORD dacl_offset;
    PACL  dacl;
    WORD  ace_count;
    DACL_STATS stats;
    PBYTE      ace_ptr;
    WORD       ace_idx;
    DWORD      interesting_threshold = ACE_INTEREST_MEDIUM;

    /* Phantom_ace_info allocated on heap to keep stack usage low. */
    PHANTOM_ACE_INFO *ace_info = NULL;

    (void)ctx; /* ctx kept for future use (e.g., SID resolution). */

    /* ------------------------------------------------------------------ */
    /* 1. Validate minimum size.                                            */
    /* ------------------------------------------------------------------ */
    if (!sd_bytes || sd_len < 20) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: SD too small (%lu bytes) to be valid.\n",
            (unsigned long)sd_len);
        return;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Read Control flags and check SE_DACL_PRESENT.                    */
    /* ------------------------------------------------------------------ */
    /* Control is at offset 2, little-endian WORD. */
    control = (WORD)sd_bytes[2] | ((WORD)sd_bytes[3] << 8);

    if (!(control & SE_DACL_PRESENT)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] No DACL present (SE_DACL_PRESENT not set). "
            "Object is likely fully accessible (NULL DACL) or inherits from parent.\n");
        return;
    }

    /* ------------------------------------------------------------------ */
    /* 3. Get DACL offset (at byte offset 16, little-endian DWORD).        */
    /* ------------------------------------------------------------------ */
    dacl_offset = (DWORD)sd_bytes[16]        |
                  ((DWORD)sd_bytes[17] << 8)  |
                  ((DWORD)sd_bytes[18] << 16) |
                  ((DWORD)sd_bytes[19] << 24);

    if (dacl_offset == 0 || dacl_offset + sizeof(ACL) > sd_len) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: DACL offset 0x%lX is out of bounds (SD len=%lu).\n",
            (unsigned long)dacl_offset, (unsigned long)sd_len);
        return;
    }

    dacl = (PACL)(sd_bytes + dacl_offset);

    /* ------------------------------------------------------------------ */
    /* 4. Validate ACL header.                                             */
    /* ------------------------------------------------------------------ */
    ace_count = dacl->AceCount;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] DACL Analysis: %s\n"
        "    SD Size  : %lu bytes  |  Control: 0x%04X  |  ACE Count: %u\n"
        "    %s\n",
        target_dn,
        (unsigned long)sd_len,
        (unsigned)control,
        (unsigned)ace_count,
        ACL_SEPARATOR);

    if (ace_count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] DACL is empty (0 ACEs). Object has no explicit permissions.\n");
        return;
    }

    /* ------------------------------------------------------------------ */
    /* 5. Allocate ACE info buffer.                                         */
    /* ------------------------------------------------------------------ */
    PHANTOM_ALLOC_OR_CLEANUP(ace_info, sizeof(PHANTOM_ACE_INFO), sd_parse_cleanup);

    /* ------------------------------------------------------------------ */
    /* 6. Iterate ACEs.                                                     */
    /* ------------------------------------------------------------------ */
    {
        PBYTE p = (PBYTE)dacl;
        p = (PBYTE)dacl + sizeof(ACL);  /* First ACE immediately follows ACL header. */

        /* Zero stats. */
        stats.num_interesting = 0;
        stats.num_critical    = 0;
        stats.total_aces      = 0;

        for (ace_idx = 0; ace_idx < ace_count; ace_idx++) {
            PACE_HEADER ace_hdr;
            BOOL        parsed;

            /* Bounds check: ensure the ACE_HEADER is within the SD buffer. */
            if ((DWORD)((PBYTE)p - sd_bytes) + sizeof(ACE_HEADER) > sd_len) {
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] enum_acl: ACE #%u overflows SD buffer at offset 0x%lX. Stopping.\n",
                    (unsigned)ace_idx,
                    (unsigned long)((PBYTE)p - sd_bytes));
                break;
            }

            ace_hdr = (PACE_HEADER)p;

            /* Additional bounds check using AceSize. */
            if (ace_hdr->AceSize < sizeof(ACE_HEADER) ||
                (DWORD)((PBYTE)p - sd_bytes) + ace_hdr->AceSize > sd_len) {
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] enum_acl: ACE #%u has invalid AceSize=%u. Stopping.\n",
                    (unsigned)ace_idx, (unsigned)ace_hdr->AceSize);
                break;
            }

            /* Zero the ace_info structure for this iteration. */
            {
                PBYTE  zp = (PBYTE)ace_info;
                SIZE_T zs = sizeof(PHANTOM_ACE_INFO);
                while (zs--) { *zp++ = 0; }
            }

            parsed = parse_ace(ace_hdr, ace_info);
            stats.total_aces++;

            if (parsed) {
                if (ace_info->interest >= (ACE_INTEREST_LEVEL)interesting_threshold) {
                    stats.num_interesting++;
                }
                if (ace_info->interest == ACE_INTEREST_CRITICAL) {
                    stats.num_critical++;
                }
                /* Print ACEs at MEDIUM severity or above. */
                if (ace_info->interest >= (ACE_INTEREST_LEVEL)ACE_INTEREST_MEDIUM) {
                    print_ace(ace_info, ace_idx + 1);
                }
            }

            /* Advance to the next ACE. */
            p += ace_hdr->AceSize;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 7. Summary.                                                          */
    /* ------------------------------------------------------------------ */
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n    %s\n"
        "    Summary: Total ACEs: %lu | Interesting (>=MEDIUM): %lu | Critical: %lu\n",
        ACL_SEPARATOR,
        (unsigned long)stats.total_aces,
        (unsigned long)stats.num_interesting,
        (unsigned long)stats.num_critical);

    if (stats.num_critical > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!!!] %lu CRITICAL ACE(s) found -- immediate exploitation may be possible!\n",
            (unsigned long)stats.num_critical);
    } else if (stats.num_interesting > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [!] %lu interesting ACE(s) found -- review output above.\n",
            (unsigned long)stats.num_interesting);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [*] No high-severity ACEs detected from this context.\n"
            "        Note: Access to read nTSecurityDescriptor may have been denied for some ACEs.\n");
    }

sd_parse_cleanup:
    PHANTOM_FREE(ace_info);
}

/* =========================================================================
 * LDAP callback
 * ========================================================================= */

/**
 * @brief Paged-search callback — processes results from the SCOPE_BASE query.
 *
 * Since we are searching by DN at SCOPE_BASE, there should be exactly one
 * result page with one entry.
 *
 * @param ctx       Active PHANTOM_CONTEXT
 * @param message   LDAPMessage result chain for this page
 * @param user_data Pointer to the target_dn narrow string (const char *)
 * @return          TRUE to continue (no-op: SCOPE_BASE returns one page)
 */
static BOOL acl_callback(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     message,
    PVOID            user_data)
{
    const char  *target_dn = (const char *)user_data;
    PLDAPMessage entry;
    PLDAP_BERVAL *bv_arr   = NULL;

    if (!message) return FALSE;

    entry = ctx->api.ldap_first_entry(ctx->ldap_handle, message);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: No entries returned. The DN may not exist or\n"
            "    you may lack rights to read nTSecurityDescriptor.\n");
        return TRUE;
    }

    /* Retrieve binary nTSecurityDescriptor. */
    bv_arr = ctx->api.ldap_get_values_len(ctx->ldap_handle, entry,
                                           ATTR_NT_SECURITY_DESC);
    if (!bv_arr || !bv_arr[0] || bv_arr[0]->bv_len == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: nTSecurityDescriptor attribute is empty or inaccessible.\n"
            "    Ensure your context has ReadProperty rights on the object.\n");
        goto cb_cleanup;
    }

    parse_security_descriptor(
        ctx,
        (const BYTE *)bv_arr[0]->bv_val,
        bv_arr[0]->bv_len,
        target_dn ? target_dn : "(unknown DN)");

cb_cleanup:
    if (bv_arr) ctx->api.ldap_value_free_len(bv_arr);
    return TRUE;
}

/* =========================================================================
 * BOF entry point
 * ========================================================================= */

/**
 * @brief BOF entry point for DACL analysis.
 *
 * Argument buffer (bof_pack):
 *   [z]  target_dn   — Distinguished name of the object to analyse (required)
 *   [z]  dc_name     — Optional DC hostname (empty = auto-discover)
 *
 * @param args  Raw BOF argument buffer
 * @param alen  Buffer length in bytes
 */
void go(char *args, int alen)
{
    datap         parser;
    char         *target_dn_a = NULL;
    char         *dc_name_a   = NULL;
    int           str_sz      = 0;
    PHANTOM_CONTEXT ctx;
    WCHAR         target_dn_w[PHANTOM_MAX_DN_LEN];
    DWORD         rc = 0;
    BOOL          ok = FALSE;

    /* nTSecurityDescriptor only — no other attributes needed. */
    PWSTR attrs[] = {
        ATTR_NT_SECURITY_DESC,
        NULL
    };

    /* Zero-init stack structures. */
    {
        PBYTE p = (PBYTE)&ctx; SIZE_T s = sizeof(ctx); while (s--) { *p++ = 0; }
    }
    {
        PBYTE p = (PBYTE)target_dn_w; SIZE_T s = sizeof(target_dn_w); while (s--) { *p++ = 0; }
    }

    /* ------------------------------------------------------------------ */
    /* 1. Parse arguments.                                                  */
    /* ------------------------------------------------------------------ */
    BeaconDataParse(&parser, args, alen);

    target_dn_a = BeaconDataExtract(&parser, &str_sz);
    if (!target_dn_a || !target_dn_a[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: target_dn argument is required. "
            "Usage: enum_acl <dn> [dc_name]\n");
        return;
    }

    dc_name_a = BeaconDataExtract(&parser, &str_sz);

    /* ------------------------------------------------------------------ */
    /* 2. Banner.                                                           */
    /* ------------------------------------------------------------------ */
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] PhantomLDAP :: DACL Analyser v" PHANTOM_VERSION_STR "\n"
        "    Target    : %s\n"
        "    DC target : %s\n"
        "    %s\n",
        target_dn_a,
        (dc_name_a && dc_name_a[0]) ? dc_name_a : "(auto-discover)",
        ACL_SEPARATOR);

    /* ------------------------------------------------------------------ */
    /* 3. LDAP init.                                                        */
    /* ------------------------------------------------------------------ */
    {
        WCHAR dc_wide[256];
        { PBYTE p = (PBYTE)dc_wide; SIZE_T s = sizeof(dc_wide); while (s--) { *p++ = 0; } }
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
            "[!] enum_acl: phantom_ldap_init failed. "
            "Verify DC reachability and Kerberos ticket.\n");
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Convert target DN to wide string.                                 */
    /* ------------------------------------------------------------------ */
    phantom_str_to_wstr(target_dn_a, target_dn_w, PHANTOM_MAX_DN_LEN);

    /* ------------------------------------------------------------------ */
    /* 5. Execute SCOPE_BASE search for the specific object.                */
    /* ------------------------------------------------------------------ */
    rc = phantom_ldap_paged_search(
        &ctx,
        target_dn_w,            /* base = the target object DN itself */
        LDAP_SCOPE_BASE,        /* base search — single object        */
        L"(objectClass=*)",     /* trivially true filter              */
        attrs,
        acl_callback,
        (PVOID)target_dn_a      /* pass the DN string for output      */
    );

    if (rc != LDAP_SUCCESS && rc != LDAP_NO_RESULTS_RETURNED) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] enum_acl: LDAP search error 0x%02lX.\n",
            (unsigned long)rc);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "    %s\n\n",
        ACL_SEPARATOR);

cleanup:
    phantom_ldap_cleanup(&ctx);
}
