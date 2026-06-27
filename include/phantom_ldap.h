/**
 * @file phantom_ldap.h
 * @brief Core context structures, constants, and shared definitions for
 *        the PhantomLDAP BOF suite.
 *
 * This header is included by all BOF modules and defines:
 *   - Runtime context (PHANTOM_CONTEXT) passed between functions
 *   - ACL/DACL analysis result structures
 *   - AD object attribute extraction structures
 *   - Module-specific configuration constants
 *   - Shared AD GUID constants for DACL interpretation
 *   - Well-known SID string representations
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#ifndef PHANTOM_LDAP_MAIN_H
#define PHANTOM_LDAP_MAIN_H

#include "win_types.h"
#include "ldap_types.h"
#include "dynamic_resolve.h"
#include "beacon.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Version & Metadata
 * ========================================================================= */

#define PHANTOM_VERSION_MAJOR   1
#define PHANTOM_VERSION_MINOR   0
#define PHANTOM_VERSION_PATCH   0
#define PHANTOM_VERSION_STR     "1.0.0"
#define PHANTOM_PROJECT_NAME    "PhantomLDAP"
#define PHANTOM_BUILD_DATE      __DATE__

/* =========================================================================
 * Operational Constants
 * ========================================================================= */

/** Default LDAP paging size (objects per page). RFC 2696 recommends <= 1000. */
#define PHANTOM_DEFAULT_PAGE_SIZE       500

/** Maximum DN length (characters). Distinguished names can be long in deep OUs. */
#define PHANTOM_MAX_DN_LEN              1024

/** Maximum string attribute value length (characters). */
#define PHANTOM_MAX_ATTR_LEN            512

/** Maximum number of values per multi-valued attribute to process. */
#define PHANTOM_MAX_ATTR_VALUES         64

/** Maximum SPN entries per account to display. */
#define PHANTOM_MAX_SPN_DISPLAY         16

/** LDAP search timeout in seconds (0 = no timeout — not recommended). */
#define PHANTOM_SEARCH_TIMEOUT_SEC      30

/** Maximum number of ACEs to parse from a single DACL. */
#define PHANTOM_MAX_ACE_COUNT           128

/** Width of the output separator line. */
#define PHANTOM_SEPARATOR_WIDTH         72

/* =========================================================================
 * LDAP Filter Strings
 *
 * All filters are pre-defined as constants for consistency and to allow
 * easy modification without touching module logic.
 * ========================================================================= */

#define FILTER_ADMIN_ACCOUNTS   L"(&(objectCategory=person)(objectClass=user)(adminCount=1))"
#define FILTER_SPN_ACCOUNTS     L"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
#define FILTER_ASREP_ACCOUNTS   L"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
#define FILTER_COMPUTERS        L"(objectClass=computer)"
#define FILTER_DOMAIN_TRUSTS    L"(objectClass=trustedDomain)"
#define FILTER_GPO_OBJECTS      L"(objectClass=groupPolicyContainer)"
#define FILTER_ACL_TARGET       L"(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)(objectClass=domain))"

/* =========================================================================
 * LDAP Attribute Name Constants
 * ========================================================================= */

/* User/group attributes */
#define ATTR_SAM_ACCOUNT_NAME       L"sAMAccountName"
#define ATTR_DISTINGUISHED_NAME     L"distinguishedName"
#define ATTR_DISPLAY_NAME           L"displayName"
#define ATTR_MEMBER_OF              L"memberOf"
#define ATTR_SPN                    L"servicePrincipalName"
#define ATTR_USER_ACCOUNT_CTRL      L"userAccountControl"
#define ATTR_PWD_LAST_SET           L"pwdLastSet"
#define ATTR_LAST_LOGON             L"lastLogon"
#define ATTR_LAST_LOGON_TIMESTAMP   L"lastLogonTimestamp"
#define ATTR_ADMIN_COUNT            L"adminCount"
#define ATTR_OBJECT_SID             L"objectSid"
#define ATTR_OBJECT_CLASS           L"objectClass"
#define ATTR_OBJECT_CATEGORY        L"objectCategory"
#define ATTR_DESCRIPTION            L"description"

/* Security descriptor */
#define ATTR_NT_SECURITY_DESC       L"nTSecurityDescriptor"

/* Computer attributes */
#define ATTR_DNS_HOST_NAME          L"dNSHostName"
#define ATTR_OS                     L"operatingSystem"
#define ATTR_OS_VERSION             L"operatingSystemVersion"
#define ATTR_OS_SP                  L"operatingSystemServicePack"

/* Trust attributes */
#define ATTR_TRUST_PARTNER          L"trustPartner"
#define ATTR_TRUST_TYPE             L"trustType"
#define ATTR_TRUST_DIRECTION        L"trustDirection"
#define ATTR_TRUST_ATTRIBUTES       L"trustAttributes"
#define ATTR_FLAT_NAME              L"flatName"

/* GPO attributes */
#define ATTR_GPO_DISPLAY_NAME       L"displayName"
#define ATTR_GPO_FILE_SYS_PATH      L"gPCFileSysPath"
#define ATTR_GPO_VERSION            L"versionNumber"
#define ATTR_GPO_FUNC_VERSION       L"gPCFunctionalityVersion"

/* =========================================================================
 * userAccountControl Flags
 * ========================================================================= */

#define UAC_ACCOUNTDISABLE              0x00000002
#define UAC_HOMEDIR_REQUIRED            0x00000008
#define UAC_LOCKOUT                     0x00000010
#define UAC_PASSWD_NOTREQD              0x00000020
#define UAC_PASSWD_CANT_CHANGE          0x00000040
#define UAC_ENCRYPTED_TEXT_PWD_ALLOWED  0x00000080
#define UAC_NORMAL_ACCOUNT              0x00000200
#define UAC_INTERDOMAIN_TRUST_ACCOUNT   0x00000800
#define UAC_WORKSTATION_TRUST_ACCOUNT   0x00001000
#define UAC_SERVER_TRUST_ACCOUNT        0x00002000
#define UAC_DONT_EXPIRE_PASSWORD        0x00010000
#define UAC_SMARTCARD_REQUIRED          0x00040000
#define UAC_TRUSTED_FOR_DELEGATION      0x00080000      /* Unconstrained delegation */
#define UAC_NOT_DELEGATED               0x00100000
#define UAC_USE_DES_KEY_ONLY            0x00200000
#define UAC_DONT_REQUIRE_PREAUTH        0x00400000      /* AS-REP Roasting target */
#define UAC_PASSWORD_EXPIRED            0x00800000
#define UAC_TRUSTED_TO_AUTH_FOR_DELEGATION 0x01000000  /* Constrained delegation (S4U2Proxy) */
#define UAC_NO_AUTH_DATA_REQUIRED       0x02000000
#define UAC_PARTIAL_SECRETS_ACCOUNT     0x04000000      /* RODC-related */

/* =========================================================================
 * Trust Type Definitions (trustType attribute values)
 * ========================================================================= */

#define TRUST_TYPE_DOWNLEVEL        1   /**< Windows NT 4.0 domain              */
#define TRUST_TYPE_UPLEVEL          2   /**< Active Directory domain             */
#define TRUST_TYPE_MIT              3   /**< MIT Kerberos realm                  */
#define TRUST_TYPE_DCE              4   /**< DCE realm                           */

/* trustDirection flags */
#define TRUST_DIRECTION_DISABLED    0
#define TRUST_DIRECTION_INBOUND     1   /**< Remote domain trusts this domain    */
#define TRUST_DIRECTION_OUTBOUND    2   /**< This domain trusts remote domain    */
#define TRUST_DIRECTION_BIDIRECT    3   /**< Bidirectional trust                 */

/* trustAttributes flags */
#define TRUST_ATTR_NON_TRANSITIVE   0x00000001
#define TRUST_ATTR_UPLEVEL_ONLY     0x00000002
#define TRUST_ATTR_QUARANTINED      0x00000004  /**< SID filtering enabled (quarantined) */
#define TRUST_ATTR_FOREST_TRANSITIVE 0x00000008 /**< Forest-wide trust           */
#define TRUST_ATTR_CROSS_ORG        0x00000010  /**< Cross-org (selective auth)  */
#define TRUST_ATTR_WITHIN_FOREST    0x00000020  /**< Parent/child trust          */
#define TRUST_ATTR_TREAT_AS_EXTERNAL 0x00000040
#define TRUST_ATTR_PAM_TRUST        0x00000200  /**< Privileged Access Mngmt     */

/* =========================================================================
 * Well-Known SID Prefix Strings
 * Used for readability in ACL output.
 * ========================================================================= */

#define SID_EVERYONE                "S-1-1-0"
#define SID_CREATOR_OWNER           "S-1-3-0"
#define SID_CREATOR_GROUP           "S-1-3-1"
#define SID_NT_AUTHORITY            "S-1-5"
#define SID_AUTHENTICATED_USERS     "S-1-5-11"
#define SID_ENTERPRISE_DC           "S-1-5-9"
#define SID_DOMAIN_ADMINS_RID       "512"       /* Appended to domain SID       */
#define SID_ENTERPRISE_ADMINS_RID   "519"
#define SID_SCHEMA_ADMINS_RID       "518"
#define SID_ACCOUNT_OPERATORS_RID   "548"
#define SID_BACKUP_OPERATORS_RID    "551"
#define SID_PRINT_OPERATORS_RID     "550"
#define SID_SERVER_OPERATORS_RID    "549"

/* =========================================================================
 * AD Extended Rights GUIDs (for DACL object ACE interpretation)
 * Reference: https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights
 * ========================================================================= */

/** User-Force-Change-Password (reset password without knowing current) */
#define GUID_USER_FORCE_CHANGE_PASSWORD \
    {0x00299570,0x246d,0x11d0,{0xa7,0x68,0x00,0xaa,0x00,0x6e,0x05,0x29}}

/** DS-Replication-Get-Changes-All (DCSync — replicates all domain secrets) */
#define GUID_DS_REPLICATION_GET_CHANGES_ALL \
    {0x1131f6ad,0x9c07,0x11d1,{0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2}}

/** DS-Replication-Get-Changes */
#define GUID_DS_REPLICATION_GET_CHANGES \
    {0x1131f6aa,0x9c07,0x11d1,{0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2}}

/** DS-Replication-Synchronize */
#define GUID_DS_REPLICATION_SYNCHRONIZE \
    {0x1131f6ab,0x9c07,0x11d1,{0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2}}

/** Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD) */
#define GUID_ALLOWED_TO_ACT_ON_BEHALF \
    {0x3f78c3e5,0xf79a,0x46bd,{0xa0,0xb8,0x9d,0x18,0x11,0x6d,0xdc,0x79}}

/** Member attribute (group membership write) */
#define GUID_MEMBER_ATTRIBUTE \
    {0xbf9679c0,0x0de6,0x11d0,{0xa2,0x85,0x00,0xaa,0x00,0x30,0x49,0xe2}}

/** Script-Path attribute (login script write — potential persistence) */
#define GUID_SCRIPT_PATH \
    {0xbf9679a8,0x0de6,0x11d0,{0xa2,0x85,0x00,0xaa,0x00,0x30,0x49,0xe2}}

/** ServicePrincipalName attribute */
#define GUID_SERVICE_PRINCIPAL_NAME \
    {0xf3a64788,0x5306,0x11d1,{0xa9,0xc5,0x00,0x00,0xf8,0x03,0x16,0x27}}

/* =========================================================================
 * PHANTOM_CONTEXT — Global Module Runtime Context
 * ========================================================================= */

/**
 * @brief Central context structure initialized by phantom_ldap_init() and
 *        passed to every operational function within a BOF module.
 *
 * Lifetime: Stack-allocated in each module's go() function. Must be
 * zeroed on entry and cleaned up with phantom_ldap_cleanup() before return.
 */
typedef struct _PHANTOM_CONTEXT {
    /* Connection state */
    PLDAP               ldap_handle;        /**< Opaque LDAP session handle      */
    WCHAR               dc_name[256];       /**< Target DC hostname (wide)       */
    WCHAR               base_dn[512];       /**< LDAP base DN (e.g. DC=corp,DC=local) */
    BOOL                connected;          /**< TRUE after successful bind      */
    BOOL                use_ssl;            /**< TRUE = LDAPS (port 636)         */
    ULONG               ldap_port;          /**< Port number (389 or 636)        */

    /* Resolved function table */
    PHANTOM_LDAP_API    api;                /**< Fully resolved wldap32 functions */

    /* Operational parameters */
    DWORD               page_size;          /**< Objects per paginated page      */
    ULONG               search_timeout;     /**< Search timeout in seconds       */

    /* Statistics */
    DWORD               total_found;        /**< Total objects found this session */
    DWORD               page_count;         /**< Number of pages fetched         */
    DWORD               error_count;        /**< Number of non-fatal errors      */
} PHANTOM_CONTEXT, *PPHANTOM_CONTEXT;

/* =========================================================================
 * ACE Analysis Result
 * ========================================================================= */

/**
 * @brief Categorization of an interesting ACE for output.
 *
 * The ACL parser in enum_acl.c populates arrays of these for each
 * object's DACL, then outputs them in a formatted report.
 */
typedef enum _ACE_INTEREST_LEVEL {
    ACE_INTEREST_NORMAL    = 0,  /**< Standard/expected permissions             */
    ACE_INTEREST_MEDIUM    = 1,  /**< Potentially abusable (e.g., GenericWrite) */
    ACE_INTEREST_HIGH      = 2,  /**< Dangerous (WriteDACL, WriteOwner, DCSync) */
    ACE_INTEREST_CRITICAL  = 3,  /**< Directly exploitable (ForceChangePassword,
                                      AllExtendedRights on sensitive objects)   */
} ACE_INTEREST_LEVEL;

/**
 * @brief Decoded, human-readable representation of a single ACE.
 */
typedef struct _PHANTOM_ACE_INFO {
    char                ace_type_str[32];   /**< "ALLOW" / "DENY" / "ALLOW_OBJ" */
    char                sid_str[185];       /**< String SID (S-1-5-21-...)       */
    char                trustee_name[128];  /**< Resolved name if available      */
    char                access_mask_str[512]; /**< Human-readable rights list    */
    char                object_type_guid[64]; /**< GUID string for object ACEs   */
    char                right_name[128];    /**< Named right (e.g., "DCSync")    */
    DWORD               raw_mask;           /**< Raw ACCESS_MASK value           */
    BYTE                ace_flags;          /**< Inheritance flags               */
    ACE_INTEREST_LEVEL  interest;           /**< Severity classification         */
    BOOL                is_object_ace;      /**< TRUE = has GUID object type     */
    BOOL                is_dangerous;       /**< Shorthand: interest >= HIGH     */
} PHANTOM_ACE_INFO, *PPHANTOM_ACE_INFO;

/* =========================================================================
 * Module Initialization & Cleanup
 * ========================================================================= */

/**
 * @brief Initialize a PHANTOM_CONTEXT for LDAP operations.
 *
 * Performs the following steps:
 * 1. Resolves all wldap32 API functions via PEB walker.
 * 2. Calls ldap_init() to create a session handle.
 * 3. Sets LDAP protocol version to v3.
 * 4. Optionally configures SSL if use_ssl is TRUE.
 * 5. Calls ldap_bind_s() with LDAP_AUTH_NEGOTIATE (Kerberos/NTLM via SSPI).
 * 6. Populates ctx->base_dn from the rootDSE defaultNamingContext attribute.
 *
 * @param ctx       Pointer to zeroed PHANTOM_CONTEXT to initialize
 * @param dc_name   DC hostname (NULL = use current domain's DC via rootDSE)
 * @param use_ssl   TRUE to use LDAPS (port 636)
 * @param page_size LDAP paging size (0 = PHANTOM_DEFAULT_PAGE_SIZE)
 * @return          TRUE on success, FALSE on any failure
 */
BOOL phantom_ldap_init(
    PPHANTOM_CONTEXT ctx,
    const WCHAR     *dc_name,
    BOOL             use_ssl,
    DWORD            page_size
);

/**
 * @brief Release all resources held by a PHANTOM_CONTEXT.
 *
 * Calls ldap_unbind() if connected, then zeros the structure.
 * Safe to call even if initialization was only partially completed.
 *
 * @param ctx   Context to clean up (may be partially initialized)
 */
void phantom_ldap_cleanup(PPHANTOM_CONTEXT ctx);

/* =========================================================================
 * Paged LDAP Search Engine
 * ========================================================================= */

/**
 * @brief Callback type invoked once per LDAP result entry during paged search.
 *
 * @param ctx       Module runtime context (populated ldap_handle, api, etc.)
 * @param entry     Current LDAPMessage entry — valid only for the duration of the call
 * @param user_data Caller-supplied context pointer (NULL-safe)
 * @return          TRUE to continue enumeration, FALSE to abort early
 */
typedef BOOL (*PHANTOM_RESULT_CALLBACK)(
    PPHANTOM_CONTEXT ctx,
    PLDAPMessage     entry,
    PVOID            user_data
);

/**
 * @brief Execute a paged LDAP search using RFC 2696 Simple Paged Results.
 *
 * Fetches all matching objects across multiple paginated requests, invoking
 * @p callback once per entry. Manages all LDAP control and result memory
 * internally — callers must not free any LDAPMessage pointers.
 *
 * @param ctx       Initialized context (phantom_ldap_init must have been called)
 * @param base      Search base DN (wide string; NULL = ctx->base_dn)
 * @param scope     LDAP_SCOPE_BASE / LDAP_SCOPE_ONELEVEL / LDAP_SCOPE_SUBTREE
 * @param filter    LDAP filter string (wide)
 * @param attrs     NULL-terminated array of wide attribute name strings
 * @param callback  Per-entry handler (PHANTOM_RESULT_CALLBACK)
 * @param user_data Opaque pointer forwarded to each callback invocation
 * @return          Total number of objects processed across all pages
 */
DWORD phantom_ldap_paged_search(
    PPHANTOM_CONTEXT         ctx,
    PWSTR                    base,
    ULONG                    scope,
    PWSTR                    filter,
    PWSTR                   *attrs,
    PHANTOM_RESULT_CALLBACK  callback,
    PVOID                    user_data
);

/* =========================================================================
 * Output & Formatting (implemented in output.c)
 * ========================================================================= */

/**
 * @brief Print the PhantomLDAP ASCII art banner to the Beacon console.
 *
 * Called once at the start of each module's go() function.
 * Output is rate-limited internally to avoid banner spam.
 */
void phantom_print_banner(void);

/**
 * @brief Print a formatted section header to the Beacon console.
 * @param title     Header text (ASCII)
 * @param module    Module name tag (e.g., "SPN-ENUM")
 */
void phantom_print_header(const char *title, const char *module);

/**
 * @brief Print a horizontal separator line to the Beacon console.
 * @param ch    Character to repeat (e.g., '=', '-', '*')
 */
void phantom_print_separator(char ch);

/**
 * @brief Print a summary footer with object count and elapsed statistics.
 * @param ctx   Context containing counters
 */
void phantom_print_footer(PPHANTOM_CONTEXT ctx);

/**
 * @brief Print a right-aligned key: value pair to the Beacon console.
 *
 * Key is padded to 26 characters for alignment across multiple fields.
 *
 * @param key     Label string (ASCII)
 * @param value   Value string (ASCII); "(null)" printed if NULL
 * @param indent  Number of leading spaces (typically 4)
 */
void phantom_print_kv(const char *key, const char *value, int indent);

/**
 * @brief Convert a Windows FILETIME (100-ns intervals since 1601) to a
 *        human-readable UTC date string.
 *
 * @param filetime_val  64-bit FILETIME value (from ldap_get_values_len)
 * @param buf           Output buffer
 * @param buf_size      Output buffer size in characters
 */
void phantom_filetime_to_str(LONGLONG filetime_val, char *buf, SIZE_T buf_size);

/**
 * @brief Convert a FILETIME to "X days ago" representation.
 * @param filetime_val  64-bit FILETIME value
 * @param buf           Output buffer
 * @param buf_size      Output buffer size
 */
void phantom_filetime_to_age(LONGLONG filetime_val, char *buf, SIZE_T buf_size);

/**
 * @brief Convert a binary objectSid (BER value) to string form "S-1-5-21-...".
 *
 * @param sid_bytes     Raw SID bytes from LDAP binary attribute
 * @param sid_len       Length of sid_bytes
 * @param out_buf       Output string buffer (min 185 bytes)
 * @param buf_size      Size of out_buf
 * @return              TRUE on success
 */
BOOL phantom_sid_to_string(
    const BYTE *sid_bytes,
    DWORD       sid_len,
    char       *out_buf,
    SIZE_T      buf_size
);

/**
 * @brief Convert a raw 16-byte GUID to its string representation.
 *
 * @param guid      Pointer to 16-byte GUID data
 * @param out_buf   Output buffer (min 39 bytes for "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}")
 * @param buf_size  Size of out_buf
 */
void phantom_guid_to_string(
    const BYTE *guid,
    char       *out_buf,
    SIZE_T      buf_size
);

/**
 * @brief Convert a wide string to a narrow (UTF-8) string using BeaconPrintf.
 *
 * @param wstr      Source wide string
 * @param buf       Destination narrow buffer
 * @param buf_size  Destination buffer size in bytes
 */
void phantom_wstr_to_str(const WCHAR *wstr, char *buf, SIZE_T buf_size);

/**
 * @brief Convert a narrow string to wide string.
 *
 * @param str       Source narrow string (ASCII/UTF-8)
 * @param wbuf      Destination wide buffer
 * @param wbuf_len  Destination buffer size in WCHARs
 */
void phantom_str_to_wstr(const char *str, WCHAR *wbuf, SIZE_T wbuf_len);

/**
 * @brief Lookup a known extended right GUID and return its name.
 *
 * @param guid      16-byte GUID to look up
 * @return          Static string name (e.g., "DCSync"), or NULL if unknown
 */
const char *phantom_lookup_extended_right(const BYTE *guid);

/**
 * @brief Decode userAccountControl flags into a human-readable string.
 *
 * @param uac       userAccountControl DWORD value
 * @param buf       Output buffer
 * @param buf_size  Buffer size in bytes
 */
void phantom_decode_uac(DWORD uac, char *buf, SIZE_T buf_size);

/**
 * @brief Decode an ACCESS_MASK into a human-readable string for AD context.
 *
 * @param mask      Raw access mask
 * @param buf       Output buffer
 * @param buf_size  Buffer size in bytes
 */
void phantom_decode_access_mask(DWORD mask, char *buf, SIZE_T buf_size);

#ifdef __cplusplus
}
#endif

#endif /* PHANTOM_LDAP_MAIN_H */
