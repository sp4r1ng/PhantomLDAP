/**
 * @file ldap_types.h
 * @brief Standalone LDAP type definitions for wldap32.dll dynamic resolution.
 *
 * Provides all necessary types, constants, and structure definitions for
 * interacting with the Windows LDAP client library (wldap32.dll) without
 * including Winldap.h or any SDK headers.
 *
 * These definitions are derived from the public LDAP RFC specifications and
 * Microsoft's documentation. The structures defined here are compatible with
 * the wldap32.dll ABI on x64 Windows.
 *
 * @see https://docs.microsoft.com/en-us/windows/win32/api/winldap/
 * @see RFC 4511 — Lightweight Directory Access Protocol (LDAP): Protocol
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#ifndef PHANTOM_LDAP_TYPES_H
#define PHANTOM_LDAP_TYPES_H

#include "win_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * LDAP Port Constants
 * ========================================================================= */

#define LDAP_PORT               389     /**< Standard unencrypted LDAP port      */
#define LDAP_SSL_PORT           636     /**< LDAP over TLS/SSL (LDAPS) port      */
#define LDAP_GC_PORT            3268    /**< Global Catalog port                  */
#define LDAP_GC_SSL_PORT        3269    /**< Global Catalog over TLS/SSL          */

/* =========================================================================
 * LDAP Error Codes
 * ========================================================================= */

#define LDAP_SUCCESS                    0x00L
#define LDAP_OPERATIONS_ERROR           0x01L
#define LDAP_PROTOCOL_ERROR             0x02L
#define LDAP_TIMELIMIT_EXCEEDED         0x03L
#define LDAP_SIZELIMIT_EXCEEDED         0x04L
#define LDAP_AUTH_METHOD_NOT_SUPPORTED  0x07L
#define LDAP_STRONG_AUTH_REQUIRED       0x08L
#define LDAP_REFERRAL                   0x0AL
#define LDAP_ADMIN_LIMIT_EXCEEDED       0x0BL
#define LDAP_UNAVAILABLE_CRIT_EXT       0x0CL
#define LDAP_NO_SUCH_ATTRIBUTE          0x10L
#define LDAP_UNDEFINED_TYPE             0x11L
#define LDAP_NO_SUCH_OBJECT             0x20L
#define LDAP_INVALID_DN_SYNTAX          0x22L
#define LDAP_INVALID_CREDENTIALS        0x31L
#define LDAP_INSUFFICIENT_RIGHTS        0x32L
#define LDAP_BUSY                       0x33L
#define LDAP_UNAVAILABLE                0x34L
#define LDAP_UNWILLING_TO_PERFORM       0x35L
#define LDAP_ALREADY_EXISTS             0x44L
#define LDAP_OTHER                      0x50L
#define LDAP_SERVER_DOWN                0x51L
#define LDAP_LOCAL_ERROR                0x52L
#define LDAP_ENCODING_ERROR             0x53L
#define LDAP_DECODING_ERROR             0x54L
#define LDAP_TIMEOUT                    0x55L
#define LDAP_AUTH_UNKNOWN               0x56L
#define LDAP_NO_MEMORY                  0x5AL
#define LDAP_NOT_SUPPORTED              0x5CL
#define LDAP_NO_RESULTS_RETURNED        0x5EL

/* =========================================================================
 * LDAP Scope Constants
 * ========================================================================= */

#define LDAP_SCOPE_BASE         0x00    /**< Search only the base object          */
#define LDAP_SCOPE_ONELEVEL     0x01    /**< Search one level below base          */
#define LDAP_SCOPE_SUBTREE      0x02    /**< Search entire subtree (recursive)    */

/* =========================================================================
 * LDAP Authentication Methods
 * ========================================================================= */

#define LDAP_AUTH_SIMPLE        0x80L   /**< Simple (plaintext) bind              */
#define LDAP_AUTH_SSPI          0x0E00L /**< SSPI (Negotiate/Kerberos/NTLM)       */
#define LDAP_AUTH_NEGOTIATE     (LDAP_AUTH_SSPI | 0x0400L) /**< Negotiate/GSSAPI */

/* =========================================================================
 * LDAP Option Constants
 * ========================================================================= */

#define LDAP_OPT_API_INFO           0x00
#define LDAP_OPT_DESC               0x01
#define LDAP_OPT_DEREF              0x02
#define LDAP_OPT_SIZELIMIT          0x03
#define LDAP_OPT_TIMELIMIT          0x04
#define LDAP_OPT_REFERRALS          0x08
#define LDAP_OPT_RESTART            0x09
#define LDAP_OPT_SSL                0x0A    /**< Enable SSL/TLS                   */
#define LDAP_OPT_IO_FN_PTRS         0x0B
#define LDAP_OPT_CACHE_FN_PTRS      0x0D
#define LDAP_OPT_CACHE_STRATEGY     0x0E
#define LDAP_OPT_CACHE_ENABLE       0x0F
#define LDAP_OPT_REFERRAL_FN_PTRS   0x10
#define LDAP_OPT_SERVER_CONTROLS    0x12
#define LDAP_OPT_CLIENT_CONTROLS    0x13
#define LDAP_OPT_HOST_NAME          0x30
#define LDAP_OPT_ERROR_NUMBER       0x31
#define LDAP_OPT_ERROR_STRING       0x32
#define LDAP_OPT_SERVER_ERROR       0x33
#define LDAP_OPT_SERVER_EXT_ERROR   0x34
#define LDAP_OPT_HOST_REACHABLE     0x3E
#define LDAP_OPT_PING_KEEP_ALIVE    0x36
#define LDAP_OPT_PING_WAIT_TIME     0x37
#define LDAP_OPT_PING_LIMIT         0x38
#define LDAP_OPT_DNSDOMAIN_NAME     0x3B
#define LDAP_OPT_GETDSNAME_FLAGS    0x3D
#define LDAP_OPT_PROMPT_CREDENTIALS 0x3F
#define LDAP_OPT_AUTO_RECONNECT     0x91
#define LDAP_OPT_SSPI_FLAGS         0x92
#define LDAP_OPT_SSL_INFO           0x93
#define LDAP_OPT_SIGN               0x95
#define LDAP_OPT_ENCRYPT            0x96
#define LDAP_OPT_SASL_METHOD        0x97
#define LDAP_OPT_AREC_EXCLUSIVE     0x98
#define LDAP_OPT_SECURITY_CONTEXT   0x99
#define LDAP_OPT_VERSION            0x11

#define LDAP_VERSION2               2
#define LDAP_VERSION3               3
#define LDAP_VERSION                LDAP_VERSION3

/* LDAP_OPT_REFERRALS values */
#define LDAP_OPT_ON     ((void *)1)
#define LDAP_OPT_OFF    ((void *)0)

/* =========================================================================
 * LDAP Paging Control OID
 * ========================================================================= */

/**
 * @brief OID for the LDAP Simple Paged Results control.
 * @see RFC 2696 — LDAP Control Extension for Simple Paged Results Manipulation
 */
#define LDAP_PAGED_RESULT_OID_STRING    "1.2.840.113556.1.4.319"

/* =========================================================================
 * LDAP Message Types
 * ========================================================================= */

#define LDAP_RES_BIND                   0x61L
#define LDAP_RES_SEARCH_ENTRY           0x64L
#define LDAP_RES_SEARCH_RESULT          0x65L
#define LDAP_RES_SEARCH_REFERENCE       0x73L
#define LDAP_RES_MODIFY                 0x67L
#define LDAP_RES_ADD                    0x69L
#define LDAP_RES_DELETE                 0x6BL
#define LDAP_RES_MODRDN                 0x6DL
#define LDAP_RES_COMPARE                0x6FL
#define LDAP_RES_ABANDON                0x71L
#define LDAP_RES_EXTENDED               0x78L
#define LDAP_RES_ANY                    (-1L)

/* =========================================================================
 * LDAP Structures
 * ========================================================================= */

/**
 * @brief BER (Basic Encoding Rules) element opaque handle.
 * BerElement is an opaque structure managed by wldap32.dll.
 */
typedef struct berval {
    ULONG   bv_len;
    PSTR    bv_val;
} LDAP_BERVAL, *PLDAP_BERVAL;

/**
 * @brief Opaque LDAP handle returned by ldap_init().
 *
 * The internal layout of LDAP is undocumented and wldap32-version-specific.
 * We treat it as a fully opaque pointer.
 */
typedef struct ldap LDAP, *PLDAP;

/**
 * @brief Opaque LDAP message handle.
 *
 * Returned by search functions and freed with ldap_msgfree().
 */
typedef struct ldapmsg LDAPMessage, *PLDAPMessage;

/**
 * @brief Opaque BER element handle for attribute iteration.
 *
 * Used as an iterator state by ldap_first_attribute()/ldap_next_attribute().
 */
typedef struct berelement BerElement, *PBerElement;

/**
 * @brief LDAP control structure.
 *
 * Controls are extensions that modify LDAP operation behavior.
 * The paging control (RFC 2696) is the primary control used by PhantomLDAP.
 */
typedef struct ldapcontrol {
    PSTR        ldctl_oid;       /**< OID string identifying the control       */
    LDAP_BERVAL ldctl_value;     /**< BER-encoded control value                */
    UCHAR       ldctl_iscritical;/**< If TRUE, server MUST support this ctrl   */
} LDAPControl, *PLDAPControl;

/**
 * @brief timeval structure for LDAP timeout specification.
 */
typedef struct l_timeval {
    LONG tv_sec;    /**< Seconds                                               */
    LONG tv_usec;   /**< Microseconds                                          */
} LDAP_TIMEVAL, *PLDAP_TIMEVAL;

/* =========================================================================
 * wldap32.dll Function Pointer Typedefs
 *
 * These typedefs define the exact calling convention and signature for each
 * function resolved dynamically from wldap32.dll. The signatures match the
 * Windows SDK winldap.h declarations for x64.
 * ========================================================================= */

/** ldap_initW — Initialize LDAP session (Unicode, LDAP v3) */
typedef PLDAP (WINAPI *fn_ldap_initW_t)(
    PWSTR   HostName,
    ULONG   PortNumber
);

/** ldap_set_option — Set session-wide LDAP option */
typedef ULONG (WINAPI *fn_ldap_set_option_t)(
    PLDAP       ld,
    int         option,
    const void *invalue
);

/** ldap_get_option — Get session-wide LDAP option */
typedef ULONG (WINAPI *fn_ldap_get_option_t)(
    PLDAP   ld,
    int     option,
    void   *outvalue
);

/** ldap_connect — Establish underlying TCP connection */
typedef ULONG (WINAPI *fn_ldap_connect_t)(
    PLDAP           ld,
    PLDAP_TIMEVAL   timeout
);

/** ldap_bind_s (synchronous) — Authenticate to the directory */
typedef ULONG (WINAPI *fn_ldap_bind_sW_t)(
    PLDAP   ld,
    PWSTR   dn,
    PWSTR   cred,
    ULONG   method
);

/** ldap_unbind — Close session and free LDAP handle */
typedef ULONG (WINAPI *fn_ldap_unbind_t)(
    PLDAP ld
);

/** ldap_search_ext_s (synchronous) — Search directory with controls */
typedef ULONG (WINAPI *fn_ldap_search_ext_sW_t)(
    PLDAP           ld,
    PWSTR           base,
    ULONG           scope,
    PWSTR           filter,
    PWSTR          *attrs,
    ULONG           attrsonly,
    PLDAPControl   *serverControls,
    PLDAPControl   *clientControls,
    PLDAP_TIMEVAL   timeout,
    ULONG           sizelimit,
    PLDAPMessage   *res
);

/** ldap_count_entries — Count search result entries in a message chain */
typedef ULONG (WINAPI *fn_ldap_count_entries_t)(
    PLDAP       ld,
    PLDAPMessage res
);

/** ldap_first_entry — Get first entry in a result set */
typedef PLDAPMessage (WINAPI *fn_ldap_first_entry_t)(
    PLDAP       ld,
    PLDAPMessage res
);

/** ldap_next_entry — Get next entry in a result set */
typedef PLDAPMessage (WINAPI *fn_ldap_next_entry_t)(
    PLDAP       ld,
    PLDAPMessage entry
);

/** ldap_get_valuesW — Get string attribute values (Unicode) */
typedef PWSTR* (WINAPI *fn_ldap_get_valuesW_t)(
    PLDAP       ld,
    PLDAPMessage entry,
    PWSTR       attr
);

/** ldap_get_values_lenW — Get binary attribute values (BER) */
typedef PLDAP_BERVAL* (WINAPI *fn_ldap_get_values_lenW_t)(
    PLDAP       ld,
    PLDAPMessage entry,
    PWSTR       attr
);

/** ldap_count_valuesW — Count string attribute values */
typedef ULONG (WINAPI *fn_ldap_count_valuesW_t)(
    PWSTR *vals
);

/** ldap_count_values_len — Count binary attribute values */
typedef ULONG (WINAPI *fn_ldap_count_values_len_t)(
    PLDAP_BERVAL *vals
);

/** ldap_value_freeW — Free string value array */
typedef ULONG (WINAPI *fn_ldap_value_freeW_t)(
    PWSTR *vals
);

/** ldap_value_free_len — Free binary value array */
typedef ULONG (WINAPI *fn_ldap_value_free_len_t)(
    PLDAP_BERVAL *vals
);

/** ldap_msgfree — Free an LDAPMessage chain */
typedef ULONG (WINAPI *fn_ldap_msgfree_t)(
    PLDAPMessage res
);

/** ldap_get_dnW — Extract DN from an entry */
typedef PWSTR (WINAPI *fn_ldap_get_dnW_t)(
    PLDAP       ld,
    PLDAPMessage entry
);

/** ldap_memfreeW — Free memory allocated by the LDAP library */
typedef VOID (WINAPI *fn_ldap_memfreeW_t)(
    PWSTR block
);

/** ldap_first_attributeW — Get first attribute name in an entry */
typedef PWSTR (WINAPI *fn_ldap_first_attributeW_t)(
    PLDAP       ld,
    PLDAPMessage entry,
    PBerElement *ptr
);

/** ldap_next_attributeW — Get next attribute name in an entry */
typedef PWSTR (WINAPI *fn_ldap_next_attributeW_t)(
    PLDAP       ld,
    PLDAPMessage entry,
    PBerElement ptr
);

/** ber_free — Free a BerElement (attribute iterator) */
typedef VOID (WINAPI *fn_ber_free_t)(
    PBerElement pBerElement,
    int         fbuf
);

/** ldap_create_page_control — Create a paged results server control */
typedef ULONG (WINAPI *fn_ldap_create_page_controlW_t)(
    PLDAP       ld,
    ULONG       pageSize,
    PLDAP_BERVAL cookie,
    UCHAR       isCritical,
    PLDAPControl *control
);

/** ldap_parse_page_control — Extract next-page cookie from a result */
typedef ULONG (WINAPI *fn_ldap_parse_page_controlW_t)(
    PLDAP           ld,
    PLDAPControl   *serverControls,
    ULONG          *totalCount,
    PLDAP_BERVAL   *cookie
);

/** ldap_parse_result — Parse an extended result for controls */
typedef ULONG (WINAPI *fn_ldap_parse_resultW_t)(
    PLDAP           ld,
    PLDAPMessage    result,
    ULONG          *ReturnCode,
    PWSTR          *MatchedDNs,
    PWSTR          *ErrorMessage,
    PWSTR         **Referrals,
    PLDAPControl  **ServerControls,
    BOOL            Freeit
);

/** ldap_controls_freeA — Free an array of LDAPControl pointers */
typedef ULONG (WINAPI *fn_ldap_controls_freeA_t)(
    LDAPControl **controls
);

/** ldap_err2stringW — Convert LDAP error code to string */
typedef PWSTR (WINAPI *fn_ldap_err2stringW_t)(
    ULONG err
);

/* =========================================================================
 * Aggregated LDAP API Table
 *
 * All function pointers are resolved once at module initialization via
 * the PEB walker in dynamic_resolve.c. Subsequent calls use this table
 * directly, avoiding repeated hash lookups.
 * ========================================================================= */

/**
 * @brief Fully resolved wldap32.dll function pointer table.
 *
 * Usage pattern:
 * @code
 *   PHANTOM_LDAP_API api = {0};
 *   if (!phantom_resolve_ldap_api(&api)) { goto cleanup; }
 *   PLDAP ld = api.ldap_init(L"dc01.corp.local", LDAP_PORT);
 * @endcode
 */
typedef struct _PHANTOM_LDAP_API {
    fn_ldap_initW_t             ldap_init;
    fn_ldap_set_option_t        ldap_set_option;
    fn_ldap_get_option_t        ldap_get_option;
    fn_ldap_connect_t           ldap_connect;
    fn_ldap_bind_sW_t           ldap_bind_s;
    fn_ldap_unbind_t            ldap_unbind;
    fn_ldap_search_ext_sW_t     ldap_search_ext_s;
    fn_ldap_count_entries_t     ldap_count_entries;
    fn_ldap_first_entry_t       ldap_first_entry;
    fn_ldap_next_entry_t        ldap_next_entry;
    fn_ldap_get_valuesW_t       ldap_get_values;
    fn_ldap_get_values_lenW_t   ldap_get_values_len;
    fn_ldap_count_valuesW_t     ldap_count_values;
    fn_ldap_count_values_len_t  ldap_count_values_len;
    fn_ldap_value_freeW_t       ldap_value_free;
    fn_ldap_value_free_len_t    ldap_value_free_len;
    fn_ldap_msgfree_t           ldap_msgfree;
    fn_ldap_get_dnW_t           ldap_get_dn;
    fn_ldap_memfreeW_t          ldap_memfree;
    fn_ldap_first_attributeW_t  ldap_first_attribute;
    fn_ldap_next_attributeW_t   ldap_next_attribute;
    fn_ber_free_t               ber_free;
    fn_ldap_create_page_controlW_t  ldap_create_page_control;
    fn_ldap_parse_page_controlW_t   ldap_parse_page_control;
    fn_ldap_parse_resultW_t         ldap_parse_result;
    fn_ldap_controls_freeA_t        ldap_controls_free;
    fn_ldap_err2stringW_t           ldap_err2string;
} PHANTOM_LDAP_API, *PPHANTOM_LDAP_API;

#ifdef __cplusplus
}
#endif

#endif /* PHANTOM_LDAP_TYPES_H */
