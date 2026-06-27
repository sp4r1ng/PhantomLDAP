/*
 * Cobalt Strike 4.x Beacon Object File (BOF) API Header
 *
 * This header provides the declarations required to develop BOFs targeting
 * Cobalt Strike 4.x. It exposes:
 *   - BeaconPrintf / BeaconOutput     — Output to operator console
 *   - BeaconDataParse / BeaconData*   — Argument parsing
 *   - BeaconUseToken / BeaconRevertToken — Token manipulation
 *   - BeaconIsAdmin                   — Privilege check
 *   - BeaconInjectProcess             — Process injection
 *   - Dynamic function import macros  — KERNEL32, MSVCRT, etc.
 *
 * Reference: Cobalt Strike 4.x External C2 & BOF development guide
 * Source:    https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/
 *
 * @note This file is intentionally kept compatible with the official
 *       HelpSystems beacon.h to ease integration with existing BOF tooling.
 */

#ifndef BEACON_H
#define BEACON_H

#include "win_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Beacon Output Channels
 * ========================================================================= */

#define CALLBACK_OUTPUT         0x0     /**< Normal output to operator           */
#define CALLBACK_OUTPUT_OEM     0x1E    /**< Output in OEM codepage              */
#define CALLBACK_ERROR          0x0D    /**< Error message                       */
#define CALLBACK_OUTPUT_UTF8    0x20    /**< Output encoded as UTF-8             */

/* =========================================================================
 * Argument Buffer
 * ========================================================================= */

/**
 * @brief Opaque argument parser context.
 *
 * Initialize with BeaconDataParse() before extracting arguments.
 */
typedef struct {
    char   *original;   /**< Original buffer pointer (for cleanup)             */
    char   *buffer;     /**< Current read position                             */
    int     length;     /**< Bytes remaining in buffer                         */
    int     size;       /**< Total buffer size                                 */
} datap;

/* =========================================================================
 * Beacon API — Output Functions
 * ========================================================================= */

/**
 * @brief Format and send output to the operator's Beacon console.
 *
 * @param type      Output type (CALLBACK_OUTPUT, CALLBACK_ERROR, etc.)
 * @param fmt       printf-style format string
 * @param ...       Format arguments
 */
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

/**
 * @brief Send raw data to the operator's Beacon console.
 *
 * @param type      Output type (CALLBACK_OUTPUT, CALLBACK_ERROR, etc.)
 * @param data      Pointer to raw data buffer
 * @param len       Length of data buffer in bytes
 */
DECLSPEC_IMPORT void BeaconOutput(int type, const char *data, int len);

/* =========================================================================
 * Beacon API — Argument Parsing
 * ========================================================================= */

/**
 * @brief Initialize a datap parser with the BOF argument buffer.
 *
 * Always call this first in your go() function before extracting arguments.
 *
 * @param parser    Uninitialized datap structure to fill
 * @param buffer    Raw argument buffer passed to go()
 * @param size      Size of argument buffer in bytes
 */
DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);

/**
 * @brief Extract a 4-byte integer argument (little-endian).
 *
 * @param parser    Active datap parser
 * @return          Integer value extracted from buffer
 */
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);

/**
 * @brief Extract a 2-byte short integer argument (little-endian).
 *
 * @param parser    Active datap parser
 * @return          Short integer value
 */
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);

/**
 * @brief Extract a length-prefixed byte buffer argument.
 *
 * @param parser    Active datap parser
 * @param size      Output: receives the length of the extracted buffer
 * @return          Pointer into the argument buffer (not a copy — do NOT free)
 */
DECLSPEC_IMPORT char* BeaconDataExtract(datap *parser, int *size);

/**
 * @brief Return the number of bytes remaining in the parser buffer.
 *
 * @param parser    Active datap parser
 * @return          Bytes remaining
 */
DECLSPEC_IMPORT int BeaconDataLength(datap *parser);

/* =========================================================================
 * Beacon API — Format Buffer (Structured Output)
 * ========================================================================= */

/**
 * @brief Opaque format buffer for accumulating structured output.
 */
typedef struct {
    char   *original;
    char   *buffer;
    int     length;
    int     size;
} formatp;

DECLSPEC_IMPORT void  BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void  BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void  BeaconFormatAppend(formatp *format, const char *text, int len);
DECLSPEC_IMPORT void  BeaconFormatPrintf(formatp *format, const char *fmt, ...);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void  BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void  BeaconFormatInt(formatp *format, int value);

/* =========================================================================
 * Beacon API — Token & Privilege Management
 * ========================================================================= */

/**
 * @brief Check if the current Beacon context is running as administrator.
 *
 * @return TRUE if the process token has local administrator privileges.
 */
DECLSPEC_IMPORT BOOL BeaconIsAdmin(void);

/**
 * @brief Impersonate a token on the current thread.
 *
 * @param token     Token handle to impersonate.
 * @return          TRUE on success.
 */
DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);

/**
 * @brief Revert to the process's primary token.
 */
DECLSPEC_IMPORT void BeaconRevertToken(void);

/* =========================================================================
 * Beacon API — Spawn & Inject
 * ========================================================================= */

/**
 * @brief Inject a reflective DLL into a remote process.
 *
 * @param pid           Target process ID
 * @param arch          Architecture ("x86" or "x64")
 * @param payload       Beacon payload shellcode
 * @param p_len         Payload length
 * @param argdata       Optional argument data
 * @param a_len         Argument data length
 * @param listener      Listener name
 */
DECLSPEC_IMPORT void BeaconInjectProcess(
    HANDLE  hProc,
    int     pid,
    char   *payload,
    int     p_len,
    int     p_offset,
    char   *argdata,
    int     a_len
);

/**
 * @brief Inject into a process using a temporary process (fork & run).
 *
 * @param pid       Target process ID
 * @param x86       TRUE for 32-bit target, FALSE for 64-bit
 * @param payload   Shellcode payload
 * @param len       Payload length
 */
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(
    void   *pInfo,
    char   *payload,
    int     p_len,
    int     p_offset,
    char   *argdata,
    int     a_len
);

/* =========================================================================
 * Beacon API — Process Management
 * ========================================================================= */

DECLSPEC_IMPORT BOOL BeaconSpawnTemporaryProcess(
    BOOL    x86,
    BOOL    ignoreToken,
    void   *si,
    void   *pi
);

DECLSPEC_IMPORT void BeaconCleanupProcess(void *pInfo);

/* =========================================================================
 * Dynamic Import Macros
 *
 * These macros declare a function import using the compiler's
 * __declspec(dllimport) mechanism. For BOFs, the Beacon loader resolves
 * these at load time using the Cobalt Strike import mechanism.
 *
 * Usage:
 *   WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, ...);
 *
 * Then call as:
 *   HANDLE h = KERNEL32$CreateFileW(path, GENERIC_READ, ...);
 *
 * @note PhantomLDAP does NOT use this mechanism for wldap32.dll functions.
 *       All LDAP API calls are resolved dynamically via the PEB walker to
 *       avoid IAT-based detection. Only the Beacon API itself (above) and
 *       select non-sensitive kernel32 calls use this mechanism.
 * ========================================================================= */

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

/* Standard import prefix convention for BOF Cobalt Strike */
#define KERNEL32$GetProcessHeap         __declspec(dllimport) HANDLE WINAPI GetProcessHeap(void)
#define KERNEL32$HeapAlloc              __declspec(dllimport) PVOID  WINAPI HeapAlloc(HANDLE, DWORD, SIZE_T)
#define KERNEL32$HeapFree               __declspec(dllimport) BOOL   WINAPI HeapFree(HANDLE, DWORD, PVOID)
#define KERNEL32$HeapReAlloc            __declspec(dllimport) PVOID  WINAPI HeapReAlloc(HANDLE, DWORD, PVOID, SIZE_T)
#define KERNEL32$LocalFree              __declspec(dllimport) PVOID  WINAPI LocalFree(PVOID)
#define KERNEL32$GetLastError           __declspec(dllimport) DWORD  WINAPI GetLastError(void)
#define KERNEL32$SetLastError           __declspec(dllimport) void   WINAPI SetLastError(DWORD)
#define KERNEL32$GetCurrentProcess      __declspec(dllimport) HANDLE WINAPI GetCurrentProcess(void)
#define KERNEL32$WideCharToMultiByte    __declspec(dllimport) int    WINAPI WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, PBOOL)
#define KERNEL32$MultiByteToWideChar    __declspec(dllimport) int    WINAPI MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int)
#define KERNEL32$lstrlenW               __declspec(dllimport) int    WINAPI lstrlenW(LPCWSTR)
#define KERNEL32$lstrlenA               __declspec(dllimport) int    WINAPI lstrlenA(LPCSTR)
#define KERNEL32$lstrcmpW               __declspec(dllimport) int    WINAPI lstrcmpW(LPCWSTR, LPCWSTR)
#define KERNEL32$GetComputerNameExW     __declspec(dllimport) BOOL   WINAPI GetComputerNameExW(int, LPWSTR, PDWORD)
#define MSVCRT$sprintf                  __declspec(dllimport) int    __cdecl sprintf(char*, const char*, ...)
#define MSVCRT$swprintf                 __declspec(dllimport) int    __cdecl swprintf(wchar_t*, const wchar_t*, ...)
#define MSVCRT$wcslen                   __declspec(dllimport) size_t __cdecl wcslen(const wchar_t*)
#define MSVCRT$wcscpy                   __declspec(dllimport) wchar_t* __cdecl wcscpy(wchar_t*, const wchar_t*)
#define MSVCRT$wcscat                   __declspec(dllimport) wchar_t* __cdecl wcscat(wchar_t*, const wchar_t*)
#define MSVCRT$wcscmp                   __declspec(dllimport) int    __cdecl wcscmp(const wchar_t*, const wchar_t*)
#define MSVCRT$memset                   __declspec(dllimport) void*  __cdecl memset(void*, int, size_t)
#define MSVCRT$memcpy                   __declspec(dllimport) void*  __cdecl memcpy(void*, const void*, size_t)
#define MSVCRT$memcmp                   __declspec(dllimport) int    __cdecl memcmp(const void*, const void*, size_t)
#define MSVCRT$strlen                   __declspec(dllimport) size_t __cdecl strlen(const char*)
#define MSVCRT$strncpy                  __declspec(dllimport) char*  __cdecl strncpy(char*, const char*, size_t)
#define MSVCRT$snprintf                 __declspec(dllimport) int    __cdecl snprintf(char*, size_t, const char*, ...)
#define MSVCRT$_wcsnicmp                __declspec(dllimport) int    __cdecl _wcsnicmp(const wchar_t*, const wchar_t*, size_t)
#define MSVCRT$_strnicmp                __declspec(dllimport) int    __cdecl _strnicmp(const char*, const char*, size_t)

/* Code page constants */
#define CP_UTF8     65001
#define CP_ACP      0

#ifdef __cplusplus
}
#endif

#endif /* BEACON_H */
