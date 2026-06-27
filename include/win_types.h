/**
 * @file win_types.h
 * @brief Standalone Windows type definitions for BOF compilation.
 *
 * This header provides a self-contained set of Windows types, structures,
 * and constants required for Beacon Object File development without relying
 * on the full Windows SDK. Designed for cross-compilation with MinGW-w64.
 *
 * Structures are defined for 64-bit (x86_64) targets matching the in-memory
 * layout used by the Windows NT kernel.
 *
 * @author  PhantomLDAP Project
 * @version 1.0.0
 */

#ifndef PHANTOM_WIN_TYPES_H
#define PHANTOM_WIN_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Primitive Types
 * ========================================================================= */

typedef unsigned char       BYTE;
typedef unsigned char       UCHAR;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef unsigned int        UINT;
typedef unsigned long       ULONG;
typedef unsigned long long  ULONG64;
typedef unsigned long long  ULONGLONG;
typedef unsigned long long  QWORD;

typedef signed char         CHAR;
typedef signed short        SHORT;
typedef signed long         LONG;
typedef signed long long    LONGLONG;
typedef signed long long    LONG64;

typedef int                 BOOL;
typedef int                 INT;
typedef long                HRESULT;

typedef unsigned long       DWORD;
typedef unsigned long long  DWORD64;

typedef wchar_t             WCHAR;
typedef char               *PSTR;
typedef char               *LPSTR;
typedef const char         *PCSTR;
typedef const char         *LPCSTR;
typedef wchar_t            *PWSTR;
typedef wchar_t            *LPWSTR;
typedef const wchar_t      *PCWSTR;
typedef const wchar_t      *LPCWSTR;

typedef void               *PVOID;
typedef void               *LPVOID;
typedef const void         *LPCVOID;
typedef void                VOID;

typedef BYTE               *PBYTE;
typedef WORD               *PWORD;
typedef DWORD              *PDWORD;
typedef ULONG              *PULONG;
typedef BOOL               *PBOOL;
typedef PVOID              *PPVOID;
typedef LONG               *PLONG;

#ifdef _WIN64
typedef unsigned long long  SIZE_T;
typedef signed long long    SSIZE_T;
typedef unsigned long long  ULONG_PTR;
typedef signed long long    LONG_PTR;
typedef unsigned long long  DWORD_PTR;
#else
typedef unsigned long       SIZE_T;
typedef signed long         SSIZE_T;
typedef unsigned long       ULONG_PTR;
typedef signed long         LONG_PTR;
typedef unsigned long       DWORD_PTR;
#endif

typedef SIZE_T             *PSIZE_T;
typedef ULONG_PTR          *PULONG_PTR;

/* Handles */
typedef void               *HANDLE;
typedef HANDLE             *PHANDLE;
typedef HANDLE              HMODULE;
typedef HANDLE              HINSTANCE;
typedef HANDLE              HKEY;

/* =========================================================================
 * Boolean Constants
 * ========================================================================= */

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif
#ifndef NULL
#define NULL    ((void*)0)
#endif

/* =========================================================================
 * Calling Conventions
 * ========================================================================= */

#ifndef WINAPI
#define WINAPI  __stdcall
#endif
#ifndef NTAPI
#define NTAPI   __stdcall
#endif
#ifndef CALLBACK
#define CALLBACK __stdcall
#endif
#ifndef CDECL
#define CDECL   __cdecl
#endif

/* =========================================================================
 * NT Status Codes
 * ========================================================================= */

#define STATUS_SUCCESS                  ((LONG)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((LONG)0xC0000001L)
#define STATUS_NOT_FOUND                ((LONG)0xC0000225L)
#define STATUS_NO_MEMORY                ((LONG)0xC0000017L)
#define STATUS_ACCESS_DENIED            ((LONG)0xC0000022L)

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* =========================================================================
 * Error Codes
 * ========================================================================= */

#define ERROR_SUCCESS                   0L
#define ERROR_INVALID_PARAMETER         87L
#define ERROR_INSUFFICIENT_BUFFER       122L
#define ERROR_NO_MORE_ITEMS             259L
#define INVALID_HANDLE_VALUE            ((HANDLE)(LONG_PTR)-1)

/* =========================================================================
 * Heap Flags
 * ========================================================================= */

#define HEAP_ZERO_MEMORY                0x00000008
#define HEAP_NO_SERIALIZE               0x00000001

/* =========================================================================
 * String / Buffer Limits
 * ========================================================================= */

#define MAX_PATH                        260
#define ANYSIZE_ARRAY                   1

/* =========================================================================
 * NT Kernel Structures (x64 Layout)
 * ========================================================================= */

/**
 * @brief Unicode string as used by Windows NT kernel.
 * @note Length and MaximumLength are byte counts, NOT character counts.
 */
typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ANSI_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PSTR    Buffer;
} ANSI_STRING, *PANSI_STRING;

/**
 * @brief Doubly-linked list entry.
 */
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/**
 * @brief Single-linked list entry.
 */
typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

/* =========================================================================
 * PEB / TEB Structures (x64 — Windows 10+)
 *
 * Offsets verified against:
 *   - Windows 10 21H2 (Build 19044)
 *   - Windows 11 22H2 (Build 22621)
 *   - Windows Server 2019/2022
 *
 * Reference: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/
 * ========================================================================= */

/**
 * @brief Entry in the PEB loader's module list.
 *
 * Each loaded DLL has a corresponding LDR_DATA_TABLE_ENTRY. The three
 * list heads (InLoadOrder, InMemoryOrder, InInitializationOrder) all
 * chain through different LIST_ENTRY fields within this structure.
 *
 * @note When walking InMemoryOrderModuleList, the FLINK pointer points
 *       to the InMemoryOrderLinks field, so subtract
 *       offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) to get the
 *       base of the entry.
 */
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY      InLoadOrderLinks;           /* +0x000 */
    LIST_ENTRY      InMemoryOrderLinks;         /* +0x010 */
    LIST_ENTRY      InInitializationOrderLinks; /* +0x020 */
    PVOID           DllBase;                    /* +0x030 — Base VA of mapped image */
    PVOID           EntryPoint;                 /* +0x038 */
    ULONG           SizeOfImage;               /* +0x040 */
    ULONG           _pad0;                     /* +0x044 — alignment */
    UNICODE_STRING  FullDllName;               /* +0x048 */
    UNICODE_STRING  BaseDllName;               /* +0x058 */
    ULONG           Flags;                     /* +0x068 */
    USHORT          LoadCount;                 /* +0x06C */
    USHORT          TlsIndex;                 /* +0x06E */
    /* ... additional fields omitted (not needed for enumeration) */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/**
 * @brief PEB loader data — contains the three module list heads.
 */
typedef struct _PEB_LDR_DATA {
    ULONG       Length;                                 /* +0x000 */
    BOOL        Initialized;                            /* +0x004 */
    HANDLE      SsHandle;                              /* +0x008 */
    LIST_ENTRY  InLoadOrderModuleList;                 /* +0x010 */
    LIST_ENTRY  InMemoryOrderModuleList;               /* +0x020 */
    LIST_ENTRY  InInitializationOrderModuleList;       /* +0x030 */
    PVOID       EntryInProgress;                       /* +0x040 */
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/**
 * @brief Process Environment Block (partial, x64).
 *
 * Only fields required for PEB walking are defined here.
 * The full PEB on Windows 10 x64 is > 0x7B0 bytes.
 */
typedef struct _PEB {
    BYTE            InheritedAddressSpace;      /* +0x000 */
    BYTE            ReadImageFileExecOptions;   /* +0x001 */
    BYTE            BeingDebugged;              /* +0x002 */
    BYTE            BitField;                  /* +0x003 */
    BYTE            _pad0[4];                  /* +0x004 */
    HANDLE          Mutant;                    /* +0x008 */
    PVOID           ImageBaseAddress;          /* +0x010 */
    PPEB_LDR_DATA   Ldr;                       /* +0x018 — Pointer to loader data */
    /* ... fields not needed for module resolution omitted */
} PEB, *PPEB;

/**
 * @brief Thread Environment Block (partial, x64).
 *
 * The TEB is accessible via the GS segment register on x64:
 *   GS:[0x00] = TEB base (NtCurrentTeb())
 *   GS:[0x30] = pointer to self (TEB.Self)
 *   GS:[0x60] = pointer to PEB
 */
typedef struct _TEB {
    BYTE    _reserved[0x60]; /* +0x000 .. +0x05F — NT_TIB + reserved fields */
    PPEB    ProcessEnvironmentBlock; /* +0x060 */
} TEB, *PTEB;

/* =========================================================================
 * PE / Image Structures
 * ========================================================================= */

#define IMAGE_DOS_SIGNATURE             0x5A4D      /* MZ */
#define IMAGE_NT_SIGNATURE              0x00004550  /* PE\0\0 */
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0

typedef struct _IMAGE_DOS_HEADER {
    WORD    e_magic;
    WORD    e_cblp;
    WORD    e_cp;
    WORD    e_crlc;
    WORD    e_cparhdr;
    WORD    e_minalloc;
    WORD    e_maxalloc;
    WORD    e_ss;
    WORD    e_sp;
    WORD    e_csum;
    WORD    e_ip;
    WORD    e_cs;
    WORD    e_lfarlc;
    WORD    e_ovno;
    WORD    e_res[4];
    WORD    e_oemid;
    WORD    e_oeminfo;
    WORD    e_res2[10];
    LONG    e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    ULONGLONG ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

/* =========================================================================
 * Security / SID Structures (for DACL parsing)
 * ========================================================================= */

/** SID authority identifier (6 bytes, big-endian) */
typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE    Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

/** Security Identifier */
typedef struct _SID {
    BYTE    Revision;
    BYTE    SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD   SubAuthority[ANYSIZE_ARRAY];
} SID, *PSID;

/** ACL Header */
typedef struct _ACL {
    BYTE    AclRevision;
    BYTE    Sbz1;
    WORD    AclSize;
    WORD    AceCount;
    WORD    Sbz2;
} ACL, *PACL;

/** Generic ACE header present at the start of every ACE */
typedef struct _ACE_HEADER {
    BYTE    AceType;
    BYTE    AceFlags;
    WORD    AceSize;
} ACE_HEADER, *PACE_HEADER;

/** Standard access-allowed ACE */
typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER  Header;
    DWORD       Mask;
    DWORD       SidStart;  /* Variable-length SID follows */
} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;

/** Standard access-denied ACE */
typedef struct _ACCESS_DENIED_ACE {
    ACE_HEADER  Header;
    DWORD       Mask;
    DWORD       SidStart;
} ACCESS_DENIED_ACE, *PACCESS_DENIED_ACE;

/** Object-specific ACE (used for AD extended rights, property rights) */
typedef struct _ACCESS_ALLOWED_OBJECT_ACE {
    ACE_HEADER  Header;
    DWORD       Mask;
    DWORD       Flags;
    BYTE        ObjectType[16];         /* GUID */
    BYTE        InheritedObjectType[16];/* GUID */
    DWORD       SidStart;
} ACCESS_ALLOWED_OBJECT_ACE, *PACCESS_ALLOWED_OBJECT_ACE;

/** GUID structure */
typedef struct _GUID {
    DWORD   Data1;
    WORD    Data2;
    WORD    Data3;
    BYTE    Data4[8];
} GUID;

/** Security Descriptor (absolute format) */
typedef struct _SECURITY_DESCRIPTOR {
    BYTE    Revision;
    BYTE    Sbz1;
    WORD    Control;
    PSID    Owner;
    PSID    Group;
    PACL    Sacl;
    PACL    Dacl;
} SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;

/* Security descriptor control flags */
#define SE_OWNER_DEFAULTED              0x0001
#define SE_GROUP_DEFAULTED              0x0002
#define SE_DACL_PRESENT                 0x0004
#define SE_DACL_DEFAULTED               0x0008
#define SE_SACL_PRESENT                 0x0010
#define SE_SACL_DEFAULTED               0x0020
#define SE_SELF_RELATIVE                0x8000

/* ACE types */
#define ACCESS_ALLOWED_ACE_TYPE         0x00
#define ACCESS_DENIED_ACE_TYPE          0x01
#define SYSTEM_AUDIT_ACE_TYPE           0x02
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE  0x05
#define ACCESS_DENIED_OBJECT_ACE_TYPE   0x06
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE    0x07
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE 0x09
#define ACCESS_DENIED_CALLBACK_ACE_TYPE  0x0A

/* ACE flags */
#define OBJECT_INHERIT_ACE              0x01
#define CONTAINER_INHERIT_ACE           0x02
#define NO_PROPAGATE_INHERIT_ACE        0x04
#define INHERIT_ONLY_ACE                0x08
#define INHERITED_ACE                   0x10
#define SUCCESSFUL_ACCESS_ACE_FLAG      0x40
#define FAILED_ACCESS_ACE_FLAG          0x80

/* Object ACE flags */
#define ACE_OBJECT_TYPE_PRESENT         0x00000001
#define ACE_INHERITED_OBJECT_TYPE_PRESENT 0x00000002

/* AD Extended Rights GUIDs (commonly abused) */
/* All-Extended-Rights: {00000000-0000-0000-0000-000000000000} */
/* DS-Replication-Get-Changes-All: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} */
/* WriteDACL: mapped to RIGHT_DS_WRITE_DAC */

/* Active Directory access mask bits */
#define ADS_RIGHT_DS_CREATE_CHILD       0x00000001
#define ADS_RIGHT_DS_DELETE_CHILD       0x00000002
#define ADS_RIGHT_ACTRL_DS_LIST         0x00000004
#define ADS_RIGHT_DS_SELF               0x00000008
#define ADS_RIGHT_DS_READ_PROP          0x00000010
#define ADS_RIGHT_DS_WRITE_PROP         0x00000020
#define ADS_RIGHT_DS_DELETE_TREE        0x00000040
#define ADS_RIGHT_DS_LIST_OBJECT        0x00000080
#define ADS_RIGHT_DS_CONTROL_ACCESS     0x00000100
#define RIGHT_DELETE                    0x00010000
#define RIGHT_READ_CONTROL              0x00020000
#define RIGHT_WRITE_DAC                 0x00040000
#define RIGHT_WRITE_OWNER               0x00080000
#define RIGHT_GENERIC_READ              0x80000000
#define RIGHT_GENERIC_WRITE             0x40000000
#define RIGHT_GENERIC_EXECUTE           0x20000000
#define RIGHT_GENERIC_ALL               0x10000000

/* =========================================================================
 * FILETIME and related
 * ========================================================================= */

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

/* FILETIME epoch: January 1, 1601 */
/* Unix epoch offset: 116444736000000000 100-nanosecond intervals */
#define FILETIME_TO_UNIX_OFFSET     116444736000000000ULL
#define FILETIME_TICKS_PER_SEC      10000000ULL

/* =========================================================================
 * Inline Helpers
 * ========================================================================= */

/**
 * @brief Retrieve a pointer to the current thread's TEB.
 * @return Pointer to TEB (via GS segment register on x64).
 */
static __inline PTEB NtCurrentTeb(void) {
    PTEB teb;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));
#else
    __asm__ volatile ("movl %%fs:0x18, %0" : "=r"(teb));
#endif
    return teb;
}

/**
 * @brief Retrieve a pointer to the current process's PEB.
 * @return Pointer to PEB.
 */
static __inline PPEB NtCurrentPeb(void) {
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

/**
 * @brief Get the process heap handle.
 */
static __inline HANDLE PhantomGetProcessHeap(void) {
    /* PEB.ProcessHeap is at offset 0x30 on x64 */
    return *((HANDLE *)((PBYTE)NtCurrentPeb() + 0x30));
}

#ifdef __cplusplus
}
#endif

#endif /* PHANTOM_WIN_TYPES_H */
