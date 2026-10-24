// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#ifndef RESOLVE_APIS_H
#define RESOLVE_APIS_H

#include "Common.h"
#include "ReadThroughGadgets.h"

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#ifdef __cplusplus
extern "C" {
#endif

    UINT32 HashStringCrc32bA(IN PCHAR pszString);
    UINT32 HashIStringCrc32bA(IN PCHAR pszString);

    UINT32 HashStringCrc32bW(IN PWCHAR pwszString);
    UINT32 HashIStringCrc32bW(IN PWCHAR pwszString);

#ifdef __cplusplus
}
#endif

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#define HASH_STRING_A(STR)			HashStringCrc32bA((PCHAR)(STR))
#define HASH_STRING_A_CI(STR)		HashIStringCrc32bA((PCHAR)(STR))

#define HASH_STRING_W(STR)			HashStringCrc32bW((PWCHAR)(STR))
#define HASH_STRING_W_CI(STR)		HashIStringCrc32bW((PWCHAR)(STR))

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#ifdef __cplusplus
extern "C" {
#endif

    HMODULE GetModuleHandleH(IN UINT32 uModuleNameHash);

    BOOL GetModuleInfoFromHandle(IN OPTIONAL HMODULE hModule, OUT OPTIONAL PWSTR pwszModuleName, OUT OPTIONAL PWSTR pwszFullPath);

    FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uFunctionNameHash);

#ifdef __cplusplus
}
#endif


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#pragma region API_SET_DATA_DIFENITIONS

/*
* 
* https://github.com/ajkhoury/ApiSet
*
*/

#define API_SET_SCHEMA_VERSION_V2       0x00000002
#define API_SET_SCHEMA_VERSION_V3       0x00000003 
#define API_SET_SCHEMA_VERSION_V4       0x00000004
#define API_SET_SCHEMA_VERSION_V6       0x00000006

#define API_SET_PREFIX_API              (ULONGLONG)0x002D004900500041 /* L"api-" */
#define API_SET_PREFIX_EXT              (ULONGLONG)0x002D005400580045 /* L"ext-" */
    
#define CHAR_TO_LOWER_W(wc)             (((WCHAR)((wc) - L'A') <= (L'Z' - L'A')) ? ((wc) | 0x20) : (wc))

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;  // API_SET_NAMESPACE_ENTRY_V6
    ULONG HashOffset;   // API_SET_NAMESPACE_HASH_ENTRY_V6
    ULONG HashFactor;
} API_SET_NAMESPACE_V6, * PAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, * PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_HASH_ENTRY_V6 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY_V6, * PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, * PAPI_SET_VALUE_ENTRY_V6;

typedef const API_SET_VALUE_ENTRY_V6* PCAPI_SET_VALUE_ENTRY_V6;
typedef const API_SET_HASH_ENTRY_V6* PCAPI_SET_HASH_ENTRY_V6;
typedef const API_SET_NAMESPACE_ENTRY_V6* PCAPI_SET_NAMESPACE_ENTRY_V6;
typedef const API_SET_NAMESPACE_V6* PCAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;        // 0x00
    ULONG NameOffset;   // 0x04
    ULONG NameLength;   // 0x08
    ULONG ValueOffset;  // 0x0C
    ULONG ValueLength;  // 0x10
} API_SET_VALUE_ENTRY_V4, * PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4 {
    ULONG Flags;        // 0x00
    ULONG Count;        // 0x04
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, * PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V4
} API_SET_NAMESPACE_ENTRY_V4, * PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
    ULONG Version;      // 0x00
    ULONG Size;         // 0x04
    ULONG Flags;        // 0x08
    ULONG Count;        // 0x0C
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, * PAPI_SET_NAMESPACE_ARRAY_V4;

typedef const API_SET_VALUE_ENTRY_V4* PCAPI_SET_VALUE_ENTRY_V4;
typedef const API_SET_VALUE_ARRAY_V4* PCAPI_SET_VALUE_ARRAY_V4;
typedef const API_SET_NAMESPACE_ENTRY_V4* PCAPI_SET_NAMESPACE_ENTRY_V4;
typedef const API_SET_NAMESPACE_ARRAY_V4* PCAPI_SET_NAMESPACE_ARRAY_V4;

typedef struct _API_SET_VALUE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V3, * PAPI_SET_VALUE_ENTRY_V3;

typedef struct _API_SET_VALUE_ARRAY_V3 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V3, * PAPI_SET_VALUE_ARRAY_V3;

typedef struct _API_SET_NAMESPACE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V3
} API_SET_NAMESPACE_ENTRY_V3, * PAPI_SET_NAMESPACE_ENTRY_V3;

typedef struct _API_SET_NAMESPACE_ARRAY_V3 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V3, * PAPI_SET_NAMESPACE_ARRAY_V3;

typedef const API_SET_VALUE_ENTRY_V3* PCAPI_SET_VALUE_ENTRY_V3;
typedef const API_SET_VALUE_ARRAY_V3* PCAPI_SET_VALUE_ARRAY_V3;
typedef const API_SET_NAMESPACE_ENTRY_V3* PCAPI_SET_NAMESPACE_ENTRY_V3;
typedef const API_SET_NAMESPACE_ARRAY_V3* PCAPI_SET_NAMESPACE_ARRAY_V3;

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, * PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, * PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V2
} API_SET_NAMESPACE_ENTRY_V2, * PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, * PAPI_SET_NAMESPACE_ARRAY_V2;

typedef const API_SET_VALUE_ENTRY_V2* PCAPI_SET_VALUE_ENTRY_V2;
typedef const API_SET_VALUE_ARRAY_V2* PCAPI_SET_VALUE_ARRAY_V2;
typedef const API_SET_NAMESPACE_ENTRY_V2* PCAPI_SET_NAMESPACE_ENTRY_V2;
typedef const API_SET_NAMESPACE_ARRAY_V2* PCAPI_SET_NAMESPACE_ARRAY_V2;

#pragma endregion 



#endif // !RESOLVE_APIS_H
