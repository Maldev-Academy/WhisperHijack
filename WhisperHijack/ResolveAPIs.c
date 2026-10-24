// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#include "ResolveAPIs.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

/*
*
* Based on https://github.com/ajkhoury/ApiSet
*
*/

#pragma region RESOLVE_API_SET_APIS

static PAPI_SET_NAMESPACE_ENTRY_V6 SearchApiSetV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PWSTR pwszApiSetName, IN USHORT usNameLen)
{
    PWCHAR                      pwcCurrent         = NULL;
    DWORD                       dwHashKey          = 0x00;
    DWORD                       dwHashFactor       = 0x00;
    DWORD                       dwHashOffset       = 0x00;
    DWORD                       dwEntryOffset      = 0x00;
    DWORD                       dwCount            = 0x00;
    DWORD                       dwHashedLen        = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    DWORD                       dwEntryHash        = 0x00;
    DWORD                       dwEntryIndex       = 0x00;
    USHORT                      usCount            = 0x00;
    PAPI_SET_HASH_ENTRY_V6      pHashEntry         = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V6 pFoundEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;

    if (!pApiSetMap || !pwszApiSetName || !usNameLen) return NULL;

    // Cache namespace header fields (read once via gadget)
    dwHashFactor    = READ_DWORD(pApiSetMap, API_SET_NAMESPACE_V6, HashFactor);
    dwHashOffset    = READ_DWORD(pApiSetMap, API_SET_NAMESPACE_V6, HashOffset);
    dwEntryOffset   = READ_DWORD(pApiSetMap, API_SET_NAMESPACE_V6, EntryOffset);
    dwCount         = READ_DWORD(pApiSetMap, API_SET_NAMESPACE_V6, Count);

    if (!dwCount) return NULL;

    // Calculate hash for API Set name
    pwcCurrent = pwszApiSetName;
    usCount = usNameLen;
    while (usCount)
    {
        dwHashKey = dwHashKey * dwHashFactor + (USHORT)CHAR_TO_LOWER_W(*pwcCurrent);
        pwcCurrent++;
        usCount--;
    }

    // Binary search in hash table
    dwLeft = 0x00;
    dwRight = dwCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pHashEntry = (PAPI_SET_HASH_ENTRY_V6)((PBYTE)pApiSetMap + dwHashOffset + (dwMid * sizeof(API_SET_HASH_ENTRY_V6)));

        dwEntryHash = READ_DWORD(pHashEntry, API_SET_HASH_ENTRY_V6, Hash);

        if (dwHashKey < dwEntryHash)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (dwHashKey > dwEntryHash)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            // Found hash match - get entry
            dwEntryIndex = READ_DWORD(pHashEntry, API_SET_HASH_ENTRY_V6, Index);
            pFoundEntry  = (PAPI_SET_NAMESPACE_ENTRY_V6)((PBYTE)pApiSetMap + dwEntryOffset + (dwEntryIndex * sizeof(API_SET_NAMESPACE_ENTRY_V6)));
            break;
        }
    }

    if (!pFoundEntry) return NULL;

    // Verify name match (hash collision check)
    pwszEntryName = (PWCHAR)((PBYTE)pApiSetMap + READ_DWORD(pFoundEntry, API_SET_NAMESPACE_ENTRY_V6, NameOffset));
    dwHashedLen   = READ_DWORD(pFoundEntry, API_SET_NAMESPACE_ENTRY_V6, HashedLength) / sizeof(WCHAR);

    // Manual case-insensitive comparison
    for (DWORD i = 0; i < dwHashedLen; i++)
    {
        WCHAR wc1 = CHAR_TO_LOWER_W(pwszApiSetName[i]);                          // stack - directly
        // The CHAR_TO_LOWER_W macro evaluates its argument three times
        // Meaning, we would run our gadget three time if we called it like this:
        // wc2 = CHAR_TO_LOWER_W((WCHAR)READ_WORD_RAW(&pwszEntryName[i]))
        // So, we are saving it locally first. We'll do this to the following 
        // Api Set functions below as well.
        WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszEntryName[i]);                   // ApiSet map - via gadgeted
        WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);                                     
        if (wc1 != wc2) return NULL;
    }

    return pFoundEntry;
}

static PAPI_SET_VALUE_ENTRY_V6 SearchApiSetHostV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PAPI_SET_NAMESPACE_ENTRY_V6 pEntry, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    DWORD                   dwValueOffset  = 0x00;
    DWORD                   dwValueCount   = 0x00;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;
    PAPI_SET_VALUE_ENTRY_V6 pValueEntry    = NULL;
    PAPI_SET_VALUE_ENTRY_V6 pHostEntry     = NULL;
    PWCHAR                  pwszHostName   = NULL;
    LONG                    lCompare       = 0x00;

    if (!pEntry || !pApiSetMap) return NULL;

    // Cache namespace entry fields
    dwValueOffset = READ_DWORD(pEntry, API_SET_NAMESPACE_ENTRY_V6, ValueOffset);
    dwValueCount  = READ_DWORD(pEntry, API_SET_NAMESPACE_ENTRY_V6, ValueCount);

    // Get default entry (first one)
    pValueEntry = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + dwValueOffset);

    // If only one entry or no parent specified, return default
    if (dwValueCount <= 1 || !pwszParentName || !usParentLen)
        return pValueEntry;

    // Binary search for matching host (skip first entry)
    dwLeft = 1;
    dwRight = dwValueCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pHostEntry    = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + dwValueOffset + (dwMid * sizeof(API_SET_VALUE_ENTRY_V6)));
        pwszHostName  = (PWCHAR)((PBYTE)pApiSetMap + READ_DWORD(pHostEntry, API_SET_VALUE_ENTRY_V6, NameOffset));
        dwHostNameLen = READ_DWORD(pHostEntry, API_SET_VALUE_ENTRY_V6, NameLength) / sizeof(WCHAR);

        // Compare names
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);                          // stack - safe
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszHostName[i]);                    // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);                                     
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pHostEntry;
        }
    }

    return pValueEntry; // Return default if not found
}

static BOOL ResolveApiSetV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    PWCHAR                      pwcCurrent         = NULL;
    DWORD                       dwApiSetLen        = 0x00;
    DWORD                       dwValueCount       = 0x00;
    DWORD                       dwValueOffset      = 0x00;
    USHORT                      usNameNoExtLen     = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V6 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ENTRY_V6     pValueEntry        = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetMap || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Check minimum length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    if (dwApiSetLen < 4) return FALSE; // Need at least "api-" or "ext-"

    // Verify prefix (api- or ext-)
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Trick to convert the chars to uppercase.

    if (ullPrefix != API_SET_PREFIX_API && // "API-"
        ullPrefix != API_SET_PREFIX_EXT)   // "EXT-"
        return FALSE;

    // Find length without version suffix (stop at last hyphen)
    pwcCurrent = (PWCHAR)pwszApiSetName + dwApiSetLen;
    usNameNoExtLen = (USHORT)dwApiSetLen;
    while (usNameNoExtLen > 0)
    {
        pwcCurrent--;
        usNameNoExtLen--;
        if (*pwcCurrent == L'-') break;
    }

    if (!usNameNoExtLen) return FALSE;

    // Search for API Set entry
    pNamespaceEntry = SearchApiSetV6(pApiSetMap, (PWSTR)pwszApiSetName, usNameNoExtLen);
    if (!pNamespaceEntry) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Cache namespace entry fields
    dwValueCount  = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V6, ValueCount);
    dwValueOffset = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V6, ValueOffset);

    // Find appropriate host entry
    if (dwValueCount > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV6(pApiSetMap, pNamespaceEntry, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }
    else if (dwValueCount > 0)
    {
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + dwValueOffset);
    }
    else
    {
        return FALSE;
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetMap + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V6, ValueOffset));
    dwResolvedLen    = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V6, ValueLength) / sizeof(WCHAR);

    if (dwResolvedLen >= dwMaxLen) return FALSE;

    // Copy resolved name via gadget
    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = (WCHAR)READ_WORD_RAW(&pwszResolvedName[i]);
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_NAMESPACE_ENTRY_V4 SearchApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PWSTR pwszApiSetName, IN USHORT usNameLen)
{
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    DWORD                       dwCount            = 0x00;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V4 pNamespaceEntry    = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !usNameLen) return NULL;

    dwCount = READ_DWORD(pApiSetArray, API_SET_NAMESPACE_ARRAY_V4, Count);
    if (!dwCount) return NULL;

    dwLeft = 0x00;
    dwRight = dwCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid           = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V4)((PBYTE)pApiSetArray + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V4, Array) + (dwMid * sizeof(API_SET_NAMESPACE_ENTRY_V4)));
        pwszEntryName   = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V4, NameOffset));
        dwEntryNameLen  = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V4, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameLen, dwEntryNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszApiSetName[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszEntryName[i]);                   // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usNameLen != dwEntryNameLen)
            lCompare = (usNameLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pNamespaceEntry;
        }
    }

    return NULL;
}

static PAPI_SET_VALUE_ENTRY_V4 SearchApiSetHostV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V4 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    DWORD                   dwValueCount   = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V4 pHostEntry     = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray) return NULL;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V4, Count);
    if (dwValueCount <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = dwValueCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid         = dwLeft + (dwRight - dwLeft) / 2;
        pHostEntry    = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array) + (dwMid * sizeof(API_SET_VALUE_ENTRY_V4)));
        pwszHostName  = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pHostEntry, API_SET_VALUE_ENTRY_V4, NameOffset));
        dwHostNameLen = READ_DWORD(pHostEntry, API_SET_VALUE_ENTRY_V4, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszHostName[i]);                    // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pHostEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    DWORD                       dwDataOffset       = 0x00;
    DWORD                       dwValueCount       = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V4 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V4     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V4     pValueEntry        = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);

    // Check minimum length (need at least "api-xxxx")
    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix (api- or ext-)
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Trick to convert the chars to uppercase.

    if (ullPrefix != API_SET_PREFIX_API && // "API-"
        ullPrefix != API_SET_PREFIX_EXT)   // "EXT-"
        return FALSE;

    // Skip prefix ("api-" or "ext-" = 4 chars)
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen   = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Search for API Set entry
    pNamespaceEntry = SearchApiSetV4(pApiSetArray, pwszNameNoPrefix, usNameNoExtLen);
    if (!pNamespaceEntry) return FALSE;

    // Get value array
    dwDataOffset = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V4, DataOffset);
    pValueArray  = (PAPI_SET_VALUE_ARRAY_V4)((PBYTE)pApiSetArray + dwDataOffset);
    if (!pValueArray) return FALSE;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V4, Count);
    if (dwValueCount == 0) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    if (dwValueCount > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV4(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
        if (!pValueEntry)
            pValueEntry = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array)); // Default to first entry
    }
    else
    {
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V4)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array)); // Use first entry
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V4, ValueOffset));
    dwResolvedLen    = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V4, ValueLength) / sizeof(WCHAR);

    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = (WCHAR)READ_WORD_RAW(&pwszResolvedName[i]);
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V3 SearchApiSetHostV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V3 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    DWORD                   dwValueCount   = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V3 pValueEntry    = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray) return NULL;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V3, Count);
    if (dwValueCount <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = dwValueCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid         = dwLeft + (dwRight - dwLeft) / 2;
        pValueEntry   = (PAPI_SET_VALUE_ENTRY_V3)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V3, Array) + (dwMid * sizeof(API_SET_VALUE_ENTRY_V3)));
        pwszHostName  = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V3, NameOffset));
        dwHostNameLen = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V3, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszHostName[i]);                    // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pValueEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    DWORD                       dwArrayCount       = 0x00;
    DWORD                       dwDataOffset       = 0x00;
    DWORD                       dwValueCount       = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    BOOL                        bFound             = FALSE;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V3 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V3     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V3     pValueEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);

    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Trick to convert the chars to uppercase.

    if (ullPrefix != API_SET_PREFIX_API && // "API-"
        ullPrefix != API_SET_PREFIX_EXT)   // "EXT-"
        return FALSE;

    // Skip prefix
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen   = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Cache array count
    dwArrayCount = READ_DWORD(pApiSetArray, API_SET_NAMESPACE_ARRAY_V3, Count);
    if (!dwArrayCount) return FALSE;

    // Binary search for API Set entry
    dwLeft  = 0x00;
    dwRight = dwArrayCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid           = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V3)((PBYTE)pApiSetArray + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V3, Array) + (dwMid * sizeof(API_SET_NAMESPACE_ENTRY_V3)));
        pwszEntryName   = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V3, NameOffset));
        dwEntryNameLen  = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V3, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameNoExtLen, dwEntryNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNameNoPrefix[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszEntryName[i]);                   // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usNameNoExtLen != dwEntryNameLen)
            lCompare = (usNameNoExtLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound || !pNamespaceEntry) return FALSE;

    // Get value array
    dwDataOffset = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V3, DataOffset);
    pValueArray  = (PAPI_SET_VALUE_ARRAY_V3)((PBYTE)pApiSetArray + dwDataOffset);
    if (!pValueArray) return FALSE;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V3, Count);
    if (dwValueCount == 0) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    pValueEntry = NULL;
    if (dwValueCount > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV3(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }

    // Default to first entry if not found or no parent specified
    if (!pValueEntry)
    {
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V3)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V3, Array));
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V3, ValueOffset));
    dwResolvedLen    = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V3, ValueLength) / sizeof(WCHAR);

    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = (WCHAR)READ_WORD_RAW(&pwszResolvedName[i]);
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V2 SearchApiSetHostV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V2 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    DWORD                   dwValueCount   = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V2 pValueEntry    = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray) return NULL;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V2, Count);
    if (dwValueCount <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = dwValueCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid         = dwLeft + (dwRight - dwLeft) / 2;
        pValueEntry   = (PAPI_SET_VALUE_ENTRY_V2)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V2, Array) + (dwMid * sizeof(API_SET_VALUE_ENTRY_V2)));
        pwszHostName  = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V2, NameOffset));
        dwHostNameLen = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V2, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszHostName[i]);                    // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pValueEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    DWORD                       dwArrayCount       = 0x00;
    DWORD                       dwDataOffset       = 0x00;
    DWORD                       dwValueCount       = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    BOOL                        bFound             = FALSE;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V2 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V2     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V2     pValueEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);

    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix (v2 only supports "api-")
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Trick to convert the chars to uppercase.

    if (ullPrefix != API_SET_PREFIX_API) // "API-"
        return FALSE;

    // Skip prefix
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen   = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Cache array count
    dwArrayCount = READ_DWORD(pApiSetArray, API_SET_NAMESPACE_ARRAY_V2, Count);
    if (!dwArrayCount) return FALSE;

    // Binary search for API Set entry
    dwLeft  = 0x00;
    dwRight = dwArrayCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid           = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V2)((PBYTE)pApiSetArray + FIELD_OFFSET(API_SET_NAMESPACE_ARRAY_V2, Array) + (dwMid * sizeof(API_SET_NAMESPACE_ENTRY_V2)));
        pwszEntryName   = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V2, NameOffset));
        dwEntryNameLen  = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V2, NameLength) / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameNoExtLen, dwEntryNameLen);
        lCompare = 0x00;

        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNameNoPrefix[i]);
            WCHAR wcRaw = (WCHAR)READ_WORD_RAW(&pwszEntryName[i]);                   // ApiSet map - via gadgeted
            WCHAR wc2 = CHAR_TO_LOWER_W(wcRaw);
            if (wc1 < wc2) { lCompare = -1; break; }
            else if (wc1 > wc2) { lCompare = 1; break; }
        }

        if (lCompare == 0 && usNameNoExtLen != dwEntryNameLen)
            lCompare = (usNameNoExtLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound || !pNamespaceEntry) return FALSE;

    // Get value array
    dwDataOffset = READ_DWORD(pNamespaceEntry, API_SET_NAMESPACE_ENTRY_V2, DataOffset);
    pValueArray  = (PAPI_SET_VALUE_ARRAY_V2)((PBYTE)pApiSetArray + dwDataOffset);
    if (!pValueArray) return FALSE;

    dwValueCount = READ_DWORD(pValueArray, API_SET_VALUE_ARRAY_V2, Count);
    if (dwValueCount == 0) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    pValueEntry = NULL;
    if (dwValueCount > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV2(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }

    // Default to first entry if not found or no parent specified
    if (!pValueEntry)
    {
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V2)((PBYTE)pValueArray + FIELD_OFFSET(API_SET_VALUE_ARRAY_V2, Array));
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V2, ValueOffset));
    dwResolvedLen    = READ_DWORD(pValueEntry, API_SET_VALUE_ENTRY_V2, ValueLength) / sizeof(WCHAR);

    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = (WCHAR)READ_WORD_RAW(&pwszResolvedName[i]);
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static BOOL ResolveApiSet(IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    PPEB                    pPeb            = NULL;
    PAPI_SET_NAMESPACE      pApiSetMap      = NULL;
    DWORD                   dwApiSetLen     = 0x00;
    DWORD                   dwParentLen     = 0x00;
    DWORD                   dwVersion       = 0x00;
    BOOL                    bResolved       = FALSE;

    if (!pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);

    if (dwApiSetLen < 8) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = NULL;
#endif

    if (!pPeb) return FALSE;

    // Read ApiSetMap pointer from PEB via gadget
    pApiSetMap = (PAPI_SET_NAMESPACE)READ_QWORD(pPeb, PEB, ApiSetMap);
    if (!pApiSetMap) return FALSE;

    // Version field is at offset 0 across all schema versions
    dwVersion = READ_DWORD(pApiSetMap, API_SET_NAMESPACE, Version);

    switch (dwVersion)
    {
        case API_SET_SCHEMA_VERSION_V2:
        {
            bResolved = ResolveApiSetV2((PAPI_SET_NAMESPACE_ARRAY_V2)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V3:
        {
            bResolved = ResolveApiSetV3((PAPI_SET_NAMESPACE_ARRAY_V3)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V4:
        {
            bResolved = ResolveApiSetV4((PAPI_SET_NAMESPACE_ARRAY_V4)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V6:
        {
            bResolved = ResolveApiSetV6((PAPI_SET_NAMESPACE_V6)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        default:
            return FALSE;
    }

    return bResolved;
}

#pragma endregion // RESOLVE_API_SET_APIS


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region RESOLVE_APIS



//
// Replaces GetModuleHandleA/W 
//
HMODULE GetModuleHandleH(IN UINT32 uModuleNameHash)
{
    PPEB                        pPeb                    = NtCurrentPeb();
    PPEB_LDR_DATA               pLdr                    = NULL;
    PLDR_DATA_TABLE_ENTRY       pEntry                  = NULL;
    PLIST_ENTRY                 pListHead               = NULL,
                                pListEntry              = NULL;
    ULONG_PTR                   uBaseDllNameAddr        = 0x00;
    PWCHAR                      pwzBaseDllName          = NULL;

    if (!pPeb) return NULL;

    // Get PEB Loader Data
    pLdr = (PPEB_LDR_DATA)READ_QWORD(pPeb, PEB, Ldr);
    if (!pLdr) return NULL;

    // Get InLoadOrderModuleList Head & First Entry
    pListHead   = (PLIST_ENTRY)((ULONG_PTR)pLdr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    pListEntry  = (PLIST_ENTRY)READ_QWORD(pListHead, LIST_ENTRY, Flink);
    pEntry      = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    // If Hash Is NULL, Return The First Module (The Process's Image)
    if (!uModuleNameHash)
    {
        return (HMODULE)READ_QWORD(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);
    }

    // Walk The Linked List & Compare Module Name Hash
    while (pListEntry != pListHead)
    {
        pEntry              = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        // Read BaseDllName.Buffer via gadget (nested field access isnt supported by our READ_* macros)
        uBaseDllNameAddr    = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseDllName);
        pwzBaseDllName      = (PWCHAR)ReadQwordViaGadget(uBaseDllNameAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));

        if (pwzBaseDllName && uModuleNameHash == HASH_STRING_W_CI(pwzBaseDllName))
        {
            // Get Module Base Address
            return (HMODULE)READ_QWORD(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);
        }

        // Advance To Next Entry
        pListEntry = (PLIST_ENTRY)READ_QWORD(pListEntry, LIST_ENTRY, Flink);
    }

    return NULL;
}


//
// Replaces GetModuleFileNameA/W 
//
BOOL GetModuleInfoFromHandle(IN OPTIONAL HMODULE hModule, OUT OPTIONAL PWSTR pwszModuleName, OUT OPTIONAL PWSTR pwszFullPath)
{
    PWCHAR                  pwszSrcName         = NULL,
                            pwszSrcPath         = NULL;
    USHORT                  usNameLenBytes      = 0x00,
                            usPathLenBytes      = 0x00;
    DWORD                   dwNameChars         = 0x00,
                            dwPathChars         = 0x00;
    PPEB                    pPeb                = NULL;
    PPEB_LDR_DATA           pLdr                = NULL;
    PLDR_DATA_TABLE_ENTRY   pEntry              = NULL;
    PLIST_ENTRY             pListHead           = NULL,
                            pListEntry          = NULL;
    HMODULE                 hCurrent            = NULL;
    ULONG_PTR               uBaseDllNameAddr    = 0x00,
                            uFullDllNameAddr    = 0x00;

    // At least one output buffer required 
    if (!pwszModuleName && !pwszFullPath) return FALSE;

    pPeb = NtCurrentPeb();
    if (!pPeb) return FALSE;

    // NULL means current process EXE
    if (!hModule)
        hModule = (HMODULE)READ_QWORD(pPeb, PEB, ImageBaseAddress);

    if (!hModule) return FALSE;

    pLdr = (PPEB_LDR_DATA)READ_QWORD(pPeb, PEB, Ldr);
    if (!pLdr) return FALSE;

    pListHead  = (PLIST_ENTRY)((ULONG_PTR)pLdr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
    pListEntry = (PLIST_ENTRY)READ_QWORD(pListHead, LIST_ENTRY, Flink);

    while (pListEntry != pListHead)
    {
        pEntry   = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        hCurrent = (HMODULE)READ_QWORD(pEntry, LDR_DATA_TABLE_ENTRY, DllBase);

        if (hCurrent == hModule)
        {
            // Nested - we cant use our READ_* macros 
            if (pwszModuleName)
            {
                uBaseDllNameAddr = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseDllName);
                usNameLenBytes   = (USHORT)ReadWordViaGadget(uBaseDllNameAddr + FIELD_OFFSET(UNICODE_STRING, Length));
                pwszSrcName      = (PWCHAR)ReadQwordViaGadget(uBaseDllNameAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));
            }

            if (pwszFullPath)
            {
                uFullDllNameAddr = (ULONG_PTR)pEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName);
                usPathLenBytes   = (USHORT)ReadWordViaGadget(uFullDllNameAddr + FIELD_OFFSET(UNICODE_STRING, Length));
                pwszSrcPath      = (PWCHAR)ReadQwordViaGadget(uFullDllNameAddr + FIELD_OFFSET(UNICODE_STRING, Buffer));
            }

            break;
        }

        pListEntry = (PLIST_ENTRY)READ_QWORD(pListEntry, LIST_ENTRY, Flink);
    }

    // Copy BaseDllName if requested
    if (pwszModuleName)
    {
        if (!pwszSrcName || !usNameLenBytes)             return FALSE;

        dwNameChars = usNameLenBytes / sizeof(WCHAR);
        if (dwNameChars >= MAX_PATH)                     return FALSE;

        // Copy The Name Via Gadget (Per-WCHAR) To Stay EAF-Clean
        for (DWORD i = 0; i < dwNameChars; i++)
        {
            pwszModuleName[i] = (WCHAR)READ_WORD_RAW(&pwszSrcName[i]);
        }
        pwszModuleName[dwNameChars] = L'\0';
    }

    // Copy FullDllName if requested
    if (pwszFullPath)
    {
        if (!pwszSrcPath || !usPathLenBytes)             return FALSE;

        dwPathChars = usPathLenBytes / sizeof(WCHAR);
        if (dwPathChars >= MAX_PATH)                     return FALSE;

        // Copy The Path Via Gadget (Per-WCHAR) To Stay EAF-Clean
        for (DWORD i = 0; i < dwPathChars; i++)
        {
            pwszFullPath[i] = (WCHAR)READ_WORD_RAW(&pwszSrcPath[i]);
        }
        pwszFullPath[dwPathChars] = L'\0';
    }

    return TRUE;
}



//
// Replaces GetProcAddress 
//
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uFunctionNameHash)
{
    PIMAGE_DOS_HEADER           pDosImgHdr          = NULL;
    PIMAGE_NT_HEADERS           pNtImgHdrs          = NULL;
    PIMAGE_EXPORT_DIRECTORY     pExportDir          = NULL;
    PIMAGE_DATA_DIRECTORY       pDataDir            = NULL;
    PDWORD                      pFuncNamesArray     = NULL;
    PDWORD                      pFuncAddrsArray     = NULL;
    PWORD                       pNameOrdsArray      = NULL;
    DWORD                       dwExportRva         = 0x00,
                                dwExportSize        = 0x00,
                                dwFunctionRva       = 0x00,
                                dwIndex             = 0x00;
    FARPROC                     pFunctionAddr       = NULL;

    if (!hModule || !uFunctionNameHash) return NULL;

    //
    // if (!IsBadReadPtr(hModule, 4096)) return FALSE;
    //

    // Get DOS & Verify its Magic
    pDosImgHdr = (PIMAGE_DOS_HEADER)hModule;
    if (READ_WORD(pDosImgHdr, IMAGE_DOS_HEADER, e_magic) != IMAGE_DOS_SIGNATURE) return NULL;

    // Get NT Headers & Verify its Signature
    pNtImgHdrs = (PIMAGE_NT_HEADERS)((PBYTE)hModule + READ_DWORD(pDosImgHdr, IMAGE_DOS_HEADER, e_lfanew));
    if (READ_DWORD(pNtImgHdrs, IMAGE_NT_HEADERS, Signature) != IMAGE_NT_SIGNATURE) return NULL;

    // Get Export Data Directory 
    pDataDir        = (PIMAGE_DATA_DIRECTORY)((ULONG_PTR)pNtImgHdrs + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, DataDirectory) + (IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)));
    
    // Get Export Directory VirtualAddress & Size
    dwExportRva     = READ_DWORD(pDataDir, IMAGE_DATA_DIRECTORY, VirtualAddress);
    dwExportSize    = READ_DWORD(pDataDir, IMAGE_DATA_DIRECTORY, Size);

    // Bail Out If Module Has No Export Directory (Exportless DLLs)
    if (!dwExportRva || !dwExportSize) return NULL;

    // Get Export Directory & Function Address Array
    pExportDir      = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + dwExportRva);
    pFuncAddrsArray = (PDWORD)((PBYTE)hModule + READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, AddressOfFunctions));

    // Resolve Function By Ordinal
    if (HIWORD(uFunctionNameHash) == 0)
    {
        // Get Ordinal & Export Base & Number Of Functions
        WORD    wOrdinal            = LOWORD(uFunctionNameHash);
        DWORD   dwBase              = READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, Base);
        DWORD   dwNumberOfFunctions = READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, NumberOfFunctions);

        // Validate Ordinal Is Within Range
        if (wOrdinal < dwBase || wOrdinal >= dwBase + dwNumberOfFunctions)
            return NULL;

        // Get Function RVA From Address Array Using Ordinal Index
        dwFunctionRva = READ_DWORD_RAW(&pFuncAddrsArray[wOrdinal - dwBase]);
    }
    // Resolve Function By Name 
    else
    {
        // Get Name Array & Name Ordinal Array & Number Of Names
        DWORD dwAddrOfNames         = READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, AddressOfNames);
        DWORD dwAddrOfNameOrdinals  = READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals);
        DWORD dwNumberOfNames       = READ_DWORD(pExportDir, IMAGE_EXPORT_DIRECTORY, NumberOfNames);

        pFuncNamesArray = (PDWORD)((PBYTE)hModule + dwAddrOfNames);
        pNameOrdsArray  = (PWORD)((PBYTE)hModule + dwAddrOfNameOrdinals);
        
        // Iterate Over Export Names & Compare Hash
        for (dwIndex = 0; dwIndex < dwNumberOfNames; dwIndex++)
        {

            CHAR    szFuncName[BUFFER_SIZE_1024]    = { 0 };
            PCHAR   pFuncName                       = (PCHAR)((PBYTE)hModule + READ_DWORD_RAW(&pFuncNamesArray[dwIndex]));
            DWORD   dwCharIdx                       = 0x00;

            //
            // Copy The Function Name Locally Via Gadget. 
            // 
            // Hashing pFuncName directly would walk it from non-image RIP (from the hashing function)
            // Therefore, we copy via the gadget first, then hash the local copy.
            for (; dwCharIdx < BUFFER_SIZE_1024 - 1; dwCharIdx++)
            {
                CHAR c0 = (CHAR)READ_WORD_RAW(&pFuncName[dwCharIdx]);
                szFuncName[dwCharIdx] = c0;
                if (!c0) break;
            }
            szFuncName[BUFFER_SIZE_1024 - 1] = '\0';

            if (uFunctionNameHash == HASH_STRING_A(szFuncName))
            {
                // Get Function RVA Using Name Ordinal As Index Into Address Array
                dwFunctionRva = READ_DWORD_RAW(&pFuncAddrsArray[READ_WORD_RAW(&pNameOrdsArray[dwIndex])]);
                break;
            }
        }

        if (dwIndex == dwNumberOfNames) return NULL;
    }

    // Bail out
    if (!dwFunctionRva) return NULL;

    // Calculate The Function Address Based On The RVA
    pFunctionAddr = (FARPROC)((PBYTE)hModule + dwFunctionRva);

    // Check If The Function Is Forwarded (RVA Falls Within Export Directory)
    if (dwFunctionRva >= dwExportRva && dwFunctionRva < (dwExportRva + dwExportSize))
    {
        CHAR            szFuncName[MAX_PATH]    = { 0 };
        WCHAR           wszLibName[MAX_PATH]    = { 0 }; 
        PCHAR           pForwardFuncName        = (PCHAR)pFunctionAddr;
        DWORD           dwDotIdx                = 0x00;
        HMODULE         hForwardMod             = NULL;

        // Find The Dot Separator & Validate It's Within Export Directory Bounds
        while ((PBYTE)&pForwardFuncName[dwDotIdx] < ((PBYTE)pExportDir + dwExportSize))
        {
            CHAR c0 = (CHAR)READ_WORD_RAW(&pForwardFuncName[dwDotIdx]);

            if (c0 == '\0' || c0 == '.')
                break;

            dwDotIdx++;
        }

        if ((PBYTE)&pForwardFuncName[dwDotIdx] >= ((PBYTE)pExportDir + dwExportSize) || (CHAR)READ_WORD_RAW(&pForwardFuncName[dwDotIdx]) != '.')
        {
            printf("[!] Invalid Forwarded Function Format: %s\n", pForwardFuncName);
            return NULL;
        }

        // Validate DLL Name Length Will Fit (Name + ".dll" + Null = dwDotIdx + 5)
        if (dwDotIdx == 0 || dwDotIdx >= MAX_PATH - 5)
        {
            printf("[!] Forwarded Module Name Too Long Or Empty: %s\n", pForwardFuncName);
            return NULL;
        }

        // Copy Forwarded Module Name (ANSI To Wide) Via Gadget
        for (DWORD i = 0; i < dwDotIdx; i++)
        {
            wszLibName[i] = (UCHAR)READ_WORD_RAW(&pForwardFuncName[i]);
        }

        // Append ".dll" Extension
        wszLibName[dwDotIdx]        = L'.';        
        wszLibName[dwDotIdx + 1]    = L'd';       
        wszLibName[dwDotIdx + 2]    = L'l'; 
        wszLibName[dwDotIdx + 3]    = L'l';
        wszLibName[dwDotIdx + 4]    = L'\0';  

        // Handle API Set DLLs (e.g., api-ms-win-core-memory-l1-1-0.dll, ext-ms-*.dll)
        // Case-insensitive prefix check via OR 0x20 to lowecase
        {
            WCHAR c0 = wszLibName[0] | 0x20;
            WCHAR c1 = wszLibName[1] | 0x20;
            WCHAR c2 = wszLibName[2] | 0x20;
 
            if (((c0 == L'a' && c1 == L'p' && c2 == L'i') || (c0 == L'e' && c1 == L'x' && c2 == L't')) && wszLibName[3] == L'-')
            {
                WCHAR wszParentName[MAX_PATH]   = { 0 };
                PWSTR pwszParent                = NULL;

                // Get module name 
                if (GetModuleInfoFromHandle(hModule, wszParentName, NULL))
                    pwszParent = wszParentName;

                if (!ResolveApiSet(wszLibName, pwszParent, wszLibName, MAX_PATH))
                {
                    printf("[!] Failed To Resolve ApiSet: %ws\n", wszLibName);
                    return NULL;
                }
            }
        }

        // Copy Function Name or Ordinal Via Gadget
        for (DWORD i = 0; (PBYTE)&pForwardFuncName[dwDotIdx + 1 + i] < ((PBYTE)pExportDir + dwExportSize) && i < MAX_PATH - 1; i++)
        {
            CHAR c0 = (CHAR)READ_WORD_RAW(&pForwardFuncName[dwDotIdx + 1 + i]);

            if (!c0) break;

            szFuncName[i] = c0;
        }

        if (!szFuncName[0])
        {
            printf("[!] Empty Forwarded Function Name Or Ordinal\n");
            return NULL;
        }

        // Get Forwarded Module Base Address (Load It If Not Already Loaded)
        if (!(hForwardMod = GetModuleHandleH(HASH_STRING_W_CI(wszLibName))))
        {
            if (!(hForwardMod = LoadLibraryW(wszLibName)))
            {
                printf("[!] LoadLibraryW Failed Loading %ws With Error: %ld\n", wszLibName, GetLastError());
                return NULL;
            }
        }

        // Check If It's An Ordinal Forward (#123)
        if (szFuncName[0] == '#')
        {
            DWORD dwOrdinal = 0x00;

            if (!szFuncName[1])
            {
                printf("[!] Empty Forwarded Ordinal\n");
                return NULL;
            }

            // Parse Ordinal Number From String With Overflow Guard
            for (DWORD i = 1; szFuncName[i]; i++)
            {
                if (szFuncName[i] >= '0' && szFuncName[i] <= '9')
                {
                    dwOrdinal = dwOrdinal * 10 + (szFuncName[i] - '0');

                    if (dwOrdinal > 0xFFFF)
                    {
                        printf("[!] Forwarded Ordinal Out Of Range: %s\n", szFuncName);
                        return NULL;
                    }
                }
                else
                {
                    printf("[!] Invalid Forwarded Ordinal: %s\n", szFuncName);
                    return NULL;
                }
            }
            // Recursively Resolve By Ordinal
            pFunctionAddr = GetProcAddressH(hForwardMod, (UINT32)(WORD)dwOrdinal);
            return pFunctionAddr;
        }
        else
        {
            // Recursively Resolve By Function Name Hash
            pFunctionAddr = GetProcAddressH(hForwardMod, HASH_STRING_A(szFuncName));
            return pFunctionAddr;
        }
    }

    return pFunctionAddr;
}


#pragma endregion
