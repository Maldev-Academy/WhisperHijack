// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#include "ReadThroughGadgets.h"

//
// Scans a module's .text section for ROP-style read gadgets and installs them
// for use by the EAF-bypass read macros (ReadQwordViaGadget, etc.).
//
// Locates three gadget shapes: 8/4/2-byte reads & accepting either [rax] or [rcx]
// as the source operand. 
//
// The QWORD gadget is mandatory; DWORD and WORD gadgets are optional (the caller
// can fall back to QWORD reads with masking if needed).
//
BOOL InitializeUnguardGadget(IN HMODULE hModule, IN OPTIONAL DWORD dwBufferSizeToScan) 
{
#define READ_GADGET_STUB_QWORD      0xC3008B48      // 48 8B 00 C3  |    mov rax, [rax]; ret
#define READ_GADGET_STUB_DWORD      0xC3008B        // 8B 00 C3     |    mov eax, [rax]; ret
#define READ_GADGET_STUB_WORD       0xC300B70F      // 0F B7 00 C3  |    movzx eax, word [rax]; ret

#define READ_GADGET_STUB_QWORD_ALT  0xC3018B48      // 48 8B 01 C3  |    mov rax, [rcx]; ret
#define READ_GADGET_STUB_DWORD_ALT  0xC3018B        // 8B 01 C3     |    mov eax, [rcx]; ret
#define READ_GADGET_STUB_WORD_ALT   0xC301B70F      // 0F B7 01 C3  |    movzx eax, word [rcx]; ret

    if (!hModule) return FALSE;

    // Skip the PE headers (first 4096 bytes) and scan into what's typically .text
    ULONG_PTR   uModuleTextSection      = (ULONG_PTR)hModule + BUFFER_SIZE_4096;
    ULONG_PTR   uQwordGadget            = 0x00;
    ULONG_PTR   uDwordGadget            = 0x00;
    ULONG_PTR   uWordGadget             = 0x00;
    // Default scan window: 4096 * 512 = 2 MB (large enough to cover most module .text sections)
    DWORD       dwBuffSizeToScan        = dwBufferSizeToScan ? dwBufferSizeToScan : (BUFFER_SIZE_4096 * BUFFER_SIZE_512);

    // Byte-by-byte signature search across the scan window
    for (DWORD i = 0; i < dwBuffSizeToScan; i++)
    {
        // Guard against unmapped pages within the module 
        if (!IsBadReadPtr((PVOID)(uModuleTextSection + i), sizeof(DWORD)))
        {
            DWORD dwStub = *(DWORD*)(uModuleTextSection + i);

            // QWORD gadget: full 4-byte match since the stub is exactly 4 bytes
            if (!uQwordGadget && (dwStub == READ_GADGET_STUB_QWORD || dwStub == READ_GADGET_STUB_QWORD_ALT))
                uQwordGadget = uModuleTextSection + i;
            
            // DWORD gadget: stub is only 3 bytes, so mask off the high byte before comparing
            else if (!uDwordGadget && ((dwStub & 0x00FFFFFF) == READ_GADGET_STUB_DWORD || (dwStub & 0x00FFFFFF) == READ_GADGET_STUB_DWORD_ALT))
                uDwordGadget = uModuleTextSection + i;
            
            // WORD gadget: full 4-byte match (movzx + ret = 4 bytes)
            else if (!uWordGadget && (dwStub == READ_GADGET_STUB_WORD || dwStub == READ_GADGET_STUB_WORD_ALT))
                uWordGadget = uModuleTextSection + i;

            // Early exit once all three gadget sizes have been located
            if (uQwordGadget && uDwordGadget && uWordGadget)
                break;
        }
    }
        
    /*
    DBG("[v] uQwordGadget: 0x%p %s", uQwordGadget, uQwordGadget ? ((*(DWORD*)uQwordGadget == READ_GADGET_STUB_QWORD) ? "[rax]" : "[rcx]") : "");
    DBG("[v] uDwordGadget: 0x%p %s", uDwordGadget, uDwordGadget ? (((*(DWORD*)uDwordGadget & 0x00FFFFFF) == READ_GADGET_STUB_DWORD) ? "[rax]" : "[rcx]") : "");
    DBG("[v] uWordGadget: 0x%p %s", uWordGadget, uWordGadget ? ((*(DWORD*)uWordGadget == READ_GADGET_STUB_WORD) ? "[rax]" : "[rcx]") : "");
    */
   
#undef READ_GADGET_STUB_QWORD
#undef READ_GADGET_STUB_DWORD
#undef READ_GADGET_STUB_WORD
#undef READ_GADGET_STUB_QWORD_ALT
#undef READ_GADGET_STUB_DWORD_ALT
#undef READ_GADGET_STUB_WORD_ALT

    // QWORD gadget is mandatory; without it, the read primitive can't function at all
    if (!uQwordGadget) return FALSE;

    // Publish the resolved gadget addresses to global state for the READ_* macros to use
    SetGadget(uQwordGadget, uDwordGadget, uWordGadget);

    return TRUE;
}
