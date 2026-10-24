// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#ifndef READ_THROUGH_GADGETS_H
#define READ_THROUGH_GADGETS_H

#include "Common.h"

// Located in ReadThroughGadgets.asm
extern VOID SetGadget(IN ULONG_PTR uQwordGadget, IN ULONG_PTR uDwordGadget, IN ULONG_PTR uWordGadget);
extern ULONG_PTR ReadQwordViaGadget(IN ULONG_PTR uPointer);
extern ULONG_PTR ReadDwordViaGadget(IN ULONG_PTR uPointer);
extern ULONG_PTR ReadWordViaGadget(IN ULONG_PTR uPointer);

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#define READ_QWORD(base, type, field)   (ULONG_PTR)ReadQwordViaGadget((ULONG_PTR)(base) + FIELD_OFFSET(type, field))
#define READ_DWORD(base, type, field)   (DWORD)ReadDwordViaGadget((ULONG_PTR)(base) + FIELD_OFFSET(type, field))
#define READ_WORD(base, type, field)    (WORD)ReadWordViaGadget((ULONG_PTR)(base) + FIELD_OFFSET(type, field))

#define READ_QWORD_RAW(addr)            (ULONG_PTR)ReadQwordViaGadget((ULONG_PTR)(addr))
#define READ_DWORD_RAW(addr)            (DWORD)ReadDwordViaGadget((ULONG_PTR)(addr))
#define READ_WORD_RAW(addr)             (WORD)ReadWordViaGadget((ULONG_PTR)(addr))

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#ifdef __cplusplus
extern "C" {
#endif

	BOOL InitializeUnguardGadget(IN HMODULE hModule, IN OPTIONAL DWORD dwBufferSizeToScan);

#ifdef __cplusplus
}
#endif

#endif // !READ_THROUGH_GADGETS_H
