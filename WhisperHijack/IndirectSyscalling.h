// Copyright 2026 MalDev Academy
// WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/WhisperHijack

#ifndef INDIRECT_SYSCALLING_H
#define INDIRECT_SYSCALLING_H

#include "Common.h"
#include "ResolveAPIs.h"
#include "ReadThroughGadgets.h"

typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                            // Syscall number
    PVOID pSyscallAddress;                  // Syscall address
    PVOID pSyscallInstAddress;              // Address of a 'syscall' instruction in ntdll.dll/win32u.dll

} NT_SYSCALL, * PNT_SYSCALL;

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// Located in InitializeSyscalls.asm
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern NTSTATUS RunSyscall();

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#define INITIALIZE_SYSCALL(SyscallEntry)    (SetSSn((DWORD)SyscallEntry.dwSSn, (PVOID)SyscallEntry.pSyscallInstAddress))
#define INVOKE_SYSCALL(...)                 (RunSyscall(__VA_ARGS__))

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


#ifdef __cplusplus
extern "C" {
#endif

    BOOL InitializeIndirectSyscall(IN DWORD64 dwSyscallNameHash, OUT PNT_SYSCALL pInitializedSyscall);

#ifdef __cplusplus
}
#endif


#endif // !INDIRECT_SYSCALLING_H
