#pragma once
#ifndef COMMON_H
#define COMMON_H


#include <Windows.h>
#include <Strsafe.h>
#include <intrin.h>
#include <immintrin.h>

#include "Structures.h"
#include "DbgMacros.h"

#pragma comment(lib, "Shlwapi.lib")

// =================================================================================================================


#define BUFFER_SIZE_512                 512
#define BUFFER_SIZE_1024                1024
#define BUFFER_SIZE_2048                2048
#define BUFFER_SIZE_4096                4096


// =================================================================================================================

/*
python.exe .\Crc32bHasher.py NtQuerySystemInformation NtOpenProcess NtQueryInformationProcess NtClose NtOpenThread NtQueryVirtualMemory NtAllocateVirtualMemory RtlFillMemory RtlMoveMemory NtQueueApcThread NtProtectVirtualMemory NtCreateUserProcess RtlCreateProcessParametersEx RtlDestroyProcessParameters RtlInitUnicodeString NtGetContextThread NtAlertThread NtSetInformationThread NtReadVirtualMemory GetThreadDescription NtCreateEvent NtDuplicateObject NtWaitForSingleObject NtSetEvent NtQueryInformationThread
*/
#define CRC32B_NTQUERYSYSTEMINFORMATION                 0x97FD2398
#define CRC32B_NTOPENPROCESS                            0xDBF381B5
#define CRC32B_NTQUERYINFORMATIONPROCESS                0xA5C44C50
#define CRC32B_NTCLOSE                                  0x0D09C750
#define CRC32B_NTOPENTHREAD                             0xB7A26D79
#define CRC32B_NTQUERYVIRTUALMEMORY                     0x03F6F38C
#define CRC32B_NTALLOCATEVIRTUALMEMORY                  0xE0762FEB
#define CRC32B_RTLFILLMEMORY                            0xEF153911
#define CRC32B_RTLMOVEMEMORY                            0x1C0CD35C
#define CRC32B_NTQUEUEAPCTHREAD                         0x235B0390
#define CRC32B_NTPROTECTVIRTUALMEMORY                   0x5C2D1A97
#define CRC32B_NTCREATEUSERPROCESS                      0x05AAA327
#define CRC32B_RTLCREATEPROCESSPARAMETERSEX             0x336B43C3
#define CRC32B_RTLDESTROYPROCESSPARAMETERS              0x725AA62D
#define CRC32B_RTLINITUNICODESTRING                     0x7AA7B69B
#define CRC32B_NTGETCONTEXTTHREAD                       0xD3534981
#define CRC32B_NTALERTTHREAD                            0xD4A60DEB
#define CRC32B_NTSETINFORMATIONTHREAD                   0x466F2056
#define CRC32B_NTREADVIRTUALMEMORY                      0x81223212
#define CRC32B_GETTHREADDESCRIPTION                     0xE188A086
#define CRC32B_NTCREATEEVENT                            0xA4A397F8
#define CRC32B_NTDUPLICATEOBJECT                        0xD23B7C02
#define CRC32B_NTWAITFORSINGLEOBJECT                    0xDD554681
#define CRC32B_NTSETEVENT                               0x606FC7B2
#define CRC32B_NTQUERYINFORMATIONTHREAD                 0x31133574

/*
python.exe .\Crc32bHasher.py -i ntdll.dll kernel32.dll
*/
#define CRC32B_NTDLLDLL                                 0x84C05E40
#define CRC32B_KERNEL32DLL                              0x6AE69F02


// =================================================================================================================

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON     (0x00000001ULL << 44)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON             (0x00000001ULL << 52)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON          (0x00000001ULL << 56)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON          (0x00000001ULL << 32)
#endif

#define MITIGATION_POLICY_HARDENED                                                                                    \
    ((UINT64)PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON  |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON          |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON       |                             \
     (UINT64)PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON)


typedef NTSTATUS (NTAPI *fnRtlCreateProcessParametersEx)(
    OUT PRTL_USER_PROCESS_PARAMETERS   *pProcessParameters,
    IN  PUNICODE_STRING                 ImagePathName,
    IN  PUNICODE_STRING                 DllPath                 OPTIONAL,
    IN  PUNICODE_STRING                 CurrentDirectory        OPTIONAL,
    IN  PUNICODE_STRING                 CommandLine             OPTIONAL,
    IN  PVOID                           Environment             OPTIONAL,
    IN  PUNICODE_STRING                 WindowTitle             OPTIONAL,
    IN  PUNICODE_STRING                 DesktopInfo             OPTIONAL,
    IN  PUNICODE_STRING                 ShellInfo               OPTIONAL,
    IN  PUNICODE_STRING                 RuntimeData             OPTIONAL,
    IN  ULONG                           Flags
);

typedef NTSTATUS (NTAPI *fnRtlDestroyProcessParameters)(
    IN PRTL_USER_PROCESS_PARAMETERS     pProcessParameters
);

typedef VOID (NTAPI *fnRtlInitUnicodeString)(
    OUT PUNICODE_STRING                 DestinationString,
    IN  PCWSTR                          SourceString            OPTIONAL
);

// =================================================================================================================



#endif // !COMMON_H
