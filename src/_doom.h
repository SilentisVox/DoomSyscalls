#include "_wn64.h"

#ifndef _DOOM_H
#define _DOOM_H

typedef struct _MODULE_CONFIG {
        ULONG_PTR       pModule;
        ULONG           NumberOfNames;
        ULONG_PTR       ArrayOfNames;
        ULONG_PTR       ArrayOfAddresses;
        ULONG_PTR       ArrayOfOrdinals;
} MODULE_CONFIG, * PMODULE_CONFIG;

typedef struct _NTDLL_FUNCTION {
        ULONG_PTR       SyscallStub;
        ULONG           SystemServiceNumber;
        ULONG_PTR       SyscallInstruction;
        ULONG_PTR       Landing;
        CHAR            Size;
} NTDLL_FUNCTION, * PNTDLL_FUNCTION;

typedef struct _NTDLL_API {
        NTDLL_FUNCTION  NtQuerySystemInformation;
        NTDLL_FUNCTION  NtOpenProcess;
        NTDLL_FUNCTION  NtAllocateVirtualMemory;
        NTDLL_FUNCTION  NtWriteVirtualMemory;
        NTDLL_FUNCTION  NtCreateThreadEx;
        NTDLL_FUNCTION  NtExitProcess;
} NTDLL_API, * PNTDLL_API;

VOID GET_NTDLL_FUN(ULONG SymbolHash, PNTDLL_FUNCTION SymbolData);
VOID INIT_NTDLL_API();

extern VOID SET_SYSCALL_ASM(
        ULONG           SystemServiceNumber,
        ULONG_PTR       SyscallInstruction,
        ULONG_PTR       Landing,
        CHAR            Size
);
extern ULONG_PTR RUN_SYSCALL_ASM();

#define SET_SYSCALL(Syscall)    SET_SYSCALL_ASM(Syscall.SystemServiceNumber, Syscall.SyscallInstruction, Syscall.Landing, Syscall.Size)
#define RUN_SYSCALL             RUN_SYSCALL_ASM

#endif // !_DOOM_H