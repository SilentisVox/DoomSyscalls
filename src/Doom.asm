section         .data
SYSTEM_SERVICE_NUMBER:  DD 0
SYSCALL_ADDRESS:        DQ 0
LANDING_ADDRESS         DQ 0
SIZE:                   DB 0

section         .text
global          SET_SYSCALL_ASM
global          RUN_SYSCALL_ASM

SET_SYSCALL_ASM:
        XOR     RAX,    RAX
        MOV     DWORD   [REL SYSTEM_SERVICE_NUMBER],    EAX
        MOV     DWORD   [REL SYSTEM_SERVICE_NUMBER],    ECX
        MOV     QWORD   [REL SYSCALL_ADDRESS],          RAX
        MOV     QWORD   [REL SYSCALL_ADDRESS],          RDX
        MOV     QWORD   [REL LANDING_ADDRESS],          RAX
        MOV     QWORD   [REL LANDING_ADDRESS],          R8
        MOV     BYTE    [REL SIZE],                     AL
        MOV     BYTE    [REL SIZE],                     R9B
        RET

RUN_SYSCALL_ASM:
        CALL    GET_STACK
        CMP     RAX,    0
        JZ      STUB
        SUB     RSP,    RAX
        MOV     RAX,    QWORD   [REL LANDING_ADDRESS]
        PUSH    RAX
        MOV     R10,    RCX
        XOR     RCX,    RCX
        MOV     RCX,    0x30
COPY:
        CMP     RCX,    0x68
        JZ      STUB
        CALL    GET_STACK
        ADD     RAX,    RCX
        MOV     RAX,    QWORD   [RSP + RAX]
        MOV     QWORD   [RSP + RCX - 8],   RAX
        ADD     RCX,    8
        JMP     COPY
STUB:
        MOV     RCX,    R10
        MOV     EAX,    DWORD   [REL SYSTEM_SERVICE_NUMBER]
        JMP     QWORD   [REL SYSCALL_ADDRESS]

GET_STACK:
        XOR     RAX,    RAX
        MOV     AL,     BYTE    [REL SIZE]
        RET