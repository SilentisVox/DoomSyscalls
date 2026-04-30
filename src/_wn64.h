#ifndef _W64_H
#define _W64_H

#ifndef BASETYPES
#define BASETYPES
#define CALLS
        #define CONST                   const
        #define WINAPI                  __stdcall
        #define NTAPI                   __stdcall
        #define VOID                    void
        #define PVOID                   void *
        #define HANDLE                  void *
        #define SOCKET                  void *
        #define INT                     int
        #define PINT                    INT *
        #define BOOL                    INT
        #define UINT                    unsigned int
        #define PUINT                   UINT *
        #define CHAR                    char
        #define PCHAR                   CHAR *
        #define UCHAR                   unsigned char
        #define PUCHAR                  UCHAR *
        #define SHORT                   short
        #define PSHORT                  SHORT *
        #define USHORT                  unsigned short
        #define PUSHORT                 USHORT *
        #define WCHAR                   USHORT
        #define PWCHAR                  WCHAR *
        #define LONG                    long
        #define PLONG                   LONG *
        #define ULONG                   unsigned long
        #define PULONG                  ULONG *
        #define ACCESS_MASK             ULONG
        #define ULONG_PTR               unsigned long long
        #define ULONGLONG               unsigned long long
#endif

#ifndef TRUE
        #define TRUE                    1
        #define FALSE                   0
#endif
#ifndef NULL
        #define NULL                    ((PVOID) 0)
#endif
#ifndef ZERO
        #define ZERO                    0
#endif

#define PROCESS_ALL_ACCESS              0x001F0FFF
#define THREAD_ALL_ACCESS               0x001F03FF
#define MEM_COMMIT                      0x00001000
#define PAGE_EXECUTE_READWRITE          0x40

#define NTSTATUS                        LONG
#define NT_SUCCESS(STATUS)              (((NTSTATUS) STATUS) >= 0)
#define NtCurrentProcess()              ((HANDLE) -1)
#define NtCurrentThread()               ((HANDLE) -2)
#define NtCurrentConsole()              ((HANDLE) -3)

typedef struct _LSA_UNICODE_STRING {
        USHORT                          Length;
        USHORT                          MaximumLength;
        PWCHAR                          Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
        ULONG                           Length;
        HANDLE                          RootDirectory;
        PUNICODE_STRING                 ObjectName;
        ULONG                           Attributes;
        PVOID                           SecurityDescriptor;
        PVOID                           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_A;

typedef struct _LARGE_INTEGER {
        ULONGLONG                        QuadPart;
} LARGE_INTEGER, * PLARGE_INTEGER;

typedef struct _VM_COUNTERS {
        ULONG_PTR                       PeakVirtualSize;
        ULONG_PTR                       VirtualSize;
        ULONG                           PageFaultCounts;
        ULONG_PTR                       PeakWorkingSet;
        ULONG_PTR                       WorkingSet;
        ULONG_PTR                       QuotaPeakPagedUsage;
        ULONG_PTR                       QuotaPagedUsage;
        ULONG_PTR                       QuotaPeakNonPagedUsage;
        ULONG_PTR                       QuotaNonPagedUsage;
        ULONG_PTR                       PagefileUsage;
        ULONG_PTR                       PeakPagefileUsage;
} VM_COUNTERS, * PVM_COUNTERS;

typedef struct _IO_COUNTERS {
        ULONGLONG                       ReadOperationCount;
        ULONGLONG                       WriteOperationCount;
        ULONGLONG                       OtherOperationCount;
        ULONGLONG                       ReadTransferCount;
        ULONGLONG                       WriteTransferCount;
        ULONGLONG                       OtherTransferCount;
} IO_COUNTERS, * PIO_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG                           NextEntryOffset;
        ULONG                           NumberOfThreads;
        LARGE_INTEGER                   Reserved[3];
        LARGE_INTEGER                   CreateTime;
        LARGE_INTEGER                   UserTime;
        LARGE_INTEGER                   KernelTime;
        UNICODE_STRING                  ImageName;
        ULONG                           BasePriority;
        HANDLE                          UniqueProcessId;
        HANDLE                          InheritedFromUniqueProcessId;
        ULONG                           HandleCount;
        ULONG                           SessionId;
        ULONG                           PageDirectoryBase;
        VM_COUNTERS                     VirtualMemoryCounters;
        ULONG_PTR                       PrivatePageCount;
        IO_COUNTERS                     IoCounters;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _CLIENT_ID {
        HANDLE                          UniqueProcess;
        HANDLE                          UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

#ifndef __readgsqword
#define __readgsqword(OFF) ({ULONGLONG VAL; __asm__ volatile ("mov %%gs:%c1, %0" : "=r" (VAL) : "i" (OFF)); VAL;})
#endif

#ifndef rand
#define rand() ({UINT LO, HI; __asm__ volatile ("rdtsc" : "=a" (LO), "=d" (HI)); (LO ^ HI);})
#endif

#endif // !_W64_H