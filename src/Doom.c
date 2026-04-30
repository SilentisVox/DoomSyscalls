#include "_wn64.h"
#include "_doom.h"

MODULE_CONFIG NTDLL_CONFIG = { 0 };

ULONG_PTR GET_NTDLL() {
        ULONG_PTR pPEB          =  __readgsqword(0x60);
        ULONG_PTR pLdrData      = *(ULONG_PTR *) (pPEB + 0x18);
        ULONG_PTR pMdlList      = *(ULONG_PTR*)  (pLdrData + 0x30);
        ULONG_PTR pModule       = *(ULONG_PTR *) (pMdlList + 0x10);

        return pModule;
}

VOID INIT_NTDLL_CONFIG() {
        ULONG_PTR pNtdll        = GET_NTDLL();
        ULONG_PTR pNtHdr        = (pNtdll + *(ULONG *) (pNtdll + 0x3C));
        ULONG_PTR pExpDir       = (pNtdll + *(ULONG *) (pNtHdr + 0x88));

        NTDLL_CONFIG.pModule            = pNtdll;
        NTDLL_CONFIG.NumberOfNames      = *(ULONG *) (pExpDir + 0x18);
        NTDLL_CONFIG.ArrayOfAddresses   = (pNtdll + *(ULONG *) (pExpDir + 0x1C));
        NTDLL_CONFIG.ArrayOfNames       = (pNtdll + *(ULONG *) (pExpDir + 0x20));
        NTDLL_CONFIG.ArrayOfOrdinals    = (pNtdll + *(ULONG *) (pExpDir + 0x24));
}

BOOL IDEAL(ULONG_PTR START, ULONG_PTR *RETURN, CHAR *SIZE) {
        for (UINT index = 0; index < 255; index++) {
                ULONG_PTR SEARCH        = *(ULONG_PTR *) (START + index);
                UCHAR AMOUNT            = *(UCHAR *)     (START + index + 3);

                if (
                        (((SEARCH & 0x000000FF00FFFFFF) == 0x000000C300C48348) ||
                        ((SEARCH & 0xFFFFFFFF00FFFFFF) == 0xC300000000C48148)) &&
                        (AMOUNT >= 0x58)
                ) {
                        *RETURN         = START + index;
                        *SIZE           = AMOUNT;
                        return TRUE;
                }
        }
        return FALSE;
}

ULONG ROR7_32(PCHAR SymbolName) {
        UINT hash       = 0;
        UINT index      = 0;

        while (SymbolName[index]) {
                hash    = ((hash >> 7) | (hash << (32 - 7)))    & 0xFFFFFFFF;
                hash    = (hash + SymbolName[index])            & 0xFFFFFFFF;
                index++;
        }
        return hash;
}

VOID GET_NTDLL_FUN(ULONG SymbolHash, PNTDLL_FUNCTION SymbolData) {
        if (!NTDLL_CONFIG.pModule)
                INIT_NTDLL_CONFIG();

        for (UINT index = 0; index != NTDLL_CONFIG.NumberOfNames; index++) {
                PCHAR SymbolName = (PCHAR) (NTDLL_CONFIG.pModule + *(ULONG *) (NTDLL_CONFIG.ArrayOfNames + (index * 4)));

                if (ROR7_32(SymbolName) != SymbolHash)
                        continue;

                USHORT SLOT             = *(USHORT *) (NTDLL_CONFIG.ArrayOfOrdinals + (index * 2));
                SymbolData->SyscallStub = (NTDLL_CONFIG.pModule + *(ULONG *) (NTDLL_CONFIG.ArrayOfAddresses + (SLOT * 4)));
                break;
        }
        for (UINT index = 0; index != 255; index++) {
                if ((*(ULONG *) (SymbolData->SyscallStub + index) & 0xFF0000FF) != 0x000000B8)
                        continue;

                SymbolData->SystemServiceNumber = *(ULONG *) (SymbolData->SyscallStub + index + 1);
                break;
        }
        for (UINT index = 0; index != 255; index++) {
                if (*(USHORT *) (SymbolData->SyscallStub + index) != 0x050F)
                        continue;

                SymbolData->SyscallInstruction = SymbolData->SyscallStub + index;
                break;
        }
        if (!SymbolData->SyscallInstruction)
                SymbolData->SyscallInstruction = SymbolData->SyscallStub;

        for (UINT index = 0, start = 0, random = rand() % NTDLL_CONFIG.NumberOfNames; index < NTDLL_CONFIG.NumberOfNames; index++, start++) {
                if ((start + random) == NTDLL_CONFIG.NumberOfNames)
                        start = 0 - random;

                USHORT SLOT     = *(USHORT *) (NTDLL_CONFIG.ArrayOfOrdinals + ((start + random) * 2));
                ULONG_PTR START = (NTDLL_CONFIG.pModule + *(ULONG*) (NTDLL_CONFIG.ArrayOfAddresses + (SLOT * 4)));

                ULONG_PTR RETURN;
                CHAR AMOUNT;

                if (!IDEAL(START, &RETURN, &AMOUNT)) {
                        continue;
                }

                SymbolData->Landing = RETURN;
                SymbolData->Size    = AMOUNT;
                break;
        }
}