#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "api_untangle.h"

#include <string.h>


BOOL ModifyFunctionInMemory(const char* dllName, const char* functionName);
void ExecuteModifications(int argc, char *argv[]);

// int main(int argc, char *argv[]) {

//     ExecuteModifications(argc, argv);

//     // if (ModifyFunctionInMemory("ntdll.dll", "NtCreateThreadEx")) {
//     //     printf("[+] Operation completed successfully.\n");
//     // } else {
//     //     printf("[-] Operation failed.\n");
//     // }
//     return 0;
// }

BOOL ReadFunctionBytesFromDisk(const char* dllPath, const char* functionName, unsigned char* buffer, size_t bufferSize);

// int main() {
//     unsigned char callStub[5] = {0};
//     if (ReadFunctionBytesFromDisk("C:\\Windows\\System32\\ntdll.dll", "NtCreateThreadEx", callStub, sizeof(callStub))) {
//         printf("[+] First 5 bytes of NtCreateThreadEx: ");
//         for (int i = 0; i < 5; ++i) {
//             printf("%02X ", callStub[i]);
//         }
//         printf("\n");
//     } else {
//         printf("[-] Failed to read bytes.\n");
//     }
//     return 0;
// }

BOOL ReadFunctionBytesFromDisk(const char* dllPath, const char* functionName, unsigned char* buffer, size_t bufferSize) {
    // Open the DLL file
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open DLL file.\n");
        return FALSE;
    }

    // Map the DLL file into memory
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == NULL) {
        printf("[-] Failed to create file mapping.\n");
        CloseHandle(hFile);
        return FALSE;
    }

    LPVOID dllBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (dllBase == NULL) {
        printf("[-] Failed to map view of file.\n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Locate the function in the DLL file
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + exportDirRVA);

    DWORD* namePtr = (DWORD*)((DWORD_PTR)dllBase + exportDir->AddressOfNames);
    WORD* ordinalPtr = (WORD*)((DWORD_PTR)dllBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcPtr = (DWORD*)((DWORD_PTR)dllBase + exportDir->AddressOfFunctions);
    BOOL found = FALSE;

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        LPCSTR exportName = (LPCSTR)((DWORD_PTR)dllBase + namePtr[i]);
        if (strcmp(exportName, functionName) == 0) {
            DWORD funcRVA = funcPtr[ordinalPtr[i]];
            LPVOID funcAddress = (LPVOID)((DWORD_PTR)dllBase + funcRVA);
            memcpy(buffer, funcAddress, bufferSize);
            found = TRUE;
            break;
        }
    }

    UnmapViewOfFile(dllBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    if (!found) {
        printf("[-] Function %s not found in %s.\n", functionName, dllPath);
        return FALSE;
    }

    return TRUE;
}


BOOL ModifyFunctionInMemory(const char* dllName, const char* functionName) {
    char dllPath[MAX_PATH];
    sprintf(dllPath, "C:\\Windows\\System32\\%s", dllName);

    unsigned char callStub[5] = {0};
    if (!ReadFunctionBytesFromDisk(dllPath, functionName, callStub, sizeof(callStub))) {
        printf("[-] Failed to read bytes from disk.\n");
        return FALSE;
    }

    // In ntdll.dll, the 5th byte is the syscall ID we are interested in. 
    printf("[+] First 5 bytes of %s: ", functionName);
    for (int i = 0; i < 5; ++i) {
        printf("%02X ", callStub[i]);
    }
    printf("\n");

    HMODULE dllModule = LoadLibraryA(dllName);
    if (!dllModule) {
        printf("[-] Failed to load %s.\n", dllName);
        return FALSE;
    }

    FARPROC procAddress = GetProcAddress(dllModule, functionName);
    if (!procAddress) {
        printf("[-] Failed to get address of %s in %s.\n", functionName, dllName);
        FreeLibrary(dllModule);
        return FALSE;
    }

    printf("[+] Obtained function address for %s in %s.\n", functionName, dllName);

    DWORD oldProtection;
    if (!VirtualProtect((LPVOID)procAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        printf("[-] Failed to change memory protection of %s!%s. Error Code: %lu\n", dllName, functionName, GetLastError());
        FreeLibrary(dllModule);
        return FALSE;
    }
    printf("[+] Updated memory protection of %s!%s.\n", dllName, functionName);

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)procAddress, callStub, 5, &bytesWritten)) {
        printf("[-] Failed to write to %s!%s. Error Code: %lu\n", dllName, functionName, GetLastError());
        VirtualProtect((LPVOID)procAddress, 10, oldProtection, &oldProtection);
        FreeLibrary(dllModule);
        return FALSE;
    }
    printf("[+] Successfully wrote to %s!%s. Bytes written: %llu\n", dllName, functionName, (unsigned long long)bytesWritten);

    DWORD newOld;
    if (!VirtualProtect((LPVOID)procAddress, 10, oldProtection, &newOld)) {
        printf("[-] Failed to restore memory protection of %s!%s. Error Code: %lu\n", dllName, functionName, GetLastError());
        FreeLibrary(dllModule);
        return FALSE;
    }
    printf("[+] Restored memory protection of %s!%s.\n", dllName, functionName);

    FreeLibrary(dllModule);
    return TRUE;
}



void ExecuteModifications(int argc, char *argv[]) {
    const char *defaultFunctions[] = {"NtCreateThreadEx", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory"};
    const char *functionsToModify[sizeof(defaultFunctions) / sizeof(defaultFunctions[0])];
    int functionsCount = sizeof(defaultFunctions) / sizeof(defaultFunctions[0]);

    // Check if command line arguments are provided
    if (argc > 1 && strcmp(argv[1], "-api") == 0 && argc == 3) {
        // Parse the command line argument for API functions
        char *token = strtok(argv[2], ",");
        int index = 0;
        while (token != NULL && index < functionsCount) {
            functionsToModify[index++] = token;
            token = strtok(NULL, ",");
        }
        functionsCount = index; // Update the count based on the provided arguments
    } else {
        // Use default functions if no command line arguments are specified
        memcpy(functionsToModify, defaultFunctions, sizeof(defaultFunctions));
    }

    // Execute ModifyFunctionInMemory for each specified function
    for (int i = 0; i < functionsCount; ++i) {
        printf("[*] Only ntdll is supported for now.\n ");
        if (ModifyFunctionInMemory("ntdll.dll", functionsToModify[i])) {
            printf("[+] Modified %s successfully.\n", functionsToModify[i]);
        } else {
            printf("[-] Failed to modify %s.\n", functionsToModify[i]);
        }
    }
}
