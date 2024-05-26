/// Reference: https://github.com/CognisysGroup/SweetDreams
#include "sleep_encrypt.h"
#include <cstdlib>
#include <cstdio>
//nice sleep: 

unsigned long long fetchCurrentTick()
{
    const size_t EPOCH_START = 0x019DB1DED53E8000; // Unix epoch start in ticks
    const size_t TICKS_PER_MS = 10000; // Ticks per millisecond
    LARGE_INTEGER currentTime;
    currentTime.LowPart = *(DWORD*)(0x7FFE0000 + 0x14); // Read LowPart
    currentTime.HighPart = *(long*)(0x7FFE0000 + 0x1c); // Read HighPart
    return (unsigned long long)((currentTime.QuadPart - EPOCH_START) / TICKS_PER_MS);
}

void waitMilliseconds(size_t ms)
{
    volatile size_t counter = rand(); // Random initial value
    const unsigned long long stopTime = fetchCurrentTick() + ms; // When to stop
    while (fetchCurrentTick() < stopTime) { counter += 1; } // Increment counter until time is reached
    if (fetchCurrentTick() - stopTime > 2000) return; // Check if overshoot
}




void xor_stack(void* stack_top, void* stack_base);


void xor_stack(void* stack_top, void* stack_base) {
    unsigned char* top = (unsigned char*)stack_top;
    unsigned char* base = (unsigned char*)stack_base;

    for (unsigned char* p = top; p < base; ++p) {
        *p ^= 0xABCDE;
    }
}


void (WINAPI* pSleep)(
    DWORD dwMilliseconds
) = Sleep;



typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


 struct ThreadParams {
    DWORD mainThreadId;
    DWORD sleepTime;
};


void SuspendThreads(DWORD TheThreadId) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TheThreadId) {

            SuspendThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));
}


void ResumeThreads(DWORD TheThreadId) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
        return;

    do {
        if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TheThreadId) {

            ResumeThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID));
        }
    } while (Thread32Next(hSnapshot, &te32));

}




DWORD WINAPI EncryptDecryptThread(LPVOID lpParam) {
    // DWORD mainThreadId = *((DWORD*)lpParam);
    ThreadParams* params = (ThreadParams*)lpParam;
    DWORD mainThreadId = params->mainThreadId;
    DWORD time = params->sleepTime;

    DWORD currentThreadId = GetCurrentThreadId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot. Error: %lu\n", GetLastError());
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

                if (hThread != NULL) {
                    if (te32.th32ThreadID == mainThreadId) {
                        SuspendThread(hThread);
                    }

                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }
    //Set time variable
    // DWORD time = 15000;

    printf("Sleeping for %d seconds\n", time / 1000);
    // Sleep(time); // Specify number of ms to sleep
    waitMilliseconds(time); //performing a custom sleep for 5 seconds

    // getchar();


    /////

    // Decrypt the stacks and resume threads
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                    NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

                    THREAD_BASIC_INFORMATION tbi;
                    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

                    if (status == 0) {
                        PVOID teb_base_address = tbi.TebBaseAddress;
                        PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
                            PVOID stack_top = tib->StackLimit;
                            PVOID stack_base = tib->StackBase;

                            xor_stack(stack_top, stack_base);
                        }
                        else {
                            printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
                        }

                        free(tib);
                    }
                    else {
                        printf("NtQueryInformationThread failed with status: 0x%X\n", status);
                    }

                    if (te32.th32ThreadID == mainThreadId) {
                        ResumeThread(hThread);
                        // delay for the main thread to be resumed
                        Sleep(1000);
                    }
                    CloseHandle(hThread);
                }
                else {
                    printf("Failed to open thread. Error: %lu\n", GetLastError());
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    else {
        printf("Thread32First failed. Error:%lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
    return 0;
}




void SweetSleep(DWORD sleepTime) {


    
    DWORD mainThreadId = GetCurrentThreadId();

    // Suspend all threads , only the main thread 
    SuspendThreads(mainThreadId);
    // Iterate over all heaps allocations , and do encryption.
    // HeapEncryptDecrypt();
    
    ThreadParams params;
    params.mainThreadId = mainThreadId;
    params.sleepTime = sleepTime; // Example sleep time
    
    HANDLE hEncryptDecryptThread = CreateThread(NULL, 0, EncryptDecryptThread, &params, 0, NULL);
    if (hEncryptDecryptThread == NULL) {
        printf("Failed to create encrypt/decrypt thread. Error: %lu\n", GetLastError());
        return ;
    } else {
        printf("Encrypt/Decrypt thread created.\n");
    }
    WaitForSingleObject(hEncryptDecryptThread, INFINITE);
    CloseHandle(hEncryptDecryptThread);
    

    // Decrypt Allocations for heap only there is heap allocations
    // HeapEncryptDecrypt();
    // Resume Threads
    ResumeThreads(mainThreadId);





}


