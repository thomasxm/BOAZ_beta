#include "ipv4_converter.h"
//// IPV4 part: 

#include <stdlib.h> // for malloc
#include <stdio.h>   // for printf
// void ParseIPv4StringAndStore(const char* ipString, unsigned char* dest) {
//     unsigned int a, b, c, d;
//     sscanf(ipString, "%u.%u.%u.%u", &a, &b, &c, &d);
//     dest[0] = a & 0xFF;
//     dest[1] = b & 0xFF;
//     dest[2] = c & 0xFF;
//     dest[3] = d & 0xFF;
// }

// // Function to convert an array of IPv4 strings to a shellcode (magiccode) buffer
// void convertIPv4sToMagicCode(const char* IPv4s[], unsigned char* magiccode, int numIPs) {
//     for (int i = 0; i < numIPs; i++) {
//         ParseIPv4StringAndStore(IPv4s[i], &magiccode[i * 4]);
//     }
// }

// Function to parse a single IPv4 string and store its byte representation
// void ParseIPv4StringAndStore(const char* ipString, unsigned char* dest) {
//     unsigned int a, b, c, d;
//     sscanf(ipString, "%u.%u.%u.%u", &a, &b, &c, &d);
//     dest[0] = a & 0xFF;
//     dest[1] = b & 0xFF;
//     dest[2] = c & 0xFF;
//     dest[3] = d & 0xFF;
//     printf("Converted: %s -> %02x %02x %02x %02x\n", ipString, dest[0], dest[1], dest[2], dest[3]);
// }

// // Function to convert an array of IPv4 strings to a shellcode (magiccode) buffer
// void convertIPv4sToMagicCode(const char* IPv4s[], unsigned char* magiccode, int numIPs) {
//     for (int i = 0; i < numIPs; i++) {
//         printf("Converting IP %d: %s\n", i + 1, IPv4s[i]);
//         ParseIPv4StringAndStore(IPv4s[i], &magiccode[i * 4]);
//     }
// }
// Function to parse a single IPv4 string and store its byte representation
void ParseIPv4StringAndStore(const char* ipString, unsigned char* dest) {
    unsigned int a, b, c, d;
    sscanf(ipString, "%u.%u.%u.%u", &a, &b, &c, &d);
    dest[0] = a & 0xFF;
    dest[1] = b & 0xFF;
    dest[2] = c & 0xFF;
    dest[3] = d & 0xFF;
}

// Function to convert an array of IPv4 strings to a shellcode (magiccode) buffer
void convertIPv4sToMagicCode(const char* IPv4s[], unsigned char* magiccode, int numIPs) {
    for (int i = 0; i < numIPs; i++) {
        ParseIPv4StringAndStore(IPv4s[i], &magiccode[i * 4]);
        
        // Debug message for the first 8 bytes
        if (i == 0) {
            printf("First 4 bytes: %02x %02x %02x %02x\n", magiccode[0], magiccode[1], magiccode[2], magiccode[3]);
        } else if (i == 1) {
            printf("Next 4 bytes: %02x %02x %02x %02x\n", magiccode[4], magiccode[5], magiccode[6], magiccode[7]);
        }
    }

    // Debug message for the last 8 bytes
    if (numIPs >= 2) {
        printf("Last 8 bytes: ");
        for (int i = numIPs - 2; i < numIPs; i++) {
            int index = i * 4;
            printf("%02x %02x %02x %02x ", magiccode[index], magiccode[index + 1], magiccode[index + 2], magiccode[index + 3]);
        }
        printf("\n");
    }
}
