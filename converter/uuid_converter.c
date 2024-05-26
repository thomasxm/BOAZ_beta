#include "uuid_converter.h"
// #include <stdlib.h> // for malloc
#include <string.h> // for memcpy
#include <stdio.h>

void customUuidFromString(const char* uuidStr, unsigned char* bytes) {
    unsigned int data[16] = {0};
    sscanf(uuidStr, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           &data[3], &data[2], &data[1], &data[0], &data[5], &data[4], &data[7], &data[6],
           &data[8], &data[9], &data[10], &data[11], &data[12], &data[13], &data[14], &data[15]);

    for (int i = 0; i < 16; ++i) {
        bytes[i] = static_cast<unsigned char>(data[i]);
    }
}

void convertUUIDsToMagicCode(const char* UUIDs[], unsigned char* magiccode, int numUuids) {
    // Assuming numUuids is passed correctly as the number of UUIDs
    for (int i = 0; i < numUuids; i++) {
        unsigned char bytes[16];
        customUuidFromString(UUIDs[i], bytes);
        memcpy(magiccode + (i * 16), bytes, 16);
    }
}

// unsigned char convertUUIDsToMagicCode(const char* UUIDs[]) {


//     constexpr int numUuids = sizeof(UUIDs) / sizeof(UUIDs[0]);  

//     unsigned char magiccode[numUuids * 16];
    
//     // Convert each UUID to binary and store in magicCode
//     for (int i = 0; i < numUuids; i++) {
//         unsigned char bytes[16];
//         customUuidFromString(UUIDs[i], bytes);
//         memcpy(magiccode + (i * 16), bytes, 16);
//     }
    
//     return magiccode;
// }
