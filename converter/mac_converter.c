#include "mac_converter.h"
/// Mac part begin:
#include <stdio.h>
#include <stdlib.h>
// Modified custom function to process an array of MAC address strings
void CustomEthernetStringToAddressArray(const char** macArray, int arraySize, unsigned char* destBuffer) {
    for (int i = 0; i < arraySize; i++) {
        const char* macStr = macArray[i];
        int values[6]; // To store the parsed hex values

        // sscanf parses the input string according to the format provided
        // Each "%02x" reads two hexadecimal characters as one byte
        // The results are stored in the values array
        if (sscanf(macStr, "%02x-%02x-%02x-%02x-%02x-%02x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]) == 6) {
            // Loop through the parsed values and assign them to the current position in destination buffer
            for (int j = 0; j < 6; ++j) {
                destBuffer[i * 6 + j] = (unsigned char)values[j]; // Cast to unsigned char to ensure proper byte size
            }
        } else {
            // Handle error: invalid MAC address format
            printf("Invalid MAC address format: %s\n", macStr);
            // Optionally, you could memset the current mac address slot in destBuffer to 0 or another value indicating an error
        }
    }
}
// // Custom function to parse a MAC address string and store its byte representation
// void CustomEthernetStringToAddressA(const char* macStr, unsigned char* dest) {
//     int values[6]; // To store the parsed hex values

//     // sscanf parses the input string according to the format provided
//     // Each "%02x" reads two hexadecimal characters as one byte
//     // The results are stored in the values array
//     if (sscanf(macStr, "%02x-%02x-%02x-%02x-%02x-%02x",
//                &values[0], &values[1], &values[2],
//                &values[3], &values[4], &values[5]) == 6) {
//         // Loop through the parsed values and assign them to the destination
//         for (int i = 0; i < 6; ++i) {
//             dest[i] = (unsigned char)values[i]; // Cast to unsigned char to ensure proper byte size
//         }
//     } else {
//         // Handle error: invalid MAC address format
//         printf("Invalid MAC address format: %s\n", macStr);
//     }
// }
///Mac part end.