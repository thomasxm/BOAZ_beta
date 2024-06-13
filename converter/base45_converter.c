#include "base45_converter.h"
#include <cstring>


#define BASE45_ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

DWORD CalculateBase45DecodedSize(const char* base45str) {
    DWORD base45strLen = strlen(base45str);
    return (base45strLen * 2) / 3;
}

int base45_char_value(char c) {
    const char* pos = strchr(BASE45_ALPHABET, c);
    if (pos) {
        return (int)(pos - BASE45_ALPHABET);
    } else {
        return -1; // Indicates error or invalid character
    }
}

int CustomBase45ToBinary(const char* base45str, DWORD base45strLen, BYTE* binary, DWORD* binaryLen) {
    DWORD expectedLen = CalculateBase45DecodedSize(base45str);
    DWORD j = 0, k = 0;
    unsigned char decoded[2];

    for (DWORD i = 0; i < base45strLen; i += 3) {
        int values[3] = {0};
        for (int n = 0; n < 3; ++n) {
            if (i + n < base45strLen) {
                values[n] = base45_char_value(base45str[i + n]);
                if (values[n] == -1) {
                    return 0; // Error if invalid character
                }
            } else {
                values[n] = 0;
            }
        }

        int combined = (values[0] * 45 * 45) + (values[1] * 45) + values[2];
        decoded[0] = combined / 256;
        decoded[1] = combined % 256;

        for (k = 0; k < 2; ++k) {
            if (j + k < expectedLen) { // Avoid buffer overflow and correctly handle padding
                binary[j + k] = decoded[k];
            }
        }
        j += 2;
    }

    *binaryLen = expectedLen; // Correctly set the binaryLen to the actual expected length
    return 0; 
}