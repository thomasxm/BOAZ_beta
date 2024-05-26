#include "base64_converter.h" 
//// Base64 part: #include <windows.h>   

DWORD CalculateDecodedSize(const char* base64str) {
    DWORD base64strLen = strlen(base64str);
    // Adjust for padding
    if (base64strLen >= 2 && base64str[base64strLen - 1] == '=') base64strLen--;
    if (base64strLen >= 1 && base64str[base64strLen - 2] == '=') base64strLen--;

    return (base64strLen * 3) / 4;
}

int base64_char_value(char c) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char* found = strchr(base64_chars, c);
    if (found) {
        return (int)(found - base64_chars);
    } else {
        return -1; // Indicates error or padding
    }
}

int CustomCryptStringToBinaryA(const char* base64str, DWORD base64strLen, BYTE* binary, DWORD* binaryLen) {
    DWORD expectedLen = CalculateDecodedSize(base64str); // Use CalculateDecodedSize to get the correct expected length
    DWORD j = 0, k = 0;
    unsigned char decoded[3];

    for (DWORD i = 0; i < base64strLen; i += 4) {
        int values[4] = {0};
        for (int n = 0; n < 4; ++n) {
            values[n] = base64_char_value(base64str[i + n]);
            if (values[n] == -1) {
                if (base64str[i + n] != '=')
                    return 0; // Error if not padding character
            }
        }

        decoded[0] = (values[0] << 2) | (values[1] >> 4);
        decoded[1] = (values[1] & 0x0F) << 4 | (values[2] >> 2);
        decoded[2] = ((values[2] & 0x03) << 6) | values[3];

        for (k = 0; k < 3; ++k) {
            if (j + k < expectedLen) { // Avoid buffer overflow and correctly handle padding
                binary[j + k] = decoded[k];
            }
        }
        j += 3;
    }

    *binaryLen = expectedLen; // Correctly set the binaryLen to the actual expected length
    return 1; // Success
}