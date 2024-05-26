#include "base58_converter.h" 

/// Hello bitcoin
// Base-58 character set
static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to calculate the decoded size of a base-58 encoded string
DWORD CalculateDecodedSizeBase58(const char* base58str) {
    DWORD base58strLen = strlen(base58str);
    // Rough estimation of decoded size. Adjust as needed for padding or other considerations.
    return (DWORD)ceil((base58strLen * log(58)) / log(256));
}

// Function to find the value of a base-58 character
int base58_char_value(char c) {
    const char* found = strchr(base58_chars, c);
    if (found) {
        return (int)(found - base58_chars);
    } else {
        return -1; // Indicates error
    }
}

// Function to convert a base-58 encoded string to binary
int CustomCryptStringToBinaryA(const char* base58str, DWORD base58strLen, BYTE* binary, DWORD* binaryLen) {
    DWORD expectedLen = CalculateDecodedSizeBase58(base58str);
    if (expectedLen > *binaryLen) {
        // The provided binary buffer size (*binaryLen) is too small for the decoded data
        return 0;
    }

    memset(binary, 0, *binaryLen); // Initialize the binary array to zeros

    for (DWORD i = 0; i < base58strLen; ++i) {
        int val = base58_char_value(base58str[i]);
        if (val == -1) {
            // Invalid character in base58 string
            return 0;
        }
        unsigned int carry = val;
        for (int j = *binaryLen - 1; j >= 0; --j) {
            carry += 58 * binary[j];
            binary[j] = carry % 256;
            carry /= 256;
        }
    }

    // Calculate the number of leading zeros in the binary array
    DWORD zeros = 0;
    for (; zeros < *binaryLen && binary[zeros] == 0; ++zeros);

    // Adjust the binaryLen to exclude leading zeros, if necessary
    if (zeros > 0) {
        memmove(binary, binary + zeros, *binaryLen - zeros);
        memset(binary + *binaryLen - zeros, 0, zeros); // Zero-fill the end of the buffer if shifted
        *binaryLen -= zeros;
    }

    return 1; // Success
}


// // Base-58 character set
// static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// // Function to calculate the decoded size of a base-58 encoded string
// DWORD CalculateDecodedSizeBase58(const char* base58str) {
//     DWORD base58strLen = strlen(base58str);
//     // More accurate estimation of decoded size, considering log(256)/log(58) is approximately 1.365658...
//     return (DWORD)ceil(base58strLen * log(58) / log(256));
// }

// // Function to find the value of a base-58 character
// int base58_char_value(char c) {
//     const char* found = strchr(base58_chars, c);
//     if (found) {
//         return (int)(found - base58_chars);
//     } else {
//         return -1; // Indicates error
//     }
// }

// // Function to convert a base-58 encoded string to binary
// int CustomCryptStringToBinaryA(const char* base58str, DWORD base58strLen, BYTE* binary, DWORD* binaryLen) {
//     DWORD expectedLen = CalculateDecodedSizeBase58(base58str);
//     if (expectedLen > *binaryLen) {
//         // The provided binary buffer size (*binaryLen) is too small for the decoded data
//         return 0;
//     }

//     memset(binary, 0, *binaryLen); // Initialize the binary array to zeros

//     for (DWORD i = 0; i < base58strLen; ++i) {
//         int val = base58_char_value(base58str[i]);
//         if (val == -1) {
//             // Invalid character in base58 string
//             return 0;
//         }
//         unsigned int carry = val;
//         for (int j = *binaryLen - 1; j >= 0; --j) {
//             carry += 58 * binary[j];
//             binary[j] = carry % 256;
//             carry /= 256;
//         }
//         // Handling potential overflow if carry is still non-zero here could be critical for longer inputs
//     }

//     // Calculate the number of leading zeros in the binary array and in the Base58 string
//     DWORD leadingZeros = 0;
//     for (; leadingZeros < base58strLen && base58str[leadingZeros] == '1'; ++leadingZeros);
//     DWORD binaryLeadingZeros = 0;
//     for (; binaryLeadingZeros < *binaryLen && binary[binaryLeadingZeros] == 0; ++binaryLeadingZeros);

//     // Adjust if Base58 leading '1's are more than binary leading zeros, to match the expected format
//     if (leadingZeros > binaryLeadingZeros) {
//         DWORD shift = leadingZeros - binaryLeadingZeros;
//         if (*binaryLen + shift > expectedLen) shift = expectedLen - *binaryLen; // Safety check
//         memmove(binary + shift, binary, *binaryLen - shift);
//         memset(binary, 0, shift); // Fill the beginning with zeros
//         *binaryLen += shift;
//     }

//     return 1; // Success
// }