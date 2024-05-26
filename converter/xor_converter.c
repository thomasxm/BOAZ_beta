#include "xor_converter.h"
 
void xorDecode(const unsigned char *encodedData, unsigned char *decodedData, size_t dataSize, const unsigned char *XORkey) {
    for (size_t i = 0; i < dataSize; ++i) {
        decodedData[i] = encodedData[i] ^ XORkey[0];
    }
}