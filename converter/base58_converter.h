#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#ifndef BASE58_CONVERTER_H
#define BASE58_CONVERTER_H

DWORD CalculateDecodedSizeBase58(const char* base58str);
int CustomCryptStringToBinaryA(const char* base58str, DWORD base58strLen, BYTE* binary, DWORD* binaryLen);

#endif // BASE58_CONVERTER_H
