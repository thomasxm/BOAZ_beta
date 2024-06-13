#include <windows.h>  
#include <string.h>
#ifndef BASE45_CONVERTER_H
#define BASE45_CONVERTER_H

DWORD CalculateBase45DecodedSize(const char* base45str);
int CustomBase45ToBinary(const char* base45str, DWORD base45strLen, BYTE* binary, DWORD* binaryLen);

#endif // BASE45_CONVERTER_H
