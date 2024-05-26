#include <windows.h>  
#include <string.h>
#ifndef BASE64_CONVERTER_H
#define BASE64_CONVERTER_H

DWORD CalculateDecodedSize(const char* base64str);
int CustomCryptStringToBinaryA(const char* base64str, DWORD base64strLen, BYTE* binary, DWORD* binaryLen);

#endif // BASE64_CONVERTER_H
