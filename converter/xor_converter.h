#include <windows.h>  
#include <stdio.h>
#include <string.h>
#ifndef XOR_CONVERTER_H
#define XOR_CONVERTER_H


void xorDecode(const unsigned char *encodedData, unsigned char *decodedData, size_t dataSize, const unsigned char *XORkey);

#endif // XOR_CONVERTER_H
