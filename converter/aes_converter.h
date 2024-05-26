#include <windows.h>  
#include <stdio.h>    
#ifndef AES_CONVERTER_H
#define AES_CONVERTER_H


void DecryptAES(char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen);

#endif // AES_CONVERTER_H
