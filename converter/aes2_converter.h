#include <windows.h>  
#include <stdio.h>    
#include <stdlib.h>
#ifndef AES2_CONVERTER_H
#define AES2_CONVERTER_H


void DecryptAES(char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen);
long long int fibonacci(int n);
void printFactorial(unsigned int n);

void startExe(const char* exeName);


#endif // AES2_CONVERTER_H
