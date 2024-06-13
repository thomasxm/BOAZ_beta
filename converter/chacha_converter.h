#ifndef CHACHA_CONVERTER_H
#define CHACHA_CONVERTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>



void chacha20_encrypt(uint8_t *output, const uint8_t *input, size_t length, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
// void DecryptAES(char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen);
void print_decrypted_result(const uint8_t *decrypted, size_t length);
void test_decryption();

#endif // CHACHA_CONVERTER_H


// "\xe8\xc0\x51\x00\x00\xc0\x51\x00\x00\x4a\xa9\xb1\x2a\xc5\x35\x2b"
// "\xac\xd2\x54\xed\x25\x63\x3b\x18\x3e\x51\xa3\xeb\xf2\x9b\x35\xec"