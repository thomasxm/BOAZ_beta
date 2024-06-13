#ifndef CHACHA_CONVERTER_H
#define CHACHA_CONVERTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>



void chacha20_encrypt(uint8_t *output, const uint8_t *input, size_t length, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
void print_decrypted_result(const uint8_t *decrypted, size_t length);
void test_decryption();

#endif // CHACHA_CONVERTER_H
