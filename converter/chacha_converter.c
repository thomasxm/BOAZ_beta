#include "chacha_converter.h"


#define ROUNDS 20

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (       \
    a += b, d ^= a, d = ROTL(d, 16), \
    c += d, b ^= c, b = ROTL(b, 12), \
    a += b, d ^= a, d = ROTL(d, 8),  \
    c += d, b ^= c, b = ROTL(b, 7))

void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    uint32_t x[16];
    memcpy(x, in, 64);
    for (i = 0; i < ROUNDS; i += 2) {
        // Column rounds
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; ++i) {
        out[i] = x[i] + in[i];
    }
}

void chacha20_keysetup(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    static const uint8_t sigma[16] = { 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' };
    memcpy(state, sigma, 16);
    memcpy(state + 4, key, 32);
    state[12] = counter;
    memcpy(state + 13, nonce, 12);
}

void chacha20_encrypt(uint8_t *output, const uint8_t *input, size_t length, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16], block[16];
    uint8_t keystream[64];
    size_t i, j;

    chacha20_keysetup(state, key, nonce, counter);
    for (i = 0; i < length; i += 64) {
        chacha20_block(block, state);
        for (j = 0; j < 64 && i + j < length; ++j) {
            keystream[j] = ((uint8_t *)block)[j];
        }
        for (j = 0; j < 64 && i + j < length; ++j) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
        state[12]++;
    }
}

void print_decrypted_result(const uint8_t *decrypted, size_t length) {
    printf("unsigned char decrypted[] = \n");
    for (size_t i = 0; i < length; i += 16) {
        printf("\"");
        for (size_t j = 0; j < 16 && i + j < length; ++j) {
            printf("\\x%02x", decrypted[i + j]);
        }
        printf("\"\n");
    }
    printf(";\n");
}

// Sample function to test decryption
void test_decryption() {
    // Sample data from Python script (replace with actual encrypted data, key, and nonce)
    unsigned char CHACHA20key[] = { 0xf3, 0x9e, 0xed, 0x9f, 0x15, 0x6b, 0x51, 0xca, 0x70, 0xfd, 0xa1, 0x1d, 0x00, 0x8f, 0x70, 0x3a, 0xfb, 0x8c, 0xad, 0x68, 0xb4, 0xca, 0x07, 0x77, 0xaa, 0x15, 0xdc, 0xc6, 0x3d, 0x60, 0x22, 0x6c };
    unsigned char CHACHA20nonce[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char magic_code[] = {
        0x35, 0x9b, 0x0c, 0x93, 0xf5, 0xcd, 0xce, 0xea, 0xb5, 0x0e, 0x42, 0xd6, 0x71, 0x46, 0xd7, 0x61,
        0x85, 0x21, 0xa1, 0x6b, 0x38, 0x4c, 0xb9, 0xfd, 0x30, 0xcd, 0x30, 0x80, 0xd6, 0x72, 0x63, 0x11,
        0x1a, 0x4f, 0x5c, 0xad, 0x2c, 0x2b, 0x72, 0x20, 0xf0, 0x68, 0xed, 0x87, 0xe4, 0x11, 0xcd, 0x31
    };
    size_t magic_code_len = sizeof(magic_code);

    uint8_t encrypted[magic_code_len];
    chacha20_encrypt(encrypted, magic_code, magic_code_len, CHACHA20key, CHACHA20nonce, 1);

    print_decrypted_result(encrypted, magic_code_len);

    uint8_t decrypted[magic_code_len];
    chacha20_encrypt(decrypted, encrypted, magic_code_len, CHACHA20key, CHACHA20nonce, 1);

    print_decrypted_result(decrypted, magic_code_len);
}