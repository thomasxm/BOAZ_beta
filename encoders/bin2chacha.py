import struct

# Constants
ROUNDS = 20

def rotl(a, b):
    return ((a << b) & 0xffffffff) | (a >> (32 - b))

def qr(a, b, c, d):
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl(d, 16)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl(b, 12)
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotl(d, 8)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotl(b, 7)
    return a, b, c, d

def chacha20_block(state):
    x = state[:]
    for _ in range(ROUNDS // 2):
        x[0], x[4], x[8], x[12] = qr(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = qr(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = qr(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = qr(x[3], x[7], x[11], x[15])
        x[0], x[5], x[10], x[15] = qr(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = qr(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = qr(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = qr(x[3], x[4], x[9], x[14])
    for i in range(16):
        x[i] = (x[i] + state[i]) & 0xffffffff
    return x

def chacha20_keysetup(key, nonce, counter):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
    key_state = struct.unpack('<8I', key)
    nonce_state = struct.unpack('<3I', nonce)
    return constants + list(key_state) + [counter] + list(nonce_state)

def chacha20_encrypt(plaintext, key, nonce, counter):
    state = chacha20_keysetup(key, nonce, counter)
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block(state)
        keystream = struct.pack('<16I', *block)
        for j in range(min(64, len(plaintext) - i)):
            ciphertext.append(plaintext[i + j] ^ keystream[j])
        state[12] = (state[12] + 1) & 0xffffffff
    return bytes(ciphertext)

def printResult(key, nonce, ciphertext):
    print('unsigned char CHACHA20key[] = { ' + ', '.join('0x{:02x}'.format(x) for x in key) + ' };')
    print('unsigned char CHACHA20nonce[] = { ' + ', '.join('0x{:02x}'.format(x) for x in nonce) + ' };')
    print('unsigned char magic_code[] = ')
    for i in range(0, len(ciphertext), 16):
        print('"' + ''.join('\\x{:02x}'.format(x) for x in ciphertext[i:i+16]) + '"')
    print(';')

if __name__ == "__main__":
    import sys
    from os import urandom

    if len(sys.argv) != 2:
        print("Usage: python bin2chacha20.py payload_file")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, "rb") as file:
        content = file.read()

    key = urandom(32)
    # nonce = b'\x00' * 12  # Fixed 12-byte nonce for deterministic results
    nonce = urandom(12)

    ciphertext = chacha20_encrypt(content, key, nonce, 1)

    printResult(key, nonce, ciphertext)
