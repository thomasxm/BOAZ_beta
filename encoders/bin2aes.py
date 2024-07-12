import sys
import subprocess

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    print("PyCryptodome is not installed. Installing now...")
    install('pycryptodome')
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(KEY).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext,key

  
def printResult(key, ciphertext):
    print('unsigned char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
    print('unsigned char magiccode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
    
try:
    file = open(sys.argv[1], "rb")
    content = file.read()
except:
    print("Usage: .\\bin2aes.py payload_file")
    sys.exit()


KEY = urandom(16)
ciphertext, key = AESencrypt(content, KEY)

printResult(KEY,ciphertext)


