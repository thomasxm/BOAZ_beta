import sys
import os

def xor_encode(data, key):
    return bytes(byte ^ key for byte in data)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    # Generate a random XOR key
    xor_key = os.urandom(1)[0]
    print(f"    const unsigned char XORkey[] = {{0x{xor_key:02x}}};\n")

    try:
        with open(file_path, "rb") as file:
            print("    const unsigned char XORed[] = {")
            while True:
                chunk = file.read(16)  # Process in 16-byte blocks
                if not chunk:
                    break
                encoded_chunk = xor_encode(chunk, xor_key)
                encoded_string = ', '.join(f"0x{byte:02x}" for byte in encoded_chunk)
                print(f"        {encoded_string},")
            print("    };")
    except IOError as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
