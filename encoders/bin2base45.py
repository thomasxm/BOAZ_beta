import sys

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def base45_encode(data):
    encoded = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            x = (data[i] << 8) + data[i + 1]
            encoded.append(BASE45_ALPHABET[x // 45**2])
            encoded.append(BASE45_ALPHABET[(x // 45) % 45])
            encoded.append(BASE45_ALPHABET[x % 45])
        else:
            x = data[i]
            encoded.append(BASE45_ALPHABET[x // 45])
            encoded.append(BASE45_ALPHABET[x % 45])
    return ''.join(encoded)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <payload_file>")
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as f:
        content = f.read()
except Exception as e:
    print(f"Error reading file: {e}")
    sys.exit(1)

b45 = base45_encode(content)

# Print in the specific format requested
print(f"    const char base45[] = \"{b45}\";")
