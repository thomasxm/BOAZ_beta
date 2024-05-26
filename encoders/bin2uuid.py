import sys
import uuid

def bytes_to_uuid_string(bytes_block):
    # Ensure the block is exactly 16 bytes long for UUID conversion
    if len(bytes_block) < 16:
        bytes_block += b'\x90' * (16 - len(bytes_block))  # Pad with \x00 bytes if less than 16 bytes

    # Manually format the UUID string according to the specific byte order
    parts = [
        bytes_block[0:4][::-1],  # Reverse the first 4-byte segment
        bytes_block[4:6][::-1],  # Reverse the next 2-byte segment
        bytes_block[6:8][::-1],  # Reverse the next 2-byte segment
        bytes_block[8:10],       # Keep the next 2-byte segment as is
        bytes_block[10:16]       # Keep the last 6-byte segment as is
    ]
    # Convert each part to hexadecimal and format as a UUID string
    return '{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:012x}'.format(
        int.from_bytes(parts[0], byteorder='big'),
        int.from_bytes(parts[1], byteorder='big'),
        int.from_bytes(parts[2], byteorder='big'),
        parts[3][0], parts[3][1],
        int.from_bytes(parts[4], byteorder='big')
    )

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <binary_file>")
    sys.exit(1)

file_path = sys.argv[1]

try:
    with open(file_path, "rb") as file:
        print("    const char* UUIDs[] = {")
        while True:
            chunk = file.read(16)
            if not chunk:
                break
            uuid_string = bytes_to_uuid_string(chunk)
            print(f"        \"{uuid_string}\",")
        print("    };")
except IOError as e:
    print(f"Error opening file: {e}")
    sys.exit(1)
