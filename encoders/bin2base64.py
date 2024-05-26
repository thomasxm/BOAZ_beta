import sys
import base64

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <payload_file>")
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as f:
        content = f.read()
except Exception as e:
    print(f"Error reading file: {e}")
    sys.exit(1)

b64 = base64.b64encode(content).decode("utf-8")

# Print in the specific format requested
print(f"    const char base64[] = \"{b64}\";")
