from macaddress import MAC
import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 

with open(sys.argv[1], "rb") as f:
    chunk = f.read(6)
    print("{}const char* MAC[] =".format(' '*4))
    print("    {")
    while chunk:
        if len(chunk) < 6:
            padding = 6 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
            print("{}\"{}\"".format(' '*8,MAC(chunk)))
            break
        print("{}\"{}\",".format(' '*8,MAC(chunk)))
        chunk = f.read(6)
    print("    };")
