from ipaddress import ip_address
import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 

with open(sys.argv[1], "rb") as f:
    chunk = f.read(4)
    print("{}const char* IPv4s[] =".format(' '*4))
    print("    {")
    while chunk:
        if len(chunk) < 4:
            padding = 4 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
            print("{}\"{}\"".format(' '*8,ip_address(chunk)))
            break
        print("{}\"{}\",".format(' '*8,ip_address(chunk)))
        chunk = f.read(4)
    print("    };")
