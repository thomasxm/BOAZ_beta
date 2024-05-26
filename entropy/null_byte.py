### Script to reduce file entropy. 
# def append_zeros_to_file(filename):
#     """Append 50 null bytes (0x00) to the end of a file."""
#     with open(filename, "ab") as file:
#         file.write(b'\x00' * 5000)

# if __name__ == "__main__":
#     import sys
#     if len(sys.argv) < 2:
#         print("Usage: python append_zeros.py <filename>")
#         sys.exit(1)
    
#     filename = sys.argv[1]
#     append_zeros_to_file(filename)
#     print(f"Appended many zeros to {filename}")

import math
import sys

def calculate_entropy(file_path):
    """Calculate the Shannon entropy of a file."""
    with open(file_path, "rb") as file:
        byte_arr = file.read()
        file_size = len(byte_arr)
        if file_size == 0:
            # Empty file
            return 0
        # Calculate the frequency of each byte value in the file
        freq_list = [byte_arr.count(bytes([x])) / file_size for x in range(256)]
        # Calculate the entropy
        entropy = -sum([freq * math.log2(freq) for freq in freq_list if freq > 0])
        return entropy

def append_zeros_to_file(file_path, num_zeros=200):
    """Append specified number of 0x00 bytes to the end of a file."""
    with open(file_path, "ab") as file:
        file.write(b'\x00' * num_zeros)

def reduce_entropy(file_path, threshold=6.1):
    """Reduce the entropy of a file by appending 0x00 bytes until it's below the threshold."""
    entropy = calculate_entropy(file_path)
    print(f"Initial entropy: {entropy}")
    
    while entropy > threshold:
        append_zeros_to_file(file_path)
        entropy = calculate_entropy(file_path)
        print(f"Appended 200 zeros, new entropy: {entropy}")
    
    print(f"Final entropy: {entropy}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python entropy_reducer.py <filename>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    reduce_entropy(file_path)
