import sys

def bin_to_c_array(file_path, output_path):
    with open(file_path, 'rb') as file:
        file_content = file.read()

    lines = []
    for i in range(0, len(file_content), 16):
        hex_str = ''.join(f'\\x{byte:02x}' for byte in file_content[i:i+16])
        lines.append(f'"{hex_str}"')

    formatted_lines = '\n'.join(lines)
    c_array = f'unsigned char buf[] = \n{formatted_lines};\n'

    with open(output_path, 'w') as output_file:
        output_file.write(c_array)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bin_to_c_array.py <input_file.bin> <output_file.c>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    bin_to_c_array(input_file, output_file)
    print(f"Converted {input_file} to a C array in {output_file}.")
