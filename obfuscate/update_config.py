import random
import re

# List of benign Windows API functions that are typically safe
benign_functions = [
    "CreateFile", "CloseHandle", "ReadFileEx", "WriteFileEx",
    "GetFileSize", "SetFilePointer", "FlushFileBuffers",
    "CreateProcess", "ExitProcess", "WaitForSingleObject",
    "MessageBox", "SetWindowText", "GetWindowText"
]

def read_and_modify_config(filename):
    # Read the contents of the file
    with open(filename, 'r') as file:
        lines = file.readlines()

    # Process lines for replacements
    modified_lines = []
    should_replace_next_line = False
    for line in lines:
        stripped_line = line.strip()
        
        # Check for sections and determine if next line should be replaced
        if stripped_line in ('[user32.dll]', '[ntdll.dll]', '[kernel*.dll]'):
            should_replace_next_line = True
            modified_lines.append(line)
            continue
        
        if should_replace_next_line:
            # Extract current mapping and replace function
            if '=' in line:
                parts = line.split('=')
                new_function = random.choice(benign_functions)
                line = f"{parts[0]}={new_function}\n"
            should_replace_next_line = False
        
        # Append the line, modified or not
        modified_lines.append(line)

    # Write the modified contents back to the file
    with open(filename, 'w') as file:
        file.writelines(modified_lines)

# Usage
config_filename = "obfuscate/config.ini"
read_and_modify_config(config_filename)
