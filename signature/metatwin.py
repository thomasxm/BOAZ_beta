import subprocess
import sys
import os
import tempfile

def run_with_wine(executable, args):
    wine_cmd = ['wine', executable] + args
    log_file = '/tmp/wine_output.log'
    print(f"Running command: {' '.join(wine_cmd)} and logging to {log_file}")
    with open(log_file, 'w') as f:
        try:
            result = subprocess.run(wine_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            f.write(result.stdout)
            f.write(result.stderr)
            result.check_returncode()  # This will raise CalledProcessError if the command returned a non-zero exit status
        except subprocess.CalledProcessError as e:
            print(f"Command '{' '.join(wine_cmd)}' returned non-zero exit status {e.returncode}")
            print(f"Check the log file at {log_file} for more details")
            raise

def copy_metadata(source_file, target_file, resource_hacker_path, sigthief_path):
    # Create a temporary directory to store extracted resources
    with tempfile.TemporaryDirectory() as temp_dir:
        resource_file = os.path.join(temp_dir, 'resources.res')
        
        # Step 1: Use Resource Hacker to extract resource information from the source file
        extract_args = [
            '-open', source_file,
            '-save', resource_file,
            '-action', 'extract',
            '-mask', ',,,'
        ]
        print(f"[+] Extracting resources from {source_file} to {resource_file}")
        run_with_wine(resource_hacker_path, extract_args)
        
        # Verify that the resource file was created and is not empty
        if not os.path.exists(resource_file) or os.path.getsize(resource_file) == 0:
            print(f"Resource extraction failed, {resource_file} does not exist or is empty")
            sys.exit(1)
        
        # Step 2: Use Resource Hacker to add/overwrite resource information to the target file
        # and save the result to a new file prefixed with res_
        res_target_file = os.path.join(os.path.dirname(target_file), 'res_' + os.path.basename(target_file))
        add_args = [
            '-open', target_file,
            '-save', res_target_file,
            '-action', 'addoverwrite',
            '-resource', resource_file,
        ]
        print(f"Adding resources to {res_target_file} from {resource_file}")
        run_with_wine(resource_hacker_path, add_args)

    # Step 3: Use SigThief to copy the signature from the source file to the target file
    # and save the result to a new file prefixed with signed_
    signed_target_file = os.path.join(os.path.dirname(res_target_file), 'signed_' + os.path.basename(res_target_file))
    sigthief_args = [
        '-i', source_file,
        '-t', res_target_file,
        '-o', signed_target_file
    ]
    print(f"[+] Copying signature to {signed_target_file}")
    run_with_wine(sigthief_path, sigthief_args)
    
    print(f"[+] Resources copied from {source_file} to {res_target_file}")
    print(f"[+] Signature copied from {source_file} to {signed_target_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("[!] Usage: python3 metatwin.py <source_file> <target_file>")
        sys.exit(1)

    source_file = os.path.abspath(sys.argv[1])
    target_file = os.path.abspath(sys.argv[2])

    # Paths to Resource Hacker and SigThief executables
    # resource_hacker_path = os.path.abspath('ResourceHacker.exe')
    # sigthief_path = os.path.abspath('sigthief.exe')
    resource_hacker_path = os.path.abspath('./signature/ResourceHacker.exe')
    sigthief_path = os.path.abspath('./signature/sigthief.exe')

    # Check if the executables exist
    if not os.path.isfile(resource_hacker_path):
        print("[-] Resource Hacker not found. Please ensure it is installed and in the system's PATH.")
        sys.exit(1)

    if not os.path.isfile(sigthief_path):
        print("[-] SigThief not found. Please ensure it is installed and in the system's PATH.")
        sys.exit(1)

    copy_metadata(source_file, target_file, resource_hacker_path, sigthief_path)
