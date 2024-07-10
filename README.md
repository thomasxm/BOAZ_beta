# Boaz Mini-Evasion Tool (for educational purpose)



![c](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white) ![python](https://img.shields.io/badge/Python-00599C?style=for-the-badge&logo=python&logoColor=red) ![assembly](https://img.shields.io/badge/ASSEMBLY-ED8B00?style=for-the-badge&logo=Assembly&logoColor=white) ![windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

<img width="423" alt="loglo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/a5427ccc-e2ed-4cc3-ab81-084de691b23f">



<img width="352" alt="small_logo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/99abcf82-7084-47e5-a993-2a712b4ca664">



## Description

BOAZ (Bypass, Obfuscate, Adapt, Zero-Knowledge) evasion was inspired by the concept of multi-layered approach which is the evasive version of defence-in-depth (Swinnen & Mesbahi, 2014). It was developed to aid the penetration testing and antivirus defence testing. 

BOAZ aims to bypass the before and during execution detections that span signature, heuristic and be-havioural detection techniques. BOAZ supports x64 binary (PE) or raw playload (.bin) as input. It has been tested on separated Window-11 VMs with 14 Desktop AVs. The design of BOAZ evasion is modularised so users can add their own toolset, encoding or new techniques to the framework at will. It is written in both C and C++, and uses Python as the main program to link all modules together.

This tool has an alternative use: it can function as a packer or obfuscator to protect any x64 binary.

## Features

- **Modular Design**: Easily extendable with new tactics and techniques by adding scripts.

- **Signature Evasion**:
    - **LLVM IR level Obfuscation**: Pluto and Akira LLVM-based obfuscation including string encryption and control flow flattening.
    - **CodeBase obfuscation**:
        - Function name and string obfuscated from chars: [0-9a-zA-Z_] by 3 randomly selected algorithms: Mt19937, MinstdRand and ranlux48_base.
        - Shikata Ga Nai (SGN) encoding.
    - **Payload encoding (T1132)**:
        - UUID (Universally Unique Identifier)
        - MAC
        - IP4 format
        - base-64
        - base-45
        - base-58
        - Chacha20
        - AES
        - AES with divide and conquer to bypass logical path hijacking
    - **Compilation time obfuscation (LLVM, T1140, T1027)**:    
        - **Pluto**:
            - `bcf`: Bogus Control Flow
            - `fla`: Control Flow Flattening
            - `gle`: Global Variable Encryption
            - `mba`: Mixed-Boolean Arithmetic expressions ([MBA](https://theses.hal.science/tel-01623849/file/75068_EYROLLES_2017_archivage.pdf))
            - `sub`: Instruction Substitutions
            - `idc`: Indirect Call Promotion
            - `hlw`: Hide LLVM IR Level Warnings
        - **Akira**:
            - Indirect jumps and encrypted jump targets
            - Encrypted indirect function calls
            - Encrypted indirect global variable references
            - String encryption
            - Procedure-related control flow flattening
    - **Stripped binary (T1027.008)**
    - **Two methods to reduce entropy to below threshold by padding Pokémon names or null bytes**
    - **Signed certificate (T1036.001)**
    - **etadata copied from window binary (T1036)**

- **Heuristic Evasion**: 
    - **Anti-Emulation (T1497)**: checks based on file system operation, process and network information and “offer you have to refuse” [15, 38]. A simple heuristic that if 2 or more checks are failed, execution will stop. 
    - **Junk API instructions (“no-op” calls, or mimicry attack)**: 5 benign API functions to vary the API call sequences 
    - **API Unhooking**:
        - 1. Read the syscall stub from the original ntdll and rewrite the loaded ntdll’s stub
        - 2. Custom Peruns’ Fart unhooking
        - 3. Halo’s gate (TartarusGate)
    - **Sleep obfuscation: Custom Ekko (CreateTimerQueueTimer) with arbitrary sleep time invoked at run time**
    - **Stack encryption sleep**: Local variables and shellcode were being stored on stack. This part of memory is available for scanning both in emulator pre-execution and post-execution. 
    - **PIC convertor (T1027.009, T1027.002, T1620)**:
        - The donut (The Wover)
        - PE2SH (from the author of process-hacker)
        - RC4 encrypted convertor
        - Amber (by Ege Balcı)
        - Shoggoth (by frkngksl)
          
- **Behavioral Evasion**: 
    - **Various code execution and process injection loaders (T1055, T1106, T1027.007)**: A variety of loaders for different evasion scenarios
    - **Two LLVM-obfuscation compilers (T1027)**
    - **Output DLL/CPL (side-loading) (T1574.002, T1218.011/002)**
    - **ETW-patching (patch ETW stub with “xor rax, rax; ret”) (T1562.006)**
    - **API name spoofing via IAT, using CallObfuscator by d35ha**

    

## Prerequisites

- Linux environment with Wine configured. Kali Linux or other Debian prefered. 
- CMake, Git, GCC, G++, MingW, LLVM and other build essentials installed.

## Installation and Compilation

1. **Install required packages:**:

```console
git clone https://github.com/thomasxm/Boaz_beta/
cd Boaz_beta
```

```console
sudo bash requirements.sh
```

2. **Cavets**:

It should be noted that SGN encoder sometimes can generate bad characters, use with caution. 
requirements.sh will install LLVM, which takes a while to complete. BOAZ can be run without the -llvm handle; however, it is not optimised without the latter.

## Usage

Example usage:

```console
python3 Boaz.py -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid -g
```

Refer to the help command for more details on usage:

```console
python3 Boaz.py -h 
```

```bash
usage: Boaz.py [-h] -f INPUT_FILE [-o OUTPUT_FILE] [-divide] [-l LOADER] [-dll] [-cpl] [-sleep] [-a] [-etw] [-j] [-dream [DREAM]] [-u] [-g]
               [-t {donut,pe2sh,rc4,amber}] [-sd] [-sgn] [-e {uuid,xor,mac,ipv4,base64,base58,aes,chacha,aes2}] [-c {mingw,pluto,akira}]
               [-mllvm MLLVM] [-obf] [-w [SYSWHISPER]] [-entropy {1,2}] [-b [BINDER]] [-s [SIGN_CERTIFICATE]]

Process loader and shellcode.

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input-file INPUT_FILE
                        Path to binary.exe
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Optional: Specify the output file path and name. If not provided, a random file name will be used in the ./output
                        directory.
  -divide               Divide flag (True or False)
  -l LOADER, --loader LOADER
                        Loader number (must be a non-negative integer)
  -dll                  Compile the output as a DLL instead of an executable, can be run with rundll32.exe
  -cpl                  Compile the output as a CPL instead of an executable, can be run with control.exe
  -sleep                Obfuscation Sleep flag with random sleep time (True or False)
  -a, --anti-emulation  Anti-emulation flag (True or False)
  -etw                  Enable ETW patching functionality
  -j, --junk-api        Insert junk API function call at a random location in the main function (5 API functions)
  -dream [DREAM]        Optional: Sleep with encrypted stacks for specified time in milliseconds. Defaults to 1500ms if not provided.
  -u, --api-unhooking   Enable API unhooking functionality
  -g, --god-speed       Enable advanced unhooking technique Peruns Fart (God Speed)
  -t {donut,pe2sh,rc4,amber}, --shellcode-type {donut,pe2sh,rc4,amber}
                        Shellcode generation tool: donut (default), pe2sh, rc4, or amber
  -sd, --star_dust      Enable Stardust PIC generator, input should be .bin
  -sgn, --encode-sgn    Encode the generated shellcode using sgn tool.
  -e {uuid,xor,mac,ipv4,base64,base58,aes,chacha,aes2}, --encoding {uuid,xor,mac,ipv4,base64,base58,aes,chacha,aes2}
                        Encoding type: uuid, xor, mac, ip4, base64, base58 AES and aes2. aes2 is a devide and conquer AES decryption to bypass
                        logical path hijacking. Other encoders are under development.
  -c {mingw,pluto,akira}, --compiler {mingw,pluto,akira}
                        Compiler choice: mingw (default), pluto, or akira
  -mllvm MLLVM          LLVM passes for Pluto or Akira compiler
  -obf, --obfuscate     Enable obfuscation (optional)
  -w [SYSWHISPER], --syswhisper [SYSWHISPER]
                        Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps (default), 2 for compiling with MingW and NASM.
  -entropy {1,2}        Entropy level for post-processing the output binary. 1 for null_byte.py, 2 for pokemon.py
  -b [BINDER], --binder [BINDER]
                        Optional: Path to a utility for binding. Defaults to binder/calc.exe if not provided.
  -s [SIGN_CERTIFICATE], --sign-certificate [SIGN_CERTIFICATE]
                        Optional: Sign the payload using a cloned certificate from the specified website. Defaults to www.microsoft.com if no
                        website is provided.

```


## Evasion Modules

![Evasion101 (1)](https://github.com/thomasxm/BOAZ/assets/44269971/8c4d697b-73f6-44c4-825e-65ee27f09e68)


## Process Injection Loaders

![Process_injection_101](https://github.com/thomasxm/BOAZ/assets/44269971/232e635b-b692-4010-a65d-e5ceb39c1e5e)


## Example:

Boaz evasion wrapped Mimikatz.exe x64 release. The detection rate for wrapped Mimikatz is zero on Jotti:
<img width="1197" alt="Screenshot 2024-02-28 at 14 46 17" src="https://github.com/thomasxm/Bob-and-Alice/assets/44269971/5d756054-afeb-4103-a262-b39eff6bdd83">



## Roadmap

- **Docker**: Make it available with Docker without installation 
- **Loaders**: Implement more loader templates (process injection and code execution methods) with a divide and conquer option available.
- **COFF loaders**: Implement COFF loader suppport.
- **RISC-V VM** Implement new loader using RISC-V VM concept. 
- **Obfuscation**: Enhancing obfuscation methods and integrating new LLVM passes. 
- **Shellcode Generation**: Expand to include more techniques, e.g., PIC generated from arbitrary command, and offer users the choice of shellcode generation technique.
- **PIC Chain Reactions**: ....
- **Sleep Techniques**: Implementing additional anti-emulation and sleep techniques, like encrypting heap and stack while sleeping during pre-shellcode-execution phase. 
- **Syscall**: Improving Syswhisper2 integration for signature reduction. (e.g. on detecting virtual machine introspection and dynamic binary instrumentation)
- **Compilation**: Integrate additional compilier options like Cosmopolitan compiler.
- **File format**: Extend more file format supports, so that user can execute sample with signed utilities and more options.
- **binder**: add binder options....
- **modularised modules**: Although Boaz has all its implementations modularised in concept, it is not 'actually' modularised in its current beta version. Owing to the fact that this tool is a side project for my dissertation, I need to find time to separate each function into an actual module and ensure that each is presented with a template so that users can add a new technique and integrate it into the main programme without the need to change the main programme or other modules.
- **Templates**: using YAML and JSON files to configure and modularise the program. 

## Contributing

We welcome contributions to improve the Boaz Evasion Tool. Please review `CONTRIBUTING.md` for guidelines on how to submit contributions. 


We welcome submissions to [pull requests](https://github.com/thomasxm/Boaz_beta/pulls) and [issues](https://github.com/thomasxm/Boaz_beta/issues).


This is in development, please feel free to reach out to me @ThomasMeeeee on X for any suggestions! 

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

A special thanks to the researchers and developers whose work has inspired, contributed to, and made this tool possible: 

* [Inceptor - Bypass AV-EDR solutions combining well known techniques](https://github.com/klezVirus/inceptor/blob/main/slides/Inceptor%20-%20Bypass%20AV-EDR%20solutions%20combining%20well%20known%20techniques.pdf)

* [The donut](https://github.com/TheWover/donut)

* [avcleaner](https://github.com/scrt/avcleaner)

* [Pluto](https://github.com/bluesadi/Pluto)

* [Arkari](https://github.com/KomiMoe/Arkari)

* [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
* [Shellcode-Hide](https://github.com/SaadAhla/Shellcode-Hide)

* [PE2Shellcode](https://github.com/r00tkiter/PE2Shellcode)
* [Amber](https://github.com/thomasxm/amber)
* [Shoggoth](https://github.com/frkngksl/Shoggoth)
* [Mangle](https://github.com/optiv/Mangle)
* [CallObfuscator](https://github.com/d35ha/CallObfuscator)
* [Stardust](https://github.com/Cracked5pider/Stardust/tree/main)
* [Carbon Copy](https://github.com/paranoidninja/CarbonCopy)
* [Shikata ga nai](https://github.com/EgeBalci/sgn)
* [x86matthew](https://www.x86matthew.com/)
* [Red Team Notes](https://www.ired.team/)

And many more blogs and articles. Please feel free to add more...

## Contact

For any queries or contributions, please contact the repository owner.










![Boaz_logo3](https://github.com/thomasxm/Boaz_beta/assets/44269971/0118a0cf-9cd9-48df-8f20-37a059e4bf6a)





































