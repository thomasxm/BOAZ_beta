
> **Note:** This project is no longer actively maintained. It may still receive occasional updates, but no regular development or support is planned. Use at your own discretion.

![output](https://github.com/user-attachments/assets/a7cb09fc-7ffb-4a0b-83d3-a047b309d761)

# BOAZ Evasion and Antivirus Testing Tool (for educational purpose)



![c](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white) ![python](https://img.shields.io/badge/Python-00599C?style=for-the-badge&logo=python&logoColor=red) ![assembly](https://img.shields.io/badge/ASSEMBLY-ED8B00?style=for-the-badge&logo=Assembly&logoColor=white) ![windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)


[Features](#Features) | [Installation](#installation) | [Docker Setup & Installation](#docker-setup--installation) | [Usage](#Usage) | [Evasion Module](#evasion-modules)

## Presentation

1. [BlackHat USA, 2024 - Arsenal](https://www.blackhat.com/us-24/arsenal/schedule/index.html#boaz-yet-another-layered-evasion-tool-evasion-tool-evaluations-and-av-testing-38960)
2. [DEFCON-33](https://hackertracker.app/event/?conf=DEFCON33&event=61439)

Special thanks to Professor Rich Macfarlane [@rjmacfarlane](https://x.com/rjmacfarlane?lang=en).

## Description

BOAZ (Bypass, Obfuscate, Adapt, Zero-trace) evasion was inspired by the concept of multi-layered approach which is the evasive version of defence-in-depth first mentioned in “One packer to rule them all” at BH USA14 ([Swinnen & Mesbahi, 2014](https://www.blackhat.com/docs/us-14/materials/us-14-Mesbahi-One-Packer-To-Rule-Them-All.pdf)). BOAZ was developed to provide greater control over combinations of evasion methods, enabling more granular evaluations against antivirus and EDR [39]. 

BOAZ aims to bypass the before and during execution phases that span signature, heuristic and behavioural-based detection methods. BOAZ supports x64 binary (PE) or raw playload (.bin) as input. It has been tested on separated Window-11 Enterprise, Windows-10 and windows Server 2022 VMs (version: 22H2, 22621.1992) with 14 Desktop AVs and 7 EDRs installed include Windows Defender, Norton, BitDefender, Sophos and ESET. BOAZ’s modular design facilitates user customisation, enabling researchers to integrate their own toolsets or techniques. BOAZ is written in C++ and C and uses Python3 as the main linker to integrate all modules. 

For students and researchers in offensive security, no advanced programming or scripting knowledge or skills are required to use BOAZ to generate undetectable polymorphic samples.

This tool has an alternative use: it can function as a packer or obfuscator.



## Features

- **Modular Design**: Easily extendable with new tactics and techniques by adding scripts.

- [ ] **Signature Evasion**:
    - **LLVM IR level Obfuscation**: Pluto and Akira LLVM-based obfuscation including string encryption and control flow flattening.
    - **CodeBase obfuscation**:
        - Function name and string obfuscated from chars: [0-9a-zA-Z_] by 3 randomly selected algorithms: Mt19937, MinstdRand and ranlux48_base.
        - Shikata Ga Nai (SGN) encoding.
    - **Payload encoding (T1132)**:
        - UUID (Universally Unique Identifier)
        - XOR
        - MAC
        - IP4 format
        - base-64
        - base-45
        - base-58
        - Chacha20
        - RC4 (SystemFunction32/33)
        - AES
        - AES with divide and conquer to bypass logical path hijacking
        - DES (SystemFunction002)
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
    - **Metadata copied from window binary (T1036)**

- [ ] **Heuristic Evasion**: 
    - **Anti-Emulation (T1497)**: checks based on file system operation, process and network information and “offer you have to refuse” [15, 38]. A simple heuristic that if 2 or more checks are failed, execution will stop. 
    - **Junk API instructions (“no-op” calls, or mimicry attack)**: 5 benign API functions to vary the API call sequences 
    - **API Unhooking**:
        - 1. Read the syscall stub from the original ntdll and rewrite the loaded ntdll’s stub
        - 2. Custom Peruns’ Fart unhooking
        - 3. Halo’s gate (TartarusGate)
    - **Sifu Memory Guard**
        - New memory guard inspired by hardware breakpoints hooking techniques (Loader 48, 49, 51, 52, 57)
    - **Sleep obfuscation: Custom Ekko (CreateTimerQueueTimer) with arbitrary sleep time invoked at run time**
    - **Stack encryption sleep**: Local variables and shellcode were being stored on stack. This part of memory is available for scanning both in emulator pre-execution and post-execution. 
    - **PIC convertor (T1027.009, T1027.002, T1620)**:
        - The donut (The Wover)
        - PE2SH (hasherezade)
        - RC4 custom encrypted converter
        - Amber (by Ege Balcı)
        - Shoggoth (by frkngksl)
        - Stardust (by 5pider)
          
- [ ] **Behavioral Evasion**: 
    - **Various code execution and process injection loaders (T1055, T1106, T1027.007)**: A variety of loaders for different evasion scenarios
    - **Two LLVM-obfuscation compilers (T1027)**
    - **Output DLL/CPL (side-loading) (T1574.002, T1218.011/002)**
    - **Event tracing for windows (ETW) patching (hot patch NtTraceEvent with “xor rax, rax; ret”) (T1562.006)**
    - **Patchless ETW bypass:**
        - The patchless method can avoid detection on patching instructions.
        - EtwEventWrite and EtwEventWriteFull are wrappers call NtTraceEvent, which is a syscall. We can set up a Vectored Exception Handler (VEH) and configure a hardware breakpoint (HWBP) using RtlCaptureContext to capture the thread's context, then use NtContinue to update it. Inside the VEH handler, when NtTraceEvent is called, we can redirect RIP to the Ret instruction after the Syscall instruction, which is six instructions after the function start address. we also set Rax = 0, thereby bypassing the ETW event completely.
    - **API name spoofing via IAT, using CallObfuscator by d35ha**
    - **Parent PID Spoofing (T1134.004)**
    - **Process code injection and execution mitigation policy (M1038) (e.g. CFG, XFG, module tampering prevention, Structured Exception Handler Overwrite Protection (SEHOP), etc)**
    - **Post-execution self-deletion: output binary can be marked as self-delete upon execution (T1070.004)**
    - **Post-execution anti-forensic techniques: delete execution traces from various locations that do not require an admin privilege. For example:**
        - Modify arbitrary reg key last write time with NtSetInformationKey.
        - Delete AmCache and ShimCache
        - Copy $STANDARD_INFORMATION timestamp and zone identifier.
    - **New memory scanner evasion techniques:**
      - Conventional VEH memory guard
      - PG (page guard) --> VEH (vectored exception handler)
      - PG --> VEH --> VCH (vectored continued handler) stealth guard
      - Virtual table hooking execution guard
  -  **A new code execution and process injection primitive**
      - Threadless execution primitive 1 (Manual VEH to VCH execution)
      - Threadless execution primitive 2 (Threadless proxy call stub)


## Prerequisites

- Linux environment with Wine configured. Kali Linux or other Debian prefered. 
- CMake, Git, GCC, G++, MingW, LLVM, nasm and other build essentials installed.

## Installation

1. **Install required packages:**:

```console
git clone https://github.com/thomasxm/Boaz_beta/
cd Boaz_beta
```

```console
bash requirements.sh
```

2. **Cavets**:

It should be noted that SGN encoder sometimes can generate bad characters, use with caution. 
requirements.sh will install LLVM, which takes a while to complete. BOAZ can be run without the -llvm handle; however, it is not optimised without the latter.


## Docker Setup & Installation

BOAZ can also be used via Docker to avoid dependency and build issues.

### 1. Install Docker

If Docker is not already installed on your system:

```bash
sudo apt install docker-cli -y
sudo apt install docker.io -y
```

### 2. Pull the BOAZ Docker image

```bash
sudo docker pull mmttxx20/boaz-builder:latest
```

### 3. Verify the image has been pulled

```bash
sudo docker images | grep -in "boaz"
```

### 4. Run a Bash shell inside the container

```bash
sudo docker run --rm -it \
  --entrypoint /bin/bash \
  -v "$HOME:/host_home" \
  -v "$PWD:/boaz/output" \
  --shm-size=1024M \
  --name boaz_built \
  mmttxx20/boaz-builder
```

- `/host_home` maps your home directory inside the container.
- `-v "$PWD:/boaz/output"` mounts your current directory on the host to `/boaz/output` in the container.
- To confirm the host home path: `echo $HOME`

### 5. Run a test build with LLVM obfuscation and Notepad as input

```bash
python3 Boaz.py -h
```

```bash
python3 Boaz.py -f /host_home/Boaz_beta/notepad.exe -o ./output/boaz_output.exe -t donut -l 16 -e uuid -c akira
```

- `-t donut`: Use Donut as the position independent shellcode generator.
- `-l 16`: Use loader number 16.
- `-e uuid`: Encode the shellcode using UUID scheme.
- `-c akira`: Use Akira as the LLVM obfuscator and clang++ as the cross-compiler.

After the process completes and you exit the container, the output binary `boaz_output.exe` will be present in your current working directory on the host.


## Usage

Example usage:

```console
python3 Boaz.py -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid 
```

Use a built ELF executable in Linux environment:
```console
./Boaz -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c akira -e des -a 
```

Refer to the help command for more details on usage:

```console
python3 Boaz.py -h 
```

```console
./Boaz -h 
```

```bash
usage: Boaz.py [-h] [-f INPUT_FILE] [-o OUTPUT_FILE] [-divide] [-l LOADER] [-dll] [-cpl] [-sleep]
               [-a] [-cfg] [-etw] [-j] [-dream [DREAM]] [-u] [-g]
               [-t {donut,pe2sh,rc4,amber,shoggoth}] [-sd] [-sgn]
               [-e {uuid,xor,mac,ipv4,base45,base64,base58,aes,des,chacha,rc4,aes2,ascon}]
               [-c {mingw,pluto,akira}] [-mllvm MLLVM] [-obf] [-obf_api] [-w [SYSWHISPER]]
               [-entropy {1,2}] [-b [BINDER]] [-wm [WATERMARK]] [-d] [-af] [-icon]
               [-s [SIGN_CERTIFICATE]] [-dh]

Process loader and shellcode.

options:
  -h, --help            show this help message and exit
  -f, --input-file INPUT_FILE
                        Path to binary.exe
  -o, --output-file OUTPUT_FILE
                        Optional: Specify the output file path and name. If not provided, a random
                        file name will be used in the ./output directory.
  -divide               Divide flag (True or False)
  -l, --loader LOADER   Loader number (must be a non-negative integer)
  -dll                  Compile the output as a DLL instead of an executable, can be run with
                        rundll32.exe
  -cpl                  Compile the output as a CPL instead of an executable, can be run with
                        control.exe
  -sleep                Obfuscation Sleep flag with random sleep time (True or False)
  -a, --anti-emulation  Anti-emulation flag (True or False)
  -cfg, --control-flow-guard
                        Disable Control Flow Guard (CFG) for the loader template.
  -etw                  Enable ETW patching functionality
  -j, --junk-api        Insert junk API function call at a random location in the main function (5
                        API functions)
  -dream [DREAM]        Optional: Sleep with encrypted stacks for specified time in milliseconds.
                        Defaults to 1500ms if not provided.
  -u, --api-unhooking   Enable API unhooking functionality
  -g, --god-speed       Enable advanced unhooking technique Peruns Fart (God Speed)
  -t, --shellcode-type {donut,pe2sh,rc4,amber,shoggoth}
                        Shellcode generation tool: donut (default), pe2sh, rc4, amber or shoggoth
  -sd, --star_dust      Enable Stardust PIC generator, input should be .bin
  -sgn, --encode-sgn    Encode the generated shellcode using sgn tool.
  -e, --encoding {uuid,xor,mac,ipv4,base45,base64,base58,aes,des,chacha,rc4,aes2,ascon}
                        Encoding type: uuid, xor, mac, ip4, base45, base64, base58, AES, DES,
                        chacha, RC4 and aes2. aes2 is a devide and conquer AES decryption to
                        bypass logical path hijacking. Other encoders are under development.
  -c, --compiler {mingw,pluto,akira}
                        Compiler choice: mingw (default), pluto, or akira
  -mllvm MLLVM          LLVM passes for Pluto or Akira compiler
  -obf, --obfuscate     Enable obfuscation of codebase (source code)
  -obf_api, --obfuscate-api
                        Enable obfuscation of API calls in ntdll and kernel32.
  -w, --syswhisper [SYSWHISPER]
                        Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps
                        (default), 2 for compiling with MingW and NASM.
  -entropy {1,2}        Entropy level for post-processing the output binary. 1 for null_byte.py, 2
                        for pokemon.py
  -b, --binder [BINDER]
                        Optional: Path to a utility for binding. Defaults to binder/calc.exe if
                        not provided.
  -wm, --watermark [WATERMARK]
                        Add watermark to the binary (0 for False, 1 or no value for True)
  -d, --self-deletion   Enable self-deletion of the binary after execution
  -af, --anti-forensic  Enable anti-forensic functions to clean the execution traces.
  -icon                 Enable icon for the output binary.
  -s, --sign-certificate [SIGN_CERTIFICATE]
                        Optional: Sign the output binary and copy metadata from another binary to
                        your output. If a website or filepath is provided, use it. Defaults to
                        interactive mode if no argument is provided.
  -dh, --detect-hooks   Compile a small tool called check_hook.exe for detecting inline/IAT/EAT
                        hooks. This tool can detect both native API and export function hooks.

    loader modules:
    1.  Proxy syscall --> Custom call Stack + indirect syscall with threadless execution (local injection)
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
    16. Classic userland API calls (VirtualAllcEx --> WriteProcessMemory --> CreateRemoteThread)
    17. Sifu SysCall with Divide and Conquer
    18. Classic userland API calls with WriteProcessMemoryAPC
    19. DLL overloading 
    20. Stealth new Injection (WriteProcessMemoryAPC + DLL overloading)
    21.
    22. Advanced indirect custom call stack syscall, using VEH-->VCH logic and manually remove handlers from the list.
    23.
    24. Classic native API 
    25.
    26. Stealth new Injection (3 WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing)
    27. Stealth new Injection (3 Custom WriteProcessMemoryAPC variants + custom DLL overloading + custom dynamic API-hashing + Halo's gate patching)
    28. Halo's gate patching syscall injection + Custom write code to Process Memory by either MAC or UUID convertor + invisible dynamic loading (no loadModuleHandle, loadLibrary, GetProcessAddress)
    29. Classic indirect syscall
    30. Classic direct syscall
    31. MAC address injection
    32. Stealth new injection (Advanced)
    33. Indirect Syscall + Halo gate + Custom Call Stack
    34. EDR syscall no.1 + Halo gate + EDR Call Stack 1
    36. EDR syscall no.2 + Halo gate + EDR Call Stack 2 
    37. Stealth new loader (Advanced, evade memory scan)
    38. A novel PI with APC write method and phantom DLL overloading execution (CreateThread pointed to a memory address of UNMODIFIED DLL.)
    39. Custom Stack PI (remote) with threadless execution
    40. Custom Stack PI (remote) Threadless DLL Notification Execution
    41. Custom Stack PI (remote) with Decoy code execution
    48. Stealth new loader + Syscall breakpoints handler with memory guard AKA Sifu breakpoint handler (hook on NtResumeThread)
    49. Stealth new loader + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on NtCreateThreadEx, with Decoy address, PAGE_NOACCESS and XOR)
    51. Stealth new loader + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on ntdll!RtlUserThreadStart and kernel32!BaseThreadInitThunk, with Decoy address, PAGE_NOACCESS and XOR)
    52. RoP gadgets as the trampoline code to execute the magic code. 
    53.
    54. Stealth new loader + Exception handler + Syscall breakpoints handler with memory guard evasion AKA Sifu breakpoint handler (hook on ntdll!RtlUserThreadStart and kernel32!BaseThreadInitThunk, with Decoy address, PAGE_NOACCESS and XOR)
    56. This is a fork of Loader 37 with additional features. If -ldr flag is not provided, loader will add module (contains the shellcode) to the PEB module lists manually using code from Dark library. 
    57. A fork of loader 51 with XOR replaced with RC4 encryption offered by SystemFunction032/033.
    58. VEH add hanlder. Add ROP Trampoliine to the kernel32!BaseThreadInitThunk for additional complexity to analyse. 
    59. SEH add hanlder. Add ROP Trampoliine to the kernel32!BaseThreadInitThunk for additional complexity to analyse.
    60. Use Page guard to trigger first exception to set debug registers without using NtGetContextThread --> NtSetContextThread
    61. Use Page guard to trigger first exception to set debug registers without using NtGetContextThread --> NtSetContextThread + Use VEH to set up breakpoints Dr0~Dr3, Dr7. Then use VCH to execute the code. So, no registers and stack pointer and instruction pointer changed in VEH. 
    62. New loader in progress.
    63. Remote version of custom module loading loader 37. Remote module injection.
    64.
    65. Advanced VMT hooking with custom module loader 37. 
    66. A fork of L-65, with additional features such as optional PPID spoofing, multiple shellcode and DLL injection mitigation policies enabled on remote process.
    67. A fork of L-65, with strange trampoline code to execute the magic code in both local and remote process. 
    68. New loader in progress.
    69. A fork of L-61, manually set VEH and VCH and clean ups by remove the CrossProcessFlags from TEB->PEB.
    ...
    73. VT Pointer threadless process injection, can be invoked with decoy address to any function or triggered by injected application (e.g. explorer). Memory guard available with RC4 entryption and PAGE_NOACCESS.
    74. VT Pointer threadless process injection, can be invoked with decoy address to any function or triggered by injected application (e.g. explorer). Memory guard available with RC4 entryption and PAGE_NOACCESS. The VirtualProtect is being called within pretext.

    75. Dotnet JIT threadless process injection. 
    76. Module List PEB Entrypoint threadless process injection. 
    77. VT Pointer threadless process injection. Use RtlCreateHeap instead of BaseThreadInitThunk virtual table pointer.


```


## Evasion Modules

![Evasion101 (1)](https://github.com/thomasxm/Boaz_beta/assets/44269971/e5fd38a1-fd95-47f9-a7b0-e85710596902)

![layered](https://github.com/user-attachments/assets/b42a7ab9-7a14-4b16-8538-df20a334e234)


## Process Injection Loaders

 
<img width="1374" height="392" alt="Process_injection_101 1" src="https://github.com/user-attachments/assets/e76d7a5e-314a-45e1-89e3-a8368ff52bc5" />


## New Proxy Syscall Stubs Execution

<img width="1249" height="568" alt="Screenshot 2025-08-17 at 18 24 50" src="https://github.com/user-attachments/assets/de8ee6a8-3a85-4400-97bb-9b496cb59a24" />


<img width="1424" height="583" alt="Screenshot 2025-08-17 at 18 24 58" src="https://github.com/user-attachments/assets/9247a336-543a-409d-8b4d-d24e059c789c" />

### Defcon Slides: 

<img width="1396" height="851" alt="Screenshot 2025-08-17 at 18 22 33" src="https://github.com/user-attachments/assets/83c5db9d-ed29-4b41-a976-45d941b5521f" />



**Click to download:** [DEFCON-33-2.pdf](https://github.com/user-attachments/files/21823689/DEFCON-33-2.pdf)


### x86-64 Calling Convention

- First four arguments of a callee function: `Rcx`, `Rdx`, `R8`, and `R9`.
- Additional arguments stored on the stack starting from `(Rsp + 0x28)`.



## Example:

Boaz evasion wrapped Mimikatz.exe x64 release. The detection rate for wrapped Mimikatz is zero on Jotti: 

<img width="1197" alt="Screenshot 2024-02-28 at 14 46 17" src="https://github.com/user-attachments/assets/312fdffe-7024-4e21-8830-07bcea3004c9">

**Figure: Jotti scan results of boaz_mimi**

![Screenshot 2025-03-09 at 21 22 36](https://github.com/user-attachments/assets/88d5d56a-c6cb-4cd4-ab7a-6347674c90a6)
**Figure: Kaspersky EDR versus Mimikatz packed by Boaz**

![Screenshot 2025-03-08 at 19 05 30](https://github.com/user-attachments/assets/9247374b-2148-4aaf-80a6-1bc8fdac04f7)
**Figure: Kaspersky EDR versus Meterpreter reverse shell packed by Boaz**

![Screenshot 2025-03-08 at 18 31 38](https://github.com/user-attachments/assets/ce9844c6-16fa-4b9e-bd80-5defd755d9a8)
**Figure: Sophos EDR versus Mimikatz packed by Boaz**

## Roadmap

- **Spack**: Use Spack to manage packages
- **Add a GUI for users**: Web UI or Python UI.
- **Loaders**: Implement more loader templates (process injection and code execution methods) with a divide and conquer option available.
- **Rust**: Loader should be language agnostic. Rust loader would be a good alternative. 
- **COFF loaders**: Implement COFF loader suppport.
- **Obfuscation**: Enhancing obfuscation methods and integrating new LLVM passes. 
- **Shellcode Generation**: Expand to include more techniques, e.g., PIC generated from arbitrary command, and offer users the choice of shellcode generation technique.
- **PIC Chain Reactions**: ....
- **Sleep Techniques**: Implementing additional anti-emulation and sleep techniques, like encrypting heap and stack while sleeping during pre-shellcode-execution phase. 
- **Syscall**: Improving Syswhisper2 integration for signature reduction. (e.g. on detecting virtual machine introspection and dynamic binary instrumentation)
- **Compilation**: Integrate additional compiler options like Cosmopolitan compiler.
- **File format**: Extend more file format supports, so that user can execute sample with signed utilities and more options.
- **modularised modules**: Although Boaz has all its implementations modularised in concept, it is not 'actually' modularised in its current beta version. Owing to the fact that this tool is a side project for my dissertation, I need to find time to separate each function into an actual module and ensure that each is presented with a template so that users can add a new technique and integrate it into the main program without the need to change the main program or other modules.
- **Templates**: using YAML and JSON files to configure and modularise the program. 

## Contributing

We welcome contributions to improve the Boaz Evasion Tool. Please review `CONTRIBUTING.md` for guidelines on how to submit contributions. 


We welcome submissions to [pull requests](https://github.com/thomasxm/Boaz_beta/pulls) and [issues](https://github.com/thomasxm/Boaz_beta/issues).


This is in development, please feel free to reach out to me @thomasmeeeee on X for any suggestions! 

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

A special thanks to the researchers and developers whose work has inspired, contributed to, and made this tool possible. 
All credit goes to the original authors of the techniques and tools: 

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
* [Darkmoon](https://github.com/ASCIT31/Dark-Moon) - an open source (GPL-3.0) autonomous AI penetration testing platform for web, API, Active Directory and Kubernetes.
* [Mangle](https://github.com/optiv/Mangle)
* [CallObfuscator](https://github.com/d35ha/CallObfuscator)
* [Stardust](https://github.com/Cracked5pider/Stardust/tree/main)
* [Carbon Copy](https://github.com/paranoidninja/CarbonCopy)
* [Shikata ga nai](https://github.com/EgeBalci/sgn)
* [x86matthew](https://www.x86matthew.com/)
* [DarkLoadLibrary](https://github.com/bats3c/DarkLoadLibrary)
* [Red Team Notes](https://www.ired.team/)

And many more blogs and articles. Please feel free to add more...

## Contact

For any queries or contributions, please contact the repository owner.











<img width="1024" height="1024" alt="output" src="https://github.com/user-attachments/assets/3ba46a38-c2ba-4465-bec9-d2bc14bdfda7" />




































