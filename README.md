<img width="423" alt="loglo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/a5427ccc-e2ed-4cc3-ab81-084de691b23f">





<img width="352" alt="small_logo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/99abcf82-7084-47e5-a993-2a712b4ca664">

# BOAZ Evasion Tool (for educational purpose)



![c](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white) ![python](https://img.shields.io/badge/Python-00599C?style=for-the-badge&logo=python&logoColor=red) ![assembly](https://img.shields.io/badge/ASSEMBLY-ED8B00?style=for-the-badge&logo=Assembly&logoColor=white) ![windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)


[Features](#Features) | [Installation](#installation) | [Usage](#Usage) | [Evasion Module](#evasion-modules)

## Description

BOAZ (Bypass, Obfuscate, Adapt, Zero-Trust) evasion was inspired by the concept of multi-layered approach which is the evasive version of defence-in-depth ([Swinnen & Mesbahi, 2014](https://www.blackhat.com/docs/us-14/materials/us-14-Mesbahi-One-Packer-To-Rule-Them-All.pdf)). It was developed to aid the security testing and antivirus defence evaluation. 

BOAZ aims to bypass the before and during execution phases that span signature, heuristic and behavioural-based detection methods. BOAZ supports x64 binary (PE) or raw playload (.bin) as input. It has been tested on separated Window-11 VMs with 14 Desktop AVs. The design of BOAZ evasion is modularised so users can add their own toolset, encoding or new techniques to the framework at will. It is written in both C and C++, and uses Python as the main program to link all modules together.

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
        - RC4 encrypted convertor
        - Amber (by Ege Balcı)
        - Shoggoth (by frkngksl)
          
- [ ] **Behavioral Evasion**: 
    - **Various code execution and process injection loaders (T1055, T1106, T1027.007)**: A variety of loaders for different evasion scenarios
    - **Two LLVM-obfuscation compilers (T1027)**
    - **Output DLL/CPL (side-loading) (T1574.002, T1218.011/002)**
    - **ETW-patching (patch ETW stub with “xor rax, rax; ret”) (T1562.006)**
    - **API name spoofing via IAT, using CallObfuscator by d35ha**

    

## Prerequisites

- Linux environment with Wine configured. Kali Linux or other Debian prefered. 
- CMake, Git, GCC, G++, MingW, LLVM and other build essentials installed.

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

## Usage

Example usage:

```console
python3 Boaz.py -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid -g
```

Use a built ELF executable in Linux environment:
```console
./Boaz -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid -g
```

Refer to the help command for more details on usage:

```console
python3 Boaz.py -h 
```

```console
./Boaz -h 
```

```bash
usage: Boaz [-h] -f INPUT_FILE [-o OUTPUT_FILE] [-divide] [-l LOADER] [-dll] [-cpl] [-sleep]
            [-a] [-etw] [-j] [-dream [DREAM]] [-u] [-g] [-t {donut,pe2sh,rc4,amber,shoggoth}]
            [-sd] [-sgn] [-e {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}]
            [-c {mingw,pluto,akira}] [-mllvm MLLVM] [-obf] [-obf_api] [-w [SYSWHISPER]]
            [-entropy {1,2}] [-b [BINDER]] [-wm [WATERMARK]] [-s [SIGN_CERTIFICATE]]

Process loader and shellcode.

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input-file INPUT_FILE
                        Path to binary.exe
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Optional: Specify the output file path and name. If not provided, a
                        random file name will be used in the ./output directory.
  -divide               Divide flag (True or False)
  -l LOADER, --loader LOADER
                        Loader number (must be a non-negative integer)
  -dll                  Compile the output as a DLL instead of an executable, can be run with
                        rundll32.exe
  -cpl                  Compile the output as a CPL instead of an executable, can be run with
                        control.exe
  -sleep                Obfuscation Sleep flag with random sleep time (True or False)
  -a, --anti-emulation  Anti-emulation flag (True or False)
  -etw                  Enable ETW patching functionality
  -j, --junk-api        Insert junk API function call at a random location in the main function
                        (5 API functions)
  -dream [DREAM]        Optional: Sleep with encrypted stacks for specified time in
                        milliseconds. Defaults to 1500ms if not provided.
  -u, --api-unhooking   Enable API unhooking functionality
  -g, --god-speed       Enable advanced unhooking technique Peruns Fart (God Speed)
  -t {donut,pe2sh,rc4,amber,shoggoth}, --shellcode-type {donut,pe2sh,rc4,amber,shoggoth}
                        Shellcode generation tool: donut (default), pe2sh, rc4, amber or
                        shoggoth
  -sd, --star_dust      Enable Stardust PIC generator, input should be .bin
  -sgn, --encode-sgn    Encode the generated shellcode using sgn tool.
  -e {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}, --encoding {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}
                        Encoding type: uuid, xor, mac, ip4, base64, base58 AES and aes2. aes2 is
                        a devide and conquer AES decryption to bypass logical path hijacking.
                        Other encoders are under development.
  -c {mingw,pluto,akira}, --compiler {mingw,pluto,akira}
                        Compiler choice: mingw (default), pluto, or akira
  -mllvm MLLVM          LLVM passes for Pluto or Akira compiler
  -obf, --obfuscate     Enable obfuscation of codebase (source code)
  -obf_api, --obfuscate-api
                        Enable obfuscation of API calls in ntdll and kernel32.
  -w [SYSWHISPER], --syswhisper [SYSWHISPER]
                        Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps
                        (default), 2 for compiling with MingW and NASM.
  -entropy {1,2}        Entropy level for post-processing the output binary. 1 for null_byte.py,
                        2 for pokemon.py
  -b [BINDER], --binder [BINDER]
                        Optional: Path to a utility for binding. Defaults to binder/calc.exe if
                        not provided.
  -wm [WATERMARK], --watermark [WATERMARK]
                        Add watermark to the binary (0 for False, 1 or no value for True)
  -s [SIGN_CERTIFICATE], --sign-certificate [SIGN_CERTIFICATE]
                        Optional: Sign the output binary and copy metadata from another binary
                        to your output. If a website or filepath is provided, use it. Defaults
                        to interactive mode if no argument is provided.

```


## Evasion Modules

![Evasion101 (1)](https://github.com/thomasxm/Boaz_beta/assets/44269971/e5fd38a1-fd95-47f9-a7b0-e85710596902)

![layered](https://github.com/user-attachments/assets/b42a7ab9-7a14-4b16-8538-df20a334e234)


## Process Injection Loaders

![Process_injection_101](https://github.com/thomasxm/BOAZ/assets/44269971/232e635b-b692-4010-a65d-e5ceb39c1e5e)


## New Memory Guard

<img width="400" alt="Sifu" src="https://github.com/user-attachments/assets/935ee41b-02cd-46dc-8d29-2fd67d365b7f">

### Introduction

Due to the prevalence of Kernel PatchGuard, System Service Descriptor Table (SSDT) hooking has become less popular among AV companies. Userland hooks and kernel callback inspection are the two main methods adopted by contemporary AVs.

### Userland Hooks

- **Description**:
  - Replace a syscall or API instruction opcode with a JMP-like instruction set to a trampoline code or memory page owned by the AV’s DLL.
  - Inspect the passed arguments and associated memory for suspicious byte patterns.
  - If non-suspicious bytes or a benign call stack are found, execute the replaced instructions and JMP back to the syscall location.
  - If suspicious bytes are found, terminate the process based on the heuristic score engine.
  - Trigger memory inspection via a kernel callback notification for process and thread creation, such as `PsSetCreateThreadNotifyRoutine`.

- **Various Hooking Methods**:
  - **IAT, EAT hooking**
  - **Virtual Table hooking**
  - **Inline hooking**
  - **Detour**
  - **Kernel mode hook**
  - **Software breakpoints** (page guard, error exception)
  - **Hardware breakpoints**

Marcus proposed using hardware breakpoints to set up the function arguments at the desired instructions. In their example, they set up debug registers Dr0 and Dr1 at syscall and return instructions to evade Sophos Intercept X, which was known to check the Rcx register’s value in case NtSetContextThread is called. Hardware breakpoints offer flexibility in setting breakpoints at arbitrary locations while having a single point of detection. Other method to trigger the exception available are x86matthew's stealth hook.


### New Memory Guard Family: 

The aim is to make the shellcode "non-exist" to the AV as long as possible except when it is executed in a thread.

I intend to name this memory guard “Sifu memory guard” to pay tribute to the researchers who have shared their work with the community and passed their knowledge on.

#### Implementation

- **Tested APIs**:
  - `NtCreateThreadEx`
  - `RtlUserThreadStart` -> `BaseThreadInitThunk`
  - `NtResumeThread`

### NtResumeThread Technique

1. **CreateThread** called at Decoy entry point and suspended.
2. Call `NtResumeThread`.
3. **Dr0** at syscall instruction.
4. Change start address of thread (`lpStartAddress`) at `Rsp+0x28` from Decoy entry point to Real entry point.
5. Encode the shellcode at Real entry point.
6. Change memory page to `PAGE_NOACCESS`.
7. **Dr1** at Ret instruction.
8. Decode the shellcode at Real entry point.
9. Change memory to `PAGE_EXECUTE_READ`.
10. Change start address of thread (`lpStartAddress`) at `Rsp+0x28` from Real entry point to Decoy entry point.

### NtCreateThreadEx Technique

1. **NtCreateThreadEx** called at Decoy entry point and suspended.
2. Call `ResumeThread`.
3. **Dr0** at syscall instruction.
4. Change start address of thread (`lpStartAddress`) at `Rsp+0x28` from Decoy entry point to Real entry point.
5. Change `Rcx` -> real thread handle.
6. Encode the shellcode at Real entry point.
7. Change memory page to `PAGE_NOACCESS`.
8. **Dr1** at Ret instruction.
9. Decode the shellcode at Real entry point.
10. Change memory to `PAGE_EXECUTE_READ`.
11. Change start address of thread (`lpStartAddress`) at `Rsp+0x28` from Real entry point to Decoy entry point.
12. Change `Rax` to arbitrary values, e.g., `0xC0000156 == STATUS_TOO_MANY_SECRETS`.

### x64 Calling Convention

- First four arguments of a callee function: `Rcx`, `Rdx`, `R8`, and `R9`.
- Additional arguments stored on the stack starting from `(Rsp + 0x28)`.

### Thread Creation API Call Sequence

1. `kernel32!CreateThread` / `CreateRemoteThread`
2. `ntdll!NtCreateThreadEx` / `ZwCreateThreadEX`
3. `ntdll!LdrInitializeThunk`
4. `ntdll!NtContinue`
5. `ntdll!RtlUserThreadStart`
6. `kernel32!BaseThreadInitThunk`

### Resume Thread API Call Sequence
1. `kernel32!ResumeThread`
2. `kernelbase!ResumeThread`
3. `ntdll!NtResumeThread`
4. `ntdll!NtContinue`
5. `ntdll!RtlUserThreadStart`
6. `kernel32!BaseThreadInitThunk`


### AV Inspection Points

- Some AVs inspect `NtSetContextThread`,  `NtCreateThreadEx`, `CreateThread` and `RtlUserThreadStart`.

### Memory Guard Steps

1. Set hardware breakpoints on two debug registers from `Dr0` to `Dr3` at `ntdll!RtlUserThreadStart` and `Kernel32!BaseThreadInitThunk`.
2. Set up an exceptional handler triggered by a call to `NtCreateThreadEx` with a decoy start address (e.g., 0X12345).
3. Encode the real start address, changing its memory protection to `PAGE_NOACCESS` when `ntdll!RtlUserThreadStart` has `Rcx` pointed to decoy start address.
4. Decode the real start address, changing its memory protection to `PAGE_EXECUTE_READ` when `Kernel32!BaseThreadInitThunk` has `Rdx` pointing to the decoy start address. Then, change `Rdx` to the real start address and continue execution.
5. Change the shellcode memory to inaccessible before `RtlExitUserThread`.
6. Return any NTSTATUS values we prefer to the calling function, for example, `0xC0000157 STATUS_SECRET_TOO_LONG`.

### Additional Steps for Further Inspection

1. Write a function to search for op codes `jmp r11` from only the memory of type `MEM_IMAGE` with `PAGE_EXECUTE_READ` permission and store the Return-oriented programming (RoP) gadget locally.
2. Break at `kernel32!BaseThreadInitThunk`.
3. Change `Rdx` -> RoP gadget (trampoline code) (avoid using Rip register as it is commonly inspected).
4. Change `R11` -> Real start address.

### Choice of set exception hanlders:
- Vectored Exception Handlers (VEH, AddVectoredExceptionHandler)
- SetUnhandledExceptionFilter
- Structured Exception Handling (SEH, __try, __except, and __finally)

### Detection Point for Blue Team

- Verify the initial `lpStartAddress` at the beginning of the `CreateThread` function is equal to the `Rdx` value at the end of `BaseThreadInitThunk`.
- The order of legitimate DLL being loaded may not follow the “usual” order in InLoadOrderModuleList.
- The use of hardware breakpoints can be easily detected, however, there are various ways to replace hardware breakpoints. 


---

This technique presents a **Time-of-Check to Time-of-Use (TOCTTOU) problem** that can be exploited to protect shellcode from AV and EDR memory inspection.


![Sifu_flow_with_background](https://github.com/user-attachments/assets/adaeb9b3-7c28-47fb-a590-096c9a125568)



## Example:

Boaz evasion wrapped Mimikatz.exe x64 release. The detection rate for wrapped Mimikatz is zero on Jotti: 

<img width="1197" alt="Screenshot 2024-02-28 at 14 46 17" src="https://github.com/user-attachments/assets/312fdffe-7024-4e21-8830-07bcea3004c9">



## Roadmap

- **Docker**: Make it available with Docker without installation
- **Add a GUI for users**: Web UI or Python UI.
- **Loaders**: Implement more loader templates (process injection and code execution methods) with a divide and conquer option available.
- **COFF loaders**: Implement COFF loader suppport.
- **RISC-V VM** Implement new loader using RISC-V VM concept. 
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










![Boaz_logo3](https://github.com/thomasxm/Boaz_beta/assets/44269971/0118a0cf-9cd9-48df-8f20-37a059e4bf6a)





































