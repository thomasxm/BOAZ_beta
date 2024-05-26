.intel_syntax noprefix
.data
.align 4
stubReturn:     .long 0
returnAddress:  .long 0
espBookmark:    .long 0
syscallNumber:  .long 0
syscallAddress: .long 0

.text
.global _NtAllocateVirtualMemory
.global _NtWriteVirtualMemory
.global _NtCreateThreadEx
.global _NtProtectVirtualMemory

.global _WhisperMain

_WhisperMain:
    pop eax                                  
    mov dword ptr [stubReturn], eax         # Save the return address to the stub
    push esp
    pop eax
    add eax, 0x04
    push [eax]
    pop returnAddress                       # Save original return address
    add eax, 0x04
    push eax
    pop espBookmark                         # Save original ESP
    call _SW2_GetSyscallNumber              # Resolve function hash into syscall number
    add esp, 4                              # Restore ESP
    mov dword ptr [syscallNumber], eax      # Save the syscall number
    xor eax, eax
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    je _x86
    inc eax                                 # Inc EAX to 1 for Wow64
_x86:
    push eax                                # Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+0x04]
    call _SW2_GetRandomSyscallAddress       # Get a random 0x02E address
    mov dword ptr [syscallAddress], eax     # Save the address
    mov esp, dword ptr [espBookmark]        # Restore ESP
    mov eax, dword ptr [syscallNumber]      # Restore the syscall number
    call dword ptr syscallAddress           # Call the random syscall location
    mov esp, dword ptr [espBookmark]        # Restore ESP
    push dword ptr [returnAddress]          # Restore the return address
    ret

_NtAllocateVirtualMemory:
    push 0x0B9D610F
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x7BEB777F
    call _WhisperMain

_NtCreateThreadEx:
    push 0x05285BEF
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0xC19A0ACA
    call _WhisperMain

