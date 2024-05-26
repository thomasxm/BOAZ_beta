.intel_syntax noprefix

.text
.global _NtAllocateVirtualMemory
.global _NtWriteVirtualMemory
.global _NtCreateThreadEx
.global _NtProtectVirtualMemory

.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
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

