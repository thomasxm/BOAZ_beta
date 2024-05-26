[SECTION .data]
currentHash:    dd  0
returnAddress:  dq  0
syscallNumber:  dd  0
syscallAddress: dq  0

[SECTION .text]

BITS 64
DEFAULT REL

global NtAllocateVirtualMemory
global NtWriteVirtualMemory
global NtCreateThreadEx
global NtProtectVirtualMemory

global WhisperMain
extern SW2_GetSyscallNumber
extern SW2_GetRandomSyscallAddress
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx                   ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    mov dword [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    call SW2_GetRandomSyscallAddress    ; Get a random syscall address
    mov qword [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    mov eax, dword [syscallNumber]      ; Restore the syscall value
    add rsp, 28h
    mov rcx, [rsp+ 8]                   ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    pop qword [returnAddress]           ; Save the original return address
    call qword [syscallAddress]         ; Issue syscall
    push qword [returnAddress]          ; Restore the original return address
    ret

NtAllocateVirtualMemory:
    mov dword [currentHash], 00B9D610Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 07BEB777Fh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 005285BEFh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtProtectVirtualMemory:
    mov dword [currentHash], 0C19A0ACAh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

