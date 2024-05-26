extern Entry

global Start
global GetRIP

section .text
    Start:
        push    rbp
        mov     rbp, rsp

        call    Entry

        mov     rsp, rbp
        pop     rbp
        ret

section .text
    GetRIP:
        call    retptr

    retptr:
        pop     rax
        sub     rax, 5
        ret
