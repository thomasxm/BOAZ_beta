extern _Entry

global _Start
global _GetRIP

section .text$A
    _Start:
        push	ebp
        mov	ebp, esp

        call	_Entry

        mov	esp, ebp
        pop	ebp
    ret

section .text$F
    _GetRIP:
        call    _retptr

    _retptr:
        pop	eax
        sub	eax, 5
    ret
