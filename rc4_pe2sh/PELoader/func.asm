public getCurrAddr

_TEXT	SEGMENT
getCurrAddr PROC
		call f;
		f:
		pop rax;
		ret;
getCurrAddr ENDP

_TEXT ENDS

END