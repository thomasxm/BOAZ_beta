MEMORY
{
  CODE : ORIGIN = 0x00400000, LENGTH = 64M
}

SECTIONS
{
  .text : 
  {
    KEEP(*(.text$A))
    KEEP(*(.text$B))
    KEEP(*(.text$C))
    KEEP(*(.text$D))
    KEEP(*(.text$E))
    KEEP(*(.rdata*))
    KEEP(*(.text$F))
    KEEP(*(.text))
  } > CODE

  .idata :
  {
    KEEP(*(.idata))
  } > CODE
}
