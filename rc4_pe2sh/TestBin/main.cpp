#include <Windows.h>
#include <iostream>

int wmain(int argc, char **argv)
{

#ifdef _WIN64
	HANDLE hFile = CreateFileA("test_x64.bin", GENERIC_READ, 0, 0, OPEN_EXISTING, NULL, NULL);
#else
	HANDLE hFile = CreateFileA("test_x86.bin", GENERIC_READ, 0, 0, OPEN_EXISTING, NULL, NULL);
#endif // _WIN64


	DWORD fileSize = GetFileSize(hFile, NULL);

	void * base = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	DWORD dw;
	ReadFile(hFile, base, fileSize, &dw, NULL);

	((void(*)(void))base)();

	return 0;
}