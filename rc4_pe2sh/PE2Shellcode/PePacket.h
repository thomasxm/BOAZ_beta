#pragma once

#include <Windows.h>
#include <string>
#include <iostream>
#include <time.h>
/*
shellcode struct

			+------------+
			|   PE Load  |
			+------------+
			|    Head    |   <--- sign + struct CustomHead + rc4key
			+------------+   
			|            |
			|    exe     |
			|            |
			+------------+

*/
#pragma pack(push, 1)
#ifdef _WIN64
typedef ULONG64 QWORD;
typedef QWORD DA;
typedef struct CustomHead
{
	QWORD size;//PE size
	QWORD offsetSection;
	QWORD numberOfSection;
	QWORD offsetRelocation;
	QWORD imageAddr;
	QWORD offsetImportTable;
	QWORD entryPoint;
	QWORD flag1;
	QWORD compressSize;
	QWORD flag2;
	QWORD rc4Size;
}*pCustomHead;
#else
typedef DWORD DA;
typedef struct CustomHead
{
	DWORD size;//PE size
	DWORD offsetSection;
	DWORD numberOfSection;
	DWORD offsetRelocation;
	DWORD imageAddr;
	DWORD offsetImportTable;
	DWORD entryPoint;
	DWORD flag1;
	DWORD compressSize;
	DWORD flag2;
	DWORD rc4Size;
}*pCustomHead;
#endif // _WIN64
#pragma pack(pop)

#define SIGN_SIZE 8
#define RC4_KEY_SIZE 16

class CPePacket
{
public:
	CPePacket();
	~CPePacket();


	int ParsePara(int argc, wchar_t ** argv);

	BOOL IsExeFile();

	int ReadFileContent();

	int CreateBinFile();
	
	int PacthCustomHead();

	int GetCustomHead();

	int GenerateShellCode();

	int ProcessData();

	int GetResourceFile();

private:
	wchar_t *srcExePath;
	wchar_t *targetBinPath;

	BOOL rc4Flag;
	BOOL cmpFlag;

	char * head;
	int headSize = SIGN_SIZE + RC4_KEY_SIZE + sizeof(CustomHead);
	char * data;
	int dataSize;
	char * shellcode;
	int shellSize;
	unsigned char rc4Key[RC4_KEY_SIZE];
	CustomHead customHead;
};
