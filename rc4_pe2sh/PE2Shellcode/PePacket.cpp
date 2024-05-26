#include "PePacket.h"
#include "ProccessData.h"
#include "resource.h"
CPePacket::CPePacket()
{
	rc4Flag = FALSE;
	cmpFlag = FALSE;
	data = NULL;
	head = NULL;
	shellcode = NULL;
	dataSize = 0;
}
CPePacket::~CPePacket()
{
	if (data != NULL)
		delete data;
	data = NULL;

	if (head != NULL)
		delete head;
	head = NULL;

	if (shellcode != NULL)
		delete shellcode;
	shellcode = NULL;

	dataSize = 0;
	headSize = 0;
	shellSize = 0;
}


int CPePacket::ParsePara(int argc, wchar_t ** argv)
{
	if (argc <= 2)
	{
		printf("Used : PE2Shellcode.exe <path of PE>[output path] [-?]\n");
		printf("[-r] Rc4 encrypt\n");
		printf("[-c] Compress PE file\n");
		return 1;
	}

	srcExePath = argv[1];
	targetBinPath = argv[2];

	if (argc > 2)
	{
		for (int i = 3; i < argc; i++)
		{
			if (wcscmp(L"-r", argv[i]) == 0 && wcslen(argv[i]) == 2)
				rc4Flag = true;

			else if (wcscmp(L"-c", argv[i]) == 0 && wcslen(argv[i]) == 2)
				cmpFlag = true;
		}
	}

	return 0;
}

BOOL CPePacket::IsExeFile()
{
#ifdef _WIN64
	int bit = 64;
#else
	int bit = 32;
#endif


	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)data;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(data + pDos->e_lfanew);

	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[!] The file is not PE file.\n");
		return 1;
	}
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[!] The file is not PE file.\n");
		return 1;
	}

	if ((pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		printf("[!] DLL file is not supported.\n");
		return 1;
	}

	DWORD offsetDonet = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
	if (offsetDonet)
	{
		printf("[!] .NET applications are not supported.\n");
		return 1;
	}

	if (pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && bit == 32)
	{
		return 0;
	}
	else if ((pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
		pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) && bit == 64)
	{
		return 0;
	}

	printf("[!] Bits of PE file is not match.\n");
	return 1;
}

int CPePacket::ReadFileContent()
{

	char buffer[1024];
	DWORD filesize;
	DWORD dwReadBytes;
	int Result = 0;


	HANDLE hFile = INVALID_HANDLE_VALUE;
	do
	{
		hFile = CreateFileW(srcExePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			Result = GetLastError();
			printf("[-] Open src file failed.ErrorCode:%d\n", Result);
			break;
		}
		filesize = GetFileSize(hFile, NULL);
		data = new char[filesize];
		char *p = data;
		while (1)
		{
			if (!ReadFile(hFile, buffer, 1024, &dwReadBytes, NULL))
			{
				Result = GetLastError();
				printf("[-] ReadFile failed.ErrorCode:%d\n", Result);
				break;
			}
			if (dwReadBytes == 0)
				break;
			memcpy(p, buffer, dwReadBytes);
			p += dwReadBytes;
			dataSize += dwReadBytes;
		}
	} while (FALSE);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return Result;
}

int CPePacket::CreateBinFile()
{

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwWriteBytes;
	int Result = 0;
	do
	{
		hFile = CreateFileW(targetBinPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			Result = GetLastError();
			printf("[-] Create bin file failed. ErrorCode:%d\n", Result);
			break;
		}
		if (!WriteFile(hFile, shellcode, shellSize, &dwWriteBytes, NULL) ||
			!WriteFile(hFile, head, headSize, &dwWriteBytes, NULL) ||
			!WriteFile(hFile, data, dataSize, &dwWriteBytes, NULL)
			)
		{
			Result = GetLastError();
			printf("[-] Write bin file failed. ErrorCode:%d\n", Result);
			break;
		}

	} while (FALSE);
	

	if(hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return Result;
}


int CPePacket::GetCustomHead()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)data;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(data + pDos->e_lfanew);

	customHead.size = dataSize;
	customHead.numberOfSection = pNt->FileHeader.NumberOfSections;
	customHead.entryPoint = pNt->OptionalHeader.AddressOfEntryPoint;
	customHead.offsetImportTable = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	customHead.offsetRelocation = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	customHead.offsetSection = (DA)((char *)IMAGE_FIRST_SECTION(pNt) - (char *)data);
	customHead.imageAddr = pNt->OptionalHeader.ImageBase;

	//clear DOS head and NT head
	memset(data, 0, customHead.offsetSection);
	return 0;
}

int CPePacket::GenerateShellCode()
{
	if (
		ReadFileContent() ||
		IsExeFile() ||
		GetCustomHead() ||
		ProcessData() ||
		GetResourceFile() ||
		PacthCustomHead() ||
		CreateBinFile()
		)
	{
		printf("[-] Generate failed.\n");
	}
	else
	{
		printf("[+] Generate success.\n");
	}


	return 0;
}

int CPePacket::ProcessData()
{
	if (cmpFlag)
	{
		if (CProcsData::CompressData(data, dataSize, data, dataSize))
		{
			printf("[-] Compress PE failed.\n");
			return 1;
		}
		else
		{
			customHead.flag1 = 1;
			customHead.compressSize = dataSize;
		}
	}

	if (rc4Flag)
	{
		if (CProcsData::Rc4Encrypt(data, dataSize, rc4Key, RC4_KEY_SIZE))
		{
			printf("[-] Rc4 encrypt failed.\n");
			return 1;
		}
		else
		{
			customHead.flag2 = 1;
			customHead.rc4Size = dataSize;
		}
	}

	
	return 0;
}

int CPePacket::GetResourceFile()
{
	HRSRC hRsrc = NULL;
	DWORD dwSize = 0;
	HGLOBAL hGlobal = NULL;
	LPVOID pBuffer = NULL;
	int Result = 0;
	do
	{
#ifdef _WIN64
		hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN2), L"BIN");
#else
		hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN1), L"BIN");
#endif // _WIN64

		if (hRsrc == NULL)
		{
			Result = GetLastError();
			printf("[-] Find resource failed. ErrCode:%d\n", Result);
		}

		DWORD dwSize = SizeofResource(NULL, hRsrc);
		if (dwSize == 0)
		{
			Result = GetLastError();
			printf("[-] Get resource size failed. ErrCode:%d\n", Result);
		}


		hGlobal = LoadResource(NULL, hRsrc);
		if (hGlobal == NULL)
		{
			Result = GetLastError();
			printf("[-] Load resource failed. ErrCode:%d\n", Result);
		}

		 pBuffer = LockResource(hGlobal);

		if (pBuffer == NULL)
		{
			Result = GetLastError();
			printf("[-] Lock resource failed. ErrCode:%d\n", Result);
		}


		shellcode = new char[dwSize];
		
		memcpy(shellcode, pBuffer, dwSize);
		shellSize = dwSize;

	} while (FALSE);
	
	if(hGlobal != NULL)
		GlobalUnlock(hGlobal);


	return Result;
}


int CPePacket::PacthCustomHead()
{
	//patch head
	head = new char[headSize];
	unsigned char sign[] = { '\xaa','\xbb', '\xcc', '\xdd', '\x01', '\x01', '\x01', '\x01'};
	memcpy(head, sign, 8);
	memcpy(head + 8, &customHead, sizeof(CustomHead));
	memcpy(head + 8 + sizeof(CustomHead), rc4Key, sizeof(rc4Key));
	return 0;
}
