#include <time.h>
#include <Windows.h>
#include <iostream>
#include "ProccessData.h"

int CProcsData::Rc4Encrypt(char * org, int size, unsigned char * rc4Key, int keySize)
{
	//create key
	srand((int)time(0));
	int i = 0;
	while (1) {
		unsigned char r = rand() % 255;
		if (0x30 <= r && r <= 0x39 || 0x41 <= r && r <= 0x5a || 0x61 <= r && r <= 0x7a)
		{
			rc4Key[i++] = r;
		}
		if (i > keySize) break;
	}


	unsigned char box[256];
	unsigned int index_i = 0;
	unsigned int index_j = 0;

	//init box
	for (int i = 0; i < 256; i++)
	{
		box[i] = i;
	}

	int j = 0;
	unsigned char tmp;
	for (int i = 0; i < 256; i++)
	{
		j = (j + box[i] + rc4Key[i % 16]) % 256;
		tmp = box[i];
		box[i] = box[j];
		box[j] = tmp;
	}

	for (unsigned long k = 0; k < size; k++)
	{
		index_i = (index_i + 1) % 256;
		index_j = (index_j + box[index_i]) % 256;

		tmp = box[index_i];
		box[index_i] = box[index_j];
		box[index_j] = tmp;

		DWORD r = (box[index_i] + box[index_j]) % 256;
		org[k] ^= box[r];
	}
	return 0;
}

int CProcsData::CompressData(char * src, int size, char * retData, int & retSize)
{

	DWORD dwCompressionFormat = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;
	DWORD dwCompress;
	DWORD unKnow;

	pRtlCompressBuffer f_RtlCompressBuffer = (pRtlCompressBuffer)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCompressBuffer");
	pRtlGetCompressionWorkSpaceSize f_RelGetCompressionWorkApacesize = (pRtlGetCompressionWorkSpaceSize)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize");
	if (f_RtlCompressBuffer == NULL || f_RelGetCompressionWorkApacesize == NULL)
	{
		printf("[-] Get Function failed.\n");
		return 1;
	}


	f_RelGetCompressionWorkApacesize(dwCompressionFormat, &dwCompress, &unKnow);

	char *tempMem = new char[dwCompress];
	char *tempData = new char[size];

	DWORD ret = f_RtlCompressBuffer(
		dwCompressionFormat,
		src,
		size,
		tempData,
		size,
		unKnow,
		&dwCompress,
		tempMem
	);

	if (ret == 0)
	{
		retSize = dwCompress;
		memcpy(retData, tempData, retSize);
		
	}
	else
	{
		printf("[-] Compress PE failed.\n");
	}

	delete tempMem;
	delete tempData;
	return ret;
}
