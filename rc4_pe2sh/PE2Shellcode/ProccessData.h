#pragma once
typedef DWORD(__stdcall *pRtlCompressBuffer)(
	IN ULONG   CompressionFormat,
	IN PVOID   SourceBuffer,
	IN ULONG   SourceBufferLength,
	OUT PVOID   DestinationBuffer,
	IN ULONG   DestinationBufferLength,
	IN ULONG   Unknown,
	OUT PULONG   pDestinationSize,
	IN PVOID   WorkspaceBuffer);


typedef DWORD(__stdcall *pRtlGetCompressionWorkSpaceSize)(
	IN ULONG   CompressionFormat,
	OUT PULONG   pNeededBufferSize,
	OUT PULONG   pUnknown);

namespace CProcsData
{

	int Rc4Encrypt(char * org, int size, unsigned char * rc4Key, int keySize);

	int CompressData(char *org, int size, char * retData ,int & retSize);
}