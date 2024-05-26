#pragma once
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>

#pragma region Defines

#define DBG_MODE 1 // 0 disable, 1 enable
#define UP -32
#define DN 32
#define ARG_LEN 8
#define ARG_RSP_OFF 0x28
#define X64_PEB_OFF 0x60

#pragma endregion

#pragma region Macros

#if DBG_MODE == 0
#define DPNT(...) do {} while (0)
#else
#define DPNT(...) do { printf(__VA_ARGS__); } while (0)
#endif

#pragma endregion

#pragma region Type Definitions

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, *PPEB;

typedef BOOL(WINAPI* GtThrdCtxt_t)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* StThrdCtxt_t)(
    _In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext
    );

#pragma endregion

#pragma region Function Declarations

BOOL CmprMsk(const BYTE* dt, const BYTE* msk, const char* szMsk);
DWORD_PTR FndPtrn(DWORD_PTR dAddr, DWORD dLen, PBYTE msk, PCHAR szMsk);
DWORD_PTR FndInMdl(LPCSTR mdlName, PBYTE msk, PCHAR szMsk);
UINT64 GtMdlAddr(LPWSTR sModuleName);
UINT64 GtSymbAddr(UINT64 mdlBase, const char* fncName);
UINT64 PrprSyscl(char* fncName);
bool StMainBP();
DWORD64 FndSysclNum(DWORD64 fncAddr);
DWORD64 FndSysclRtnAddr(DWORD64 fncAddr, WORD sysclNum);
LONG HWScExHndlr(EXCEPTION_POINTERS* ExInfo);
bool OpnRICls();
bool ClsRICls();

#pragma endregion
