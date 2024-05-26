#include <Win32.h>
#include <Utils.h>
#include <Macros.h>

#include <winternl.h>

// NOTE: The Module hash needs to be a hash from a wide string instead of an ansi string.
SEC( text, B ) PVOID LdrModulePeb( UINT_PTR hModuleHash )
{
    PLDR_DATA_TABLE_ENTRY Module      = ( PLDR_DATA_TABLE_ENTRY ) ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY FirstModule = Module;

    do
    {
        DWORD ModuleHash = HashString( Module->FullDllName.Buffer, Module->FullDllName.Length );

        if ( ModuleHash == hModuleHash )
            return Module->Reserved2[ 0 ];

        Module = ( PLDR_DATA_TABLE_ENTRY ) Module->Reserved1[ 0 ];
    } while ( Module && Module != FirstModule );

    return INVALID_HANDLE_VALUE;
}

SEC( text, B ) PVOID LdrFunction( UINT_PTR Module, UINT_PTR FunctionHash )
{
    PIMAGE_NT_HEADERS       NtHeader         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = NULL;
    PDWORD                  AddrOfFunctions  = NULL;
    PDWORD                  AddrOfNames      = NULL;
    PWORD                   AddrOfOrdinals   = NULL;
    PVOID                   FunctionAddr     = NULL;
    PCHAR                   FunctionName     = NULL;
    ANSI_STRING             AnsiString       = { 0 };

    NtHeader         = C_PTR( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDirectory     = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    
    AddrOfNames      = C_PTR( Module + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Module + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Module + ExpDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        FunctionName = ( PCHAR ) Module + AddrOfNames[ i ];
        if ( HashString( FunctionName, 0 ) == FunctionHash )
        {
            return C_PTR( Module + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );
        }
    }
}