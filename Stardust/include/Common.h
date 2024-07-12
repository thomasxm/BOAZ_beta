#ifndef BOAZ_COMMON_H
#define BOAZ_COMMON_H

//
// system headers
//
#include <windows.h>

//
// BOAZ headers
//
#include <Native.h>
#include <Macros.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>

//
// BOAZ instances
//
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    //
    // base address and size
    // of the implant
    //
    BUFFER Base;

    struct {

        //
        // Ntdll.dll
        //
        D_API( RtlAllocateHeap        )
        D_API( NtProtectVirtualMemory )
        D_API( NtAllocateVirtualMemory )
        D_API( NtWriteVirtualMemory )
        D_API( NtCreateThreadEx )
        D_API( TpAllocWork )
        D_API( TpPostWork )
        D_API( TpReleaseWork )


        //
        // kernel32.dll
        //
        D_API( LoadLibraryW )
        D_API( WaitForSingleObjectEx )
        D_API( WaitForSingleObject )
        D_API( GetCurrentProcess )

        //
        // User32.dll
        //
        D_API( MessageBoxW )

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID User32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main(
    _In_ PVOID Param
);

#endif //BOAZ_COMMON_H
