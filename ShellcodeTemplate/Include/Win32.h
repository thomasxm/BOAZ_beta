#include <windows.h>
#include <Macros.h>

PVOID LdrModulePeb( UINT_PTR hModuleHash );
PVOID LdrFunction( UINT_PTR hModule, UINT_PTR ProcHash );