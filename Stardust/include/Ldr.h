#ifndef BOAZ_LDR_H
#define BOAZ_LDR_H

#include <Common.h>

PVOID LdrModulePeb(
    _In_ ULONG Hash
);

PVOID LdrFunction(
    _In_ PVOID Module,
    _In_ ULONG Function
);

#endif //BOAZ_LDR_H
