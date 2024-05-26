#ifndef API_UNTANGLE_H
#define API_UNTANGLE_H

#include <windows.h>

// Declares the ModifyFunctionInMemory function
BOOL ModifyFunctionInMemory(const char* dllName, const char* functionName);

// Declares the ExecuteModifications function
void ExecuteModifications(int argc, char *argv[]);

#endif // API_UNTANGLE_H
