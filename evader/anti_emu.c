//// x86_64-w64-mingw32-g++ -std=c++11 -static-libgcc -static-libstdc++ bee.c -o bee.exe -lws2_32 -lpsapi
//// -lws2_32 for socket, -lpsapi for instrumentation1 EnumProcessModules
#include "anti_emu.h"
#include <winsock2.h> // Include winsock2.h before windows.h
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>
#include <string.h>




// Ensure PSAPI_VERSION is defined before including psapi.h
#define PSAPI_VERSION 1
#include <stdio.h>
#include <psapi.h> // For EnumProcessModules and related functions

// Forward declarations of all check functions
BOOL fs1();
BOOL fs2();
BOOL time3();
BOOL instrumentation9();
BOOL network445();
BOOL time2();
BOOL instrumentation1();
BOOL godFather();
BOOL godMother();
BOOL numaFunc();

#pragma comment(lib, "Ws2_32.lib")

const char* realDLL[] = {"Kernel32.DLL", "networkexplorer.DLL", "NlsData000c.DLL"};
const char* falseDLL[] = {"NightWing.DLL", "Pokemon.DLL"};


bool checkExecutableName(const char* exeName, char* realName) {
    if (strstr(realName, exeName) != NULL) {
        printf("Executable name is the same. \n");
        return FALSE;
    } else {
        printf("Executable name is different. \n");
        printf("The real name of the executable is: %s\n", realName);
        printf("The name of the executable is: %s\n", exeName);
        return TRUE;
    }
}

// Global variables
int iCounter;
BOOL bState;

// Thread function to monitor the counter
unsigned __stdcall threadFunction1(void* pArguments) {
    Sleep(200); // Wait for 200 milliseconds
    if (iCounter == 10) {
        bState = TRUE; // Set bState if iCounter reached 10
    }
    _endthreadex(0); // Properly exit the thread
    return 0;
}

// Thread function to increment the counter
unsigned __stdcall threadFunction2(void* pArguments) {
    for (int i = 0; i < 10; i++) {
        iCounter++; // Increment iCounter
        Sleep(10); // Wait for 10 milliseconds between increments
    }
    _endthreadex(0); // Properly exit the thread
    return 0;
}

// Function to test threading logic
BOOL time3() {
    unsigned threadID;
    HANDLE hThread1, hThread2;

    // Initialize global variables
    iCounter = 0;
    bState = FALSE;

    // Create threads
    hThread2 = (HANDLE)_beginthreadex(NULL, 0, &threadFunction2, NULL, 0, &threadID); // Thread to increment counter
    hThread1 = (HANDLE)_beginthreadex(NULL, 0, &threadFunction1, NULL, 0, &threadID); // Thread to check counter

    // Wait for the threads to complete
    WaitForSingleObject(hThread1, INFINITE);
    WaitForSingleObject(hThread2, INFINITE);

    // Clean up handles
    CloseHandle(hThread1);
    CloseHandle(hThread2);

    // The logic to return TRUE if bState is FALSE seems inverted based on usual expectations.
    // It returns FALSE if bState is TRUE (meaning the counter reached 10 as expected).
    if (bState == TRUE) {
        // If bState is TRUE, it means the counter reached 10 as expected (no matrix detected)
        printf("time3: No matrix detected. The counter reached the expected value.\n");
        return FALSE; // Originally, the function returned !bState, so we maintain the logic.
    } else {
        // If bState is FALSE, it suggests that the counter did not reach 10 before the check,
        // which could indicate the presence of an matrix speeding up the Sleep function.
        printf("time3: Potential matrix detected. The counter did not reach the expected value before the check.\n");
        return TRUE;
    }
}


// Corrected version of instrumentation1 as provided
BOOL instrumentation1() {
    DWORD processID = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        return TRUE;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            // Correctly obtain the module base address as a pointer.
            BYTE* moduleBase = reinterpret_cast<BYTE*>(hMods[i]);
            
            // Access the DOS header.
            PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue; // Not a valid PE file.

            // Access the NT headers.
            PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(moduleBase + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) continue; // Not a valid PE file.

            // Further processing...
        }
    }
    CloseHandle(hProcess);
    return FALSE; // Adjust according to your logic.
}



// Define or declare GetNameByPid function
void GetNameByPid(DWORD pid, char* buffer, DWORD bufferSize) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    strncpy(buffer, pe32.szExeFile, bufferSize);
                    buffer[bufferSize - 1] = '\0'; // Ensure null-termination
                    CloseHandle(hSnapshot);
                    return;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    // If PID not found or other error, return an empty string
    buffer[0] = '\0';
}

BOOL fs1() {
    printf("Executing fs1...\n");
    char buff[65535];
    char DataBuffer[] = "To be or not to be, this is not a question.";
    DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;
    HANDLE hFile;
    DWORD dwBytesRead = 0;
    char ReadBuffer[256] = {0};
    GetEnvironmentVariable("TMP", buff, 65535);
    strcat(buff, "\\shakes.txt");
    hFile = CreateFile(buff, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create file for writing.\n");
        return TRUE;
    }
    bErrorFlag = WriteFile(hFile, DataBuffer, dwBytesToWrite, &dwBytesWritten, NULL);
    CloseHandle(hFile);
    if (!bErrorFlag || dwBytesToWrite != dwBytesWritten) {
        printf("Failed to write data to file.\n");
        return TRUE;
    }
    hFile = CreateFile(buff, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file for reading.\n");
        return TRUE;
    }
    ReadFile(hFile, ReadBuffer, 255, &dwBytesRead, NULL);
    CloseHandle(hFile);
    if (strstr(ReadBuffer, DataBuffer) != NULL) {
        printf("Data verified in file.\n");
        return FALSE;
    } else {
        printf("Data mismatch in file.\n");
        return TRUE;
    }
}

BOOL fs2() {
    printf("Executing fs2...\n");
    char *realDLL[] = {"Kernel32.DLL", "networkexplorer.DLL", "User32.DLL"};
    char *falseDLL[] = {"NightWing.DLL", "Pokemon.DLL"};
    HMODULE hInstLib;
    for (int i = 0; i < (sizeof(realDLL) / sizeof(*realDLL)); i++) {
        hInstLib = LoadLibraryA(realDLL[i]);
        if (hInstLib == NULL) {
            printf("Failed to load real DLL: %s\n", realDLL[i]);
            return TRUE;
        }
        FreeLibrary(hInstLib);
    }
    for (int i = 0; i < (sizeof(falseDLL) / sizeof(*falseDLL)); i++) {
        hInstLib = LoadLibraryA(falseDLL[i]);
        if (hInstLib != NULL) {
            printf("Fake DLL loaded: %s\n", falseDLL[i]);
            return TRUE;
        }
    }
    printf("DLL check passed.\n");
    return FALSE;
}


BOOL instrumentation9() {
    printf("Executing instrumentation9...\n");
    HINSTANCE hInstLib;
    HANDLE hSnapShot;
    BOOL bContinue;
    DWORD crtpid, pid = 0;
    PROCESSENTRY32 procentry;
    char ProcName[MAX_PATH] = {0};
    hInstLib = LoadLibraryA("Kernel32.DLL");
    if (hInstLib == NULL) {
        printf("Unable to load Kernel32.dll\n");
        return TRUE;
    }
    // Function pointers declaration
    HANDLE(WINAPI* lpfCreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL(WINAPI* lpfProcess32First)(HANDLE, LPPROCESSENTRY32);
    BOOL(WINAPI* lpfProcess32Next)(HANDLE, LPPROCESSENTRY32);

    lpfCreateToolhelp32Snapshot = (HANDLE(WINAPI*)(DWORD, DWORD))GetProcAddress(hInstLib, "CreateToolhelp32Snapshot");
    lpfProcess32First = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress(hInstLib, "Process32First");
    lpfProcess32Next = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress(hInstLib, "Process32Next");
    if (lpfProcess32Next == NULL || lpfProcess32First == NULL || lpfCreateToolhelp32Snapshot == NULL) {
        FreeLibrary(hInstLib);
        printf("Function pointers could not be initialized.\n");
        return TRUE;
    }
    hSnapShot = lpfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        FreeLibrary(hInstLib);
        printf("ERROR: INVALID_HANDLE_VALUE\n");
        return TRUE;
    }
    procentry.dwSize = sizeof(PROCESSENTRY32);
    bContinue = lpfProcess32First(hSnapShot, &procentry);
    crtpid = GetCurrentProcessId();
    while (bContinue) {
        if (crtpid == procentry.th32ProcessID) {
            pid = procentry.th32ParentProcessID;
            GetNameByPid(pid, ProcName, MAX_PATH);
            if (strcmp("explorer.exe", ProcName) != 0 && strcmp("cmd.exe", ProcName) != 0 && strcmp("powershell.exe", ProcName) != 0) {
                printf("Instrumentation detected based on parent process name.\n");
                printf("Parent process name: %s\n", ProcName);
                FreeLibrary(hInstLib);
                CloseHandle(hSnapShot);
                return TRUE;
            } else {
                printf("No instrumentation detected based on parent process name.\n");
                FreeLibrary(hInstLib);
                CloseHandle(hSnapShot);
                return FALSE;
            }
        }
        procentry.dwSize = sizeof(PROCESSENTRY32);
        bContinue = lpfProcess32Next(hSnapShot, &procentry);
    }
    FreeLibrary(hInstLib);
    CloseHandle(hSnapShot);
    printf("Failed to find current process in snapshot.\n");
    return FALSE;
}

BOOL network445() {
    printf("Executing network445...\n");
    WSADATA WsaDat;
    if (WSAStartup(MAKEWORD(2, 2), &WsaDat) != 0) {
        printf("WSA Initialization failed.\n");
        WSACleanup();
        return TRUE;
    }

    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Socket == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return TRUE;
    }

    struct sockaddr_in SockAddr;
    memset(&SockAddr, 0, sizeof(SockAddr));
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_port = htons(445);
    SockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0) {
        printf("Connection to port 445 failed, possibly in matrix.\n");
        closesocket(Socket);
        WSACleanup();
        return TRUE; 
    }

    printf("Connected to port 445, no matrix detected.\n");
    closesocket(Socket);
    WSACleanup();
    return FALSE;
}


BOOL time2() {
    DWORD tc1, tc2;
    tc1 = GetTickCount();
    Sleep(1000); // Sleep for 1000 milliseconds (1 second)
    tc2 = GetTickCount();
    tc2 = tc2 - tc1; // Calculate the elapsed time


    if(tc2 >= 1000) {
        printf("Time2 check passed. Execution seems normal.\n");
        return FALSE;
    }
    printf("Time2 check failed. Potential matrix detected.\n");
    return TRUE;
}


#define MONEY_TO_PAY 1000000000
BOOL godFather() {
    printf("Executing godFather...\n");
    char *memdmp = nullptr;
    memdmp = (char *) malloc(MONEY_TO_PAY);
    if (memdmp != nullptr) {
        memset(memdmp, 0, MONEY_TO_PAY);
        free(memdmp);
        return TRUE;
    } else {
        return FALSE;
    }
}

#define HR_RESOURCE 1000000000

BOOL godMother() {
    printf("Executing godMother...\n");
    int cpt = 0;
    int i = 0;
    for(i=0; i<HR_RESOURCE; i++) {
        cpt++;
    }
    if(cpt == HR_RESOURCE) {
        return TRUE;
    } else {
        return FALSE;
    }
}

BOOL numaFunc() {
    DWORD node = 0; // Example: Targeting NUMA node 0
    ULONGLONG processorMask = 0;
    
    BOOL result = GetNumaNodeProcessorMask(node, &processorMask);
    if (result) {
        printf("Processor mask for NUMA node %lu: %llu\n", node, processorMask);
    } else {
        printf("Failed to retrieve the processor mask for NUMA node %lu\n", node);
    }

    LPVOID mem = NULL;
    mem = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE |
    MEM_COMMIT, PAGE_EXECUTE_READWRITE,0);
    if (mem != NULL && result) {
        printf("VirtualAllocExNuma succeeded\n");
        printf("Getting processor mask for NUMA node %lu: %llu\n", node, processorMask);
        return FALSE;
    } else {
        printf("VirtualAllocExNuma failed\n");
        printf("Failed to retrieve the processor mask for NUMA node %lu\n", node);
        return TRUE;
    }

}
// pass the binary name to check if the name is the same in emulator:
BOOL executeAllChecksAndEvaluate(const char* name, char* argv) {
// BOOL executeAllChecksAndEvaluate() {
    int failedChecks = 0;
    // if god father fails, we exit the program
    if(godFather()) {
        printf("God father check passed. Execution seems normal.\n");
    } else {
        printf("God father check failed. Potential matrix detected.\n");
        exit(EXIT_FAILURE); // Terminate the program
        return FALSE;
    }
    if(godMother()) {
        printf("God mother check passed. Execution seems normal.\n");
    } else {
        printf("God mother check failed. Potential matrix detected.\n");
        exit(EXIT_FAILURE); // Terminate the program
        return FALSE;
    }
    
    if (time2()) failedChecks++;
    if (fs1()) failedChecks++;
    if (fs2()) failedChecks++;
    if (time3()) failedChecks++;
    if (instrumentation9()) failedChecks++;
    if (network445()) failedChecks++;
    if (instrumentation1()) failedChecks++;
    if (numaFunc()) failedChecks++;
    if (name != NULL) {
        if (checkExecutableName(name, argv)) failedChecks++;
    }

    // Evaluate the result
    if (failedChecks > 2) {
        printf("More than 2 black cats indicate matrix. Exit, exit.\n");
        exit(EXIT_FAILURE); // Terminate the program
        return FALSE;
    } else {
        printf("Most checks passed. Continuing execution.\n");
        return TRUE;
    }
}


// int main() {
//     printf("Starting anti-matrix checks...\n");

//     // Now, just call the new function to perform all checks and take action based on their outcomes.
//     executeAllChecksAndEvaluate();

//     printf("All checks completed successfully. Process continues.\n");


    // if (!time2()) {
    //     printf("[+] time1 passed. Execution seems normal.\n");
    // } else {
    //     printf("[-] time1 failed. Potential matrix detected.\n");
    // }

    // if (!fs1()) {
    //     printf("[+]FS1 check: Secure file operations verified.\n");
    // } else {
    //     printf("[-]FS1 check failed: Issue with file operations detected.\n");
    // }

    // if (!fs2()) {
    //     printf("[+]FS2 check: DLL loading behavior normal.\n");
    // } else {
    //     printf("[-]FS2 check failed: Anomaly in DLL loading detected.\n");
    // }

    // if (!time3()) {
    //     printf("[+]time3 returned FALSE. Counter reached the expected value.\n");
    // } else {
    //     printf("[-]time3 returned TRUE. Counter did not reach the expected value. Check is performed before the counter has reached its final value.\n");
    // }

    // if (!instrumentation9()) {
    //     printf("[+]Instrumentation9 check: Parent process verification passed.\n");
    // } else {
    //     printf("[-]Instrumentation9 check failed: Possible instrumentation detected.\n");
    // }

    // if (!network445()) {
    //     printf("[+]Network445 check: Network behavior normal.\n");
    // } else {
    //     printf("[-]Network445 check failed: Network behavior anomaly detected.\n");
    // }

    // // Output the result
    // if(!instrumentation1()) {
    //     printf("[+]No instrumentation patterns detected.\n");
    // } else {
    //     printf("[-]Instrumentation detection logic triggered.\n");
    // }

    // printf("[*] Anti-matrix checks completed.\n");
//     return 0;
// }
