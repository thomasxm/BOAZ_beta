#include <windows.h>

int main() {
    // Start Notepad
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    BOOL success = CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (!success) {
        MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Wait for 1 second
    Sleep(1000);

    // Display the message box
    // MessageBox(NULL, "I am benign", "Notification", MB_OK | MB_ICONINFORMATION);
    MessageBoxW(NULL, L"Failed to start Notepad.", L"Error", MB_OK | MB_ICONERROR);
    MessageBoxW(NULL, L"I am benign", L"Notification", MB_OK | MB_ICONINFORMATION);


    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
