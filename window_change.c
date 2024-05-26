#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

UINT windowChangeCount = 0;

void CALLBACK HandleWinEvent(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime) {
    if(event == EVENT_SYSTEM_FOREGROUND) {
        windowChangeCount++;
    }
}

// Function to monitor window changes, display message if more than 3 changes, and return immediately
bool MonitorWindowChanges() {
    HWINEVENTHOOK hEventHook;
    DWORD startTime;

    // Set up a hook to monitor window change events
    hEventHook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, NULL, HandleWinEvent, 0, 0, WINEVENT_OUTOFCONTEXT);

    // Reset window change count
    windowChangeCount = 0;

    // Get the start time
    startTime = GetTickCount();

    // Run a loop to monitor window changes
    while(GetTickCount() - startTime < 30000) {
        MSG msg;
        if(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        // Check the count within the loop after processing each message
        if(windowChangeCount > 3) {
            MessageBox(NULL, "Hello, you changed more than 3 times!", "Notification", MB_OK);
            UnhookWinEvent(hEventHook);
            return true; // Exit the function immediately after showing the message
        }
    }

    // Cleanup
    UnhookWinEvent(hEventHook);
    // If the function has not returned by now, it means less than 4 changes occurred
    return false;
}

int main() {
    bool moreThanThreeChanges = MonitorWindowChanges();
    if(!moreThanThreeChanges) {
        MessageBox(NULL, "No more than 3 times", "Notification", MB_OK);
    }

    return 0;
}
