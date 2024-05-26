#include <windows.h>
#include <stdio.h>

// Function to check if the execution is likely in a virtual environment.
int isRunningInVirtualEnv() {
    DWORD startTime = GetTickCount();
    DWORD sleepTime = 9000; // Sleep time in milliseconds (9 seconds)

    Sleep(sleepTime); // Sleep for a specified duration

    DWORD endTime = GetTickCount();
    DWORD actualSleepTime = endTime - startTime;

    // Allow some margin for error due to processing delays
    DWORD margin = 500; // 0.5 seconds margin

    if (actualSleepTime < sleepTime - margin || actualSleepTime > sleepTime + margin) {
        printf("Discrepancy detected: Actual sleep time is %lu ms, which is outside the expected range.\n", actualSleepTime);
        return 1; // Likely in a VE
    } else {
        printf("No significant discrepancy detected: Actual sleep time is %lu ms.\n", actualSleepTime);
        return 0; // Likely not in a VE
    }
}

int main() {
    if (isRunningInVirtualEnv()) {
        printf("The program is likely running in a virtual environment.\n");
    } else {
        printf("The program is likely running on physical hardware.\n");
    }

    return 0;
}
