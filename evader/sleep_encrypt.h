#ifndef SLEEP_ENCRYPT_H
#define SLEEP_ENCRYPT_H
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <vector>


void SweetSleep(DWORD sleepTime = 15000);

#endif // SLEEP_ENCRYPT_H