/**
Editor: Thomas X Meng
***/
#include <stdio.h>
#include <windows.h>

void exit_process();

// Function definition
void exit_process() {
    exit(0); // Exit the program normally with status 0
}

unsigned char magiccode[] = ####SHELLCODE####;



int main()
{
    printf("Good morning!\n");
    exit_process();


	return 0;
}