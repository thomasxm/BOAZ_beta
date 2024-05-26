#include <Windows.h>
#include <iostream>

#include "PePacket.h"

int wmain(int argc, wchar_t * argv[])
{

	CPePacket pePacket;

	if (pePacket.ParsePara(argc, argv))
	{
		printf("Invaild para\n");
		exit(0);
	}
	
	pePacket.GenerateShellCode();

	return 0;
}