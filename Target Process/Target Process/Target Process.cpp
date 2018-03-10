#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

void functionToRemotelyCall(int a, bool b, std::string c) {
	std::cout << "Function called with parameters: " << a << ", " << b << ", " << c.c_str() << std::endl;
}

int main() {
	DWORD offset = (DWORD)functionToRemotelyCall - (DWORD)GetModuleHandle(NULL);
	std::cout << "Function offset from base: 0x" << std::hex << offset << std::dec << std::endl;

	getchar();
	return 0;
}