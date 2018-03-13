#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

void functionToRemotelyCall(int a, bool b, std::string c) {
	std::cout << "Function called with parameters: " << a << ", " << b << ", " << c.c_str() << std::endl;
}

int testAdd(int a, int b) {
	return a + b;
}
int main() {
	DWORD offset = (DWORD)testAdd - (DWORD)GetModuleHandle(NULL);
	std::cout << "Function offset from base: 0x" << std::hex << offset << std::dec << std::endl;
	std::cout << "Absolute: 0x" << std::hex << (DWORD)testAdd << std::dec << std::endl;

	getchar();
	getchar();

	return 0;
}