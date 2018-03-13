#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <comdef.h>
#include <bitset>

// Run the "Target Process" project to find the function offset.
#define FUNCTION_OFFSET 0x1040

#define TARGET_PROCESS_NAME "Target Process.exe"

enum Type {
	T_STRING, T_CHAR, T_BOOL, T_INT, T_VOID,
};

struct Arg {
	Type type;
	LPVOID value;
};

struct Call {
	LPVOID returnValue;
	DWORD exitCode;
};

LPVOID writeMemory(HANDLE hProcess, const char* value, SIZE_T size) {
	LPVOID memoryAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, memoryAddress, value, size, NULL);
	return memoryAddress;
}

PROCESSENTRY32 findProcess(char* processName) {
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hProcessSnapshot, &pEntry)) {
		do {
			_bstr_t binaryString(pEntry.szExeFile);
			if (strcmp((const char*)binaryString, processName) == 0) {
				break;
			}
		} while (Process32Next(hProcessSnapshot, &pEntry));
	}
	return pEntry;
}

MODULEENTRY32 findModule(const char* moduleName, DWORD processId) {
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32);

	HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	if (Module32First(hModuleSnapshot, &mEntry)) {
		do {
			_bstr_t binaryString(mEntry.szModule);
			if (strcmp((const char*)binaryString, moduleName) == 0) {
				break;
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));
	}

	return mEntry;
}

Call call(HANDLE pHandle, std::vector<Arg> args, Type returnType, DWORD64 address, DWORD timeout) {
	std::vector<unsigned char> argShellcode;

	std::reverse(args.begin(), args.end());

	for (auto &arg : args) {

		if (arg.type == T_INT) {
			argShellcode.push_back(0x68);
			int value = *static_cast<int*>(arg.value);

			for (int i = 0; i < 4; i++) {
				int shifted = (value >> (i * 8)) & 0xFF;
				argShellcode.push_back(shifted);
			}

			continue;
		}

		if (arg.type == T_STRING) {
			argShellcode.push_back(0x68);
			std::string value = *static_cast<std::string*>(arg.value);
			LPVOID address = writeMemory(pHandle, value.c_str(), value.length());

			std::cout << "String allocated to 0x" << std::hex << address << std::dec << std::endl;

			for (int i = 0; i < 4; i++) {
				int shifted = ((int)address >> (i * 8)) & 0xFF;
				argShellcode.push_back(shifted);
			}

			continue;
		}

		argShellcode.push_back(0x6A);
		unsigned char value = *static_cast<unsigned char*>(arg.value);
		argShellcode.push_back(value);

	}

	std::vector<unsigned char> callShellcode = {
		0xE8, 0x00, 0x00, 0x00, 0x00, // call 0x00000000
		0x83, 0xC4, (unsigned char)(args.size() * 0x4), // add esp, [arg count * 4]
	};

	LPVOID returnValuePointer;
	if (returnType != T_VOID) {
		// call routine places return value inside eax
		callShellcode.push_back(0xA3); // mov [0x1234], eax

		returnValuePointer = VirtualAllocEx(pHandle, NULL, sizeof(int), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < 4; i++) {
			int shifted = ((DWORD)returnValuePointer >> (i * 8)) & 0xFF;
			callShellcode.push_back(shifted);
		}
	}

	callShellcode.push_back(0xC3); // return

	// concatenate the arg shellcode with the calling shellcode
	std::vector<unsigned char> shellcode;
	shellcode.reserve(argShellcode.size() + callShellcode.size());
	shellcode.insert(shellcode.end(), argShellcode.begin(), argShellcode.end());
	shellcode.insert(shellcode.end(), callShellcode.begin(), callShellcode.end());

	unsigned char* rgShellcode = shellcode.data();

	std::cout << "Opcode generated:";
	for (int i = 0; i < shellcode.size(); i++) {
		printf(" 0x%02x", rgShellcode[i]);
	}
	std::cout << std::endl;

	SIZE_T size = shellcode.size() * sizeof(unsigned char);
	int addessShellcodeOffset = argShellcode.size() + 5; // 5 = [0xE8 -> 0x0, 0x83]

	// Allocate space for the shellcode
	LPVOID pShellcode = VirtualAllocEx(pHandle, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	// Write the address of the function to call (work out relative address)
	*(uintptr_t*)(rgShellcode + (argShellcode.size() + 1)) = address - (uintptr_t)pShellcode - addessShellcodeOffset;
	
	// Write the shellcode
	WriteProcessMemory(pHandle, pShellcode, rgShellcode, size, NULL);

	// Execute the shellcode
	HANDLE thread = CreateRemoteThread(pHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcode, NULL, NULL, NULL);

	Call data = { 0, -1 };

	if (thread == NULL) {
		std::cout << "CreateRemoteThread failed" << std::endl;
		getchar();
		return data;
	}

	WaitForSingleObject(thread, INFINITE);

	GetExitCodeThread(thread, &data.exitCode);

	if (returnType != T_VOID) {
		ReadProcessMemory(pHandle, (LPVOID)returnValuePointer, &data.returnValue, sizeof(int), NULL);
		VirtualFreeEx(pHandle, returnValuePointer, sizeof(int), MEM_RELEASE);
	}

	VirtualFreeEx(pHandle, pShellcode, size, MEM_RELEASE);

	return data;
}

int main() {
	PROCESSENTRY32 process = findProcess(TARGET_PROCESS_NAME);

	_bstr_t binaryString(process.szExeFile);
	if (strcmp((const char*)binaryString, TARGET_PROCESS_NAME)) {
		std::cout << "Unable to find the target process, exiting..." << std::endl;
		getchar();
		return 0;
	}

	MODULEENTRY32 module = findModule(TARGET_PROCESS_NAME, process.th32ProcessID);

	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
	DWORD functionAddress = (DWORD)module.modBaseAddr + FUNCTION_OFFSET;

	int a = 10;
	int b = 25;
	std::vector<Arg> arg = {
		{ T_INT, &a },
		{ T_INT, &b },
	};

	Call data = call(pHandle, arg, T_INT, functionAddress, 5000);

	std::cout << "Returned value: " << (int)data.returnValue << std::endl;
	std::cout << "Exit code: " << data.exitCode << std::endl;

	getchar();
	return 0;
}

