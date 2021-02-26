#pragma once
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <mscat.h>
#pragma comment (lib, "wintrust")
#pragma comment (lib, "crypt32.lib")
#define PE_BUFF_SIZE 0x1337
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;
typedef NTSTATUS(WINAPI* _ZwQueryVirtualMemory) (HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

static GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 = {0xaac56b, 0xcd44, 0x11d0, 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee};
enum SignState
{
	DIGITAL_SIGSTATE_CANNOTGET = 0,
	DIGITAL_SIGSTATE_VALID = 1,
	DIGITAL_SIGSTATE_EXPIRE = 2,		//µ½ÆÚ
	DIGITAL_SIGSTATE_REVOKED = 3,		//È¡Ïû
	DIGITAL_SIGSTATE_OTHER = 4
};

class CdigitalSig
{
private:
	std::string DigitalSigString;
	std::string Md5DigitalSigString;
	DWORD dDigitalState = DIGITAL_SIGSTATE_CANNOTGET;

public:
	std::string GetDigitalSigString();
	std::string GetMd5DigitalSigString();
	DWORD GetDigitalState();
	CdigitalSig(LPCWSTR lpFileName);


private:
	LONG GetSoftSign(PCWSTR v_pszFilePath, char* v_pszSign, int v_iBufSize);
	void CheckFileTrust(LPCWSTR lpFileName);
};