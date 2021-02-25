#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <string.h>
#include <wchar.h>
#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include "tlhelp32.h"
#include "CdigitalSig.h"
_ZwQueryVirtualMemory fnZwQueryVirtualMemory = NULL;

BOOL Is64BitPorcess(HANDLE hProcess)
{
	BOOL bIsWow64 = false;
	IsWow64Process(hProcess, &bIsWow64);
	return bIsWow64 == false;
}
BOOL EnableDebugPrivilege(BOOL bEnable)
{
	//Enabling the debug privilege allows the application to see
	//information about service application
	BOOL fOK = FALSE;     //Assume function fails
	HANDLE hToken;
	//Try to open this process's acess token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		//Attempt to modify the "Debug" privilege
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOK = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOK;
}

void WCharToChar(const WCHAR* tchar, char* _char)
{
	int iLength;
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}
void CharToWchar(const char* _char, WCHAR* tchar)
{
	int iLength;
	iLength = MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, NULL, 0);
	MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, tchar, iLength);
}
BOOL DosPathToNtPath(WCHAR* pszDosPath, LPTSTR pszNtPath)
{
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), L"A:\\") || !lstrcmpi(&(szDriveStr[i]), L"B:\\"))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_wcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
DWORD64 GetProcessMoudleHandle(DWORD pid) {
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(0x00000008, pid);
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}
	do {
		CloseHandle(handle);
		return (DWORD64)moduleEntry.hModule;
	} while (Module32Next(handle, &moduleEntry));
	return 0;
}

bool CheckThreadAddressIsExcute(DWORD64 pAddress,HANDLE pHandle, HANDLE pID, HANDLE Tid, BOOL isRipBackTrack) {

	DWORD64 ReadNum = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (fnZwQueryVirtualMemory(pHandle, (PVOID)pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), &ReadNum) >= 0) {
		if (mbi.AllocationBase) {
			if (mbi.Type != MEM_IMAGE) {
				BOOL CheckExcuteFlag = mbi.AllocationProtect & PAGE_EXECUTE || mbi.AllocationProtect & PAGE_EXECUTE_READ || mbi.AllocationProtect & PAGE_EXECUTE_READWRITE || mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY;
				if (CheckExcuteFlag)
				{
					printf("\t => [线程堆栈回溯] 检测到未知内存区域[VirtualAlloc免杀?] 地址 %p PID %d TID %d \n", pAddress, pID, Tid);
					char PEStack[0x2];
					if (ReadProcessMemory(pHandle, mbi.BaseAddress, PEStack, sizeof(PEStack), &ReadNum)) {
						if (PEStack[0] == 'M' && PEStack[1] == 'Z') {
							printf("\t => [!!!线程堆栈回溯!!!] 检测到内存加载程序 线程地址 %p PID %d TID %d 内存加载模块地址: %p\n", pAddress, pID, Tid, mbi.BaseAddress);
						}
					}
					return true;
				}
				else if (isRipBackTrack && mbi.AllocationProtect & PAGE_READONLY && mbi.AllocationProtect & PAGE_NOACCESS) {
					printf("\t => [线程堆栈回溯] 检测到线程曾在不可执行的代码区域执行过[请检查是否有Rootkit存在或者是否被Hook] 地址 %p PID %d TID %d \n", pAddress, pID, Tid);
					return true;
				}
			}
		}
	}
	return false;
}
void ThreadStackWalk() {
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	DWORD ExitCode = 0;
	hThreadSnap = CreateToolhelp32Snapshot(0x00000004, GetCurrentProcessId());
	if (hThreadSnap)
	{
		te32.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hThreadSnap, &te32))
		{
			CloseHandle(hThreadSnap);
			return;
		}
		do
		{
			if (te32.th32OwnerProcessID != GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
			{
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				if (hThread && hThread != (HANDLE)-1)
				{
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, te32.th32OwnerProcessID);
					if (hProcess) {
						STACKFRAME_EX StackFarmeEx;
						memset(&StackFarmeEx, 0, sizeof(STACKFRAME_EX));
						if (Is64BitPorcess(hProcess)) {
							CONTEXT context = { 0 };
							context.ContextFlags = CONTEXT_ALL;
							if (GetThreadContext(hThread, &context))
							{
								if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
								{
									//hwbp hook
									printf("\t => [线程堆栈回溯] 检测到HWBP Hook PID %d TID %d \n", te32.th32OwnerProcessID, te32.th32ThreadID);
								}
								CheckThreadAddressIsExcute(context.Rip, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, TRUE);
								StackFarmeEx.AddrPC.Offset = context.Rip;
								StackFarmeEx.AddrPC.Mode = AddrModeFlat;
								StackFarmeEx.AddrStack.Offset = context.Rsp;
								StackFarmeEx.AddrStack.Mode = AddrModeFlat;
								StackFarmeEx.AddrFrame.Offset = context.Rsp;
								StackFarmeEx.AddrFrame.Mode = AddrModeFlat;
								DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
								while (true)
								{
									if (!StackWalkEx(machineType, hProcess, hThread, &StackFarmeEx, &context, NULL, NULL, NULL, NULL, NULL))
										break;
									if (StackFarmeEx.AddrFrame.Offset == 0)
										break;
									CheckThreadAddressIsExcute(StackFarmeEx.AddrPC.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, TRUE);
									CheckThreadAddressIsExcute(StackFarmeEx.AddrReturn.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, FALSE);
									CheckThreadAddressIsExcute(StackFarmeEx.AddrStack.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, FALSE);
								}
							}
						} else {
							WOW64_CONTEXT context = { 0 };
							context.ContextFlags = CONTEXT_ALL;
							if (Wow64GetThreadContext(hThread, &context))
							{
								if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
								{
									//hwbp hook
									printf("\t => [线程堆栈回溯] 检测到HWBP Hook PID %d TID %d \n", te32.th32OwnerProcessID, te32.th32ThreadID);
								}
								
								CheckThreadAddressIsExcute(context.Eip, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, TRUE);
								StackFarmeEx.AddrPC.Offset = context.Eip;
								StackFarmeEx.AddrPC.Mode = AddrModeFlat;
								StackFarmeEx.AddrStack.Offset = context.Esp;
								StackFarmeEx.AddrStack.Mode = AddrModeFlat;
								StackFarmeEx.AddrFrame.Offset = context.Ebp;
								StackFarmeEx.AddrFrame.Mode = AddrModeFlat;
								DWORD machineType = IMAGE_FILE_MACHINE_I386;//IMAGE_FILE_MACHINE_I386; IMAGE_FILE_MACHINE_AMD64;
								while (true)
								{
									if (!StackWalkEx(machineType, hProcess, hThread, &StackFarmeEx, NULL, NULL, NULL, NULL, NULL, NULL))
										break;
									if (StackFarmeEx.AddrFrame.Offset == 0)
										break;
									CheckThreadAddressIsExcute(StackFarmeEx.AddrPC.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, TRUE);
									CheckThreadAddressIsExcute(StackFarmeEx.AddrReturn.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, FALSE);
									CheckThreadAddressIsExcute(StackFarmeEx.AddrStack.Offset, hProcess, (HANDLE)te32.th32OwnerProcessID, (HANDLE)te32.th32ThreadID, FALSE);
								}
							}
						}
						CloseHandle(hProcess);
					}
					CloseHandle(hThread);
				}
			}

		} while (Thread32Next(hThreadSnap, &te32));
		CloseHandle(hThreadSnap);
	}
}
void WalkProcessMoudle(DWORD pID,HANDLE pHandle,WCHAR* pMoudleName) {

	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	char* AllocBuff = (char*)VirtualAlloc(NULL, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (AllocBuff) {
		if (!Module32First(handle, &moduleEntry)) {
			CloseHandle(handle);
			return;
		}
		do {
			DWORD64 ReadNum = 0;
			if (ReadProcessMemory(pHandle, moduleEntry.modBaseAddr, AllocBuff, 0x200, &ReadNum)) {
				if (AllocBuff[0] == 'M' && AllocBuff[1] == 'Z') {
					PIMAGE_DOS_HEADER CopyDosHead = (PIMAGE_DOS_HEADER)AllocBuff;
					PIMAGE_NT_HEADERS CopyNthead = (PIMAGE_NT_HEADERS)((LPBYTE)AllocBuff + CopyDosHead->e_lfanew);
					PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)CopyNthead + sizeof(CopyNthead->Signature) + sizeof(CopyNthead->FileHeader) + CopyNthead->FileHeader.SizeOfOptionalHeader);
					int FoundNum = 0;
					for (WORD i = 0; i < CopyNthead->FileHeader.NumberOfSections; i++)
					{
						if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
							FoundNum++;
						}
						if (FoundNum > 1) {
							printf("\t => [进程检测] 检测到额外的可执行区段(.rdata免杀 or 加壳程序) 进程名 %ws 路径 %ws 进程id %d\n", pMoudleName, moduleEntry.szExePath, pID);
							break;
						}
					}
				}
			}

		} while (Module32Next(handle, &moduleEntry));
		VirtualFree(AllocBuff, 0, MEM_RELEASE);
	}
	CloseHandle(handle);
}
void ProcessStackWalk() {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot error.\n");
		return;
	}
	BOOL bProcess = Process32First(hProcessSnap, &pe32);
	while (bProcess)
	{
		//打印进程名和进程ID
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID);
		if (hProcess) {
			WalkProcessMoudle(pe32.th32ProcessID, hProcess, pe32.szExeFile);
			WCHAR szImagePath[MAX_PATH];
			WCHAR pszFullPath[MAX_PATH];
			if (GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
			{
				if (DosPathToNtPath(szImagePath, pszFullPath))
				{
					CdigitalSig DigitalSig(pszFullPath);
					DWORD dDigitalState = DigitalSig.GetDigitalState();
					if (dDigitalState == DIGITAL_SIGSTATE_REVOKED || dDigitalState == DIGITAL_SIGSTATE_EXPIRE) {
						printf("\t => [进程扫描] 检测到可疑签名进程 路径 %ws static %d \n", pszFullPath, dDigitalState);
					}
				}
			}
			CloseHandle(hProcess);
		}
		bProcess = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return;

}
void ScanSystemDrivers() {
	DWORD cbNeeded = 0; // drivers[] 返回的字节数
	LPVOID drivers[MAX_PATH] = { 0 }; // 驱动程序地址列表数组
	int cDrivers = 0;	// 驱动个数
	Wow64EnableWow64FsRedirection(0);
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) // EnumDeviceDrivers 检索每个驱动文件的加载地址
	{
		char szDriver[MAX_PATH] = { 0 };	// 驱动文件名
		char szPath[MAX_PATH] = { 0 };	// 存放驱动文件全路径
		char szNtPath[MAX_PATH] = { 0 };
		char szSystemPath[MAX_PATH] = { 0 }; // 存放 system32 文件夹路径
		cDrivers = cbNeeded / sizeof(LPVOID);	// 驱动个数

		for (int i = 0; i < cDrivers; i++)
		{
			if (drivers[i]) {
				if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(LPVOID)))
				{
					if (GetDeviceDriverFileNameA(drivers[i], szPath, sizeof(szPath))) {
						bool isSystemDriver = true;
						//只判断非系统驱动
						if (szPath[1] == '?')
						{
							isSystemDriver = false;
							int len = strlen(szPath);
							szPath[len + 1] = '\0';
							for (int j = 0; j < len; j++)
							{
								szPath[j] = szPath[j + 4];
							}
							WCHAR UnicodeFilePath[MAX_PATH << 1] = { 0 };
							CharToWchar(szPath, UnicodeFilePath);
							CdigitalSig DigitalSig(UnicodeFilePath);
							DWORD dDigitalState = DigitalSig.GetDigitalState();
							if (dDigitalState != DIGITAL_SIGSTATE_VALID) {
								printf("\t => [驱动扫描] 检测到未知驱动 路径 %ws \n", UnicodeFilePath);
							}
						}
					}
				}
			}
		}
	}
	Wow64EnableWow64FsRedirection(1);
}
int main()
{
	printf("DuckMemoryScan By huoji 2021-02-23 \n");
	if (EnableDebugPrivilege(true) == false) {
		printf("权限提升失败,请以管理员身份运行 \n");
		system("pause");
		return 0;
	}
	if (fnZwQueryVirtualMemory == NULL) {
		fnZwQueryVirtualMemory = (_ZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryVirtualMemory");
		if (fnZwQueryVirtualMemory == NULL)
		{
			printf("没有找到ZwQueryVirtualMemory函数, 请修改源码ZwQueryVirtualMemory => VirtualQueryEx \n");
			system("pause");
			return 0;
		}
	}
	printf("线程堆栈回溯检测 ... \n");
	ThreadStackWalk();
	printf("驱动检测... \n");
	ScanSystemDrivers();
	printf("进程检测... \n");
	ProcessStackWalk();
	printf("检测完毕 ... \n");
	system("pause");
	return 0;
}