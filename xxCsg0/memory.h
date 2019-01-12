#pragma once

//#undef   UNICODE
#include <Windows.h>
#include <TlHelp32.h>
#include <atlconv.h>
#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

class NBQMemory
{
public:
	template <typename datatype>
	datatype ReadMemory(HANDLE hProcess, DWORD address)
	{
		datatype buffer;
		ReadProcessMemory(hProcess, (LPCVOID)address, &buffer, sizeof(datatype), NULL);
		return buffer;
	}

	template <typename datatype>
	void WriteMemory(HANDLE hProcess, DWORD address, datatype value)
	{
		WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(value), NULL);
	}

	HANDLE GetHandleByProcessName(const char* processName, DWORD dwAccessRights)
	{
		DWORD pID = NULL;
		HANDLE hProcess = INVALID_HANDLE_VALUE;
		HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (ss != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 pe;
			pe.dwSize = sizeof(PROCESSENTRY32);
			do
			{
				//typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character

				//USES_CONVERSION;
				//char* output = W2A(pe.szExeFile);

				if (!strcmp(pe.szExeFile, processName))
				{
					pID = pe.th32ProcessID;
					hProcess = OpenProcess(dwAccessRights, false, pID);
				}
			} while (Process32Next(ss, &pe));
			CloseHandle(ss);
		}
		return hProcess;
	}

	HANDLE GetHandleByWindowName(const char* windowName, DWORD dwAccessRights)
	{
		DWORD pID = NULL;
		HANDLE hProcess = INVALID_HANDLE_VALUE;
		HWND hW = FindWindowA(NULL, windowName);
		GetWindowThreadProcessId(hW, &pID);
		CloseHandle(hW);
		if (pID != NULL)
		{
			hProcess = OpenProcess(dwAccessRights, false, pID);
		}
		return hProcess;
	}

	DWORD GetProcessIdByProcessName(const char* processName)
	{
		DWORD pID = NULL;
		HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (ss != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 pe;
			pe.dwSize = sizeof(PROCESSENTRY32);
			do
			{
				//char cpc[] = "";
				//Unicode2Ascii(pe.szExeFile, cpc);

				//USES_CONVERSION;
				//char* output = W2A(pe.szExeFile);

				if (!strcmp(pe.szExeFile, processName))
				{
					pID = pe.th32ProcessID;
				}
			} while (Process32Next(ss, &pe));
			CloseHandle(ss);
		}
		return pID;
	}

	DWORD GetProcessIdByWindowName(const char* windowName)
	{
		DWORD pID = NULL;
		HWND hW = FindWindowA(NULL, windowName);
		GetWindowThreadProcessId(hW, &pID);
		CloseHandle(hW);
		return pID;
	}
	
	DWORD GetModuleBaseAddress(DWORD pID, const char* moduleName)
	{
		DWORD ModuleBaseAddress = NULL;
		
		HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
		if (ss != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32 me;
			me.dwSize = sizeof(MODULEENTRY32);

			if (Module32First(ss, &me))
			{
				do
				{
					//char output[256];
					//sprintf(output, "%ws", me.szModule);

					//#include <atlconv.h>
					//USES_CONVERSION;
					//char* output = W2A(me.szModule);

					//char cpc[] = "";
					//Unicode2Ascii(me.szModule, cpc);
					if (!strcmp(me.szModule, moduleName))
					{
						ModuleBaseAddress = (DWORD)me.modBaseAddr;
						break;
					}
				} while (Module32Next(ss, &me));
			}
			CloseHandle(ss);
		}
		return ModuleBaseAddress;
	}

	MODULEENTRY32 GetModule(DWORD pID, const char* moduleName)
	{
		DWORD ModuleBaseAddress = NULL;
		MODULEENTRY32 me;
		HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
		if (ss != INVALID_HANDLE_VALUE)
		{
			me.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(ss, &me))
			{
				do
				{
					if (!strcmp(me.szModule, moduleName))
					{
						ModuleBaseAddress = (DWORD)me.modBaseAddr;
						break;
					}
				} while (Module32Next(ss, &me));
			}
			CloseHandle(ss);
		}
		return me;
	}

};
