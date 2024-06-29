#include <Windows.h>
#include <Winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>

using namespace std;

namespace WinHax
{
	// returns the base address of the module in the given process
	PVOID GetModuleBase(HANDLE hProcess, LPCSTR lpModuleName)
	{
		// stores the modules
		HMODULE hModules[1024];
		// stores the needed bytes
		DWORD NeededBytes;
		// gets an array of module handles
		if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &NeededBytes))
		{
			// iterates through module handles
			for (int i = 0; i < NeededBytes / sizeof(HMODULE); i++)
			{
				// stores the module image name
				CHAR BaseName[MAX_PATH];
				// gets the name of the module
				if (GetModuleBaseName(hProcess, hModules[i], BaseName, MAX_PATH))
				{
					// compares the names
					if (_stricmp(BaseName, lpModuleName) == 0)
					{
						// returns the base address
						return hModules[i];
					}
				}
			}
		}
		// else we return null
		return NULL;
	}

	// returns the process id for the given image name
	DWORD FindProcess(LPCSTR lpImageName)
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		// validates the handle
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			// stores the process information
			PROCESSENTRY32 ProcessInfo;
			// sets the structure size
			ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
			// gets the first process
			if (Process32First(hSnapshot, &ProcessInfo))
			{
				// gets the information of the next process
				do
				{
					// checks the process name
					if (strcmp(ProcessInfo.szExeFile, lpImageName) == 0)
					{
						// returns the pid
						return ProcessInfo.th32ProcessID;
					}
				} while (Process32Next(hSnapshot, &ProcessInfo));
			}
		}
		// else we return null
		return NULL;
	}

	// returns the address for a given function in a given program
	PVOID GetFunctionAddress(HANDLE hProcess, LPCSTR lpModule, PVOID pFunction)
	{
		return (PVOID)((__int64)WinHax::GetModuleBase(hProcess, lpModule) + ((__int64)pFunction - (__int64)GetModuleHandle(lpModule)));
	}

	// changes the memory protection for the given region
	BOOL ChangeProtection(HANDLE hProcess, PVOID pAddress, SIZE_T dwSize, DWORD dwProtection)
	{
		// stores the old memory protection
		DWORD dwProtect;
		// change the protection of the memory region
		return VirtualProtectEx(hProcess, pAddress, dwSize, dwProtection, &dwProtect);
	}
}

// stores the assembly to write to the function
const BYTE ShellCode[] = { 0xEB, 0xFE };

// the program entry point
int main()
{
	// stores the process id
	DWORD dwPid;
	// stores the process handle
	HANDLE hProcess;
	// stores the old memory protection
	DWORD dwProtect;
	// stores the external address of unicode create service
	PVOID pCreateServiceW;
	// stores the external address of ansi create service
	PVOID pCreateServiceA;
	// waits for the process to open
	do { dwPid = WinHax::FindProcess("BEService.exe"); } while (!dwPid);
	// notifies the user
	cout << "[GetBE] Process found" << endl;
	// gets a handle to the battleye service
	do { hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid); } while (!hProcess);
	// notifies the user
	cout << "[GetBE] Handle opened" << endl;
	// calculates the address of unicode create service
	pCreateServiceW = WinHax::GetFunctionAddress(hProcess, "Advapi32.dll", CreateServiceW);
	// calculates the address of ansi create service
	pCreateServiceA = WinHax::GetFunctionAddress(hProcess, "Advapi32.dll", CreateServiceA);
	// notifies the user
	cout << "[GetBE] CreateServiceW address: 0x" << hex << pCreateServiceW << endl;
	// notifies the user
	cout << "[GetBE] CreateServiceA address: 0x" << hex << pCreateServiceA << endl;
	// change the protection of the memory region
	if (VirtualProtectEx(hProcess, pCreateServiceW, sizeof(ShellCode), PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		// notifies the user
		cout << "[GetBE] CreateServiceW protection = " << hex << PAGE_EXECUTE_READWRITE << endl;
		// stores the number of bytes written
		SIZE_T dwBytes;
		// writes a return to the memory region
		if (WriteProcessMemory(hProcess, pCreateServiceW, ShellCode, sizeof(ShellCode), &dwBytes))
		{
			// notifies the user
			cout << "[GetBE] Shell Code Written to CreateServiceW"  << endl;
		}
	}
	// change the protection of the memory region
	if (VirtualProtectEx(hProcess, pCreateServiceA, sizeof(ShellCode), PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		// notifies the user
		cout << "[GetBE] CreateServiceA protection = " << hex << PAGE_EXECUTE_READWRITE << endl;
		// stores the number of bytes written
		SIZE_T dwBytes;
		// writes a return to the memory region
		if (WriteProcessMemory(hProcess, pCreateServiceA, ShellCode, sizeof(ShellCode), &dwBytes))
		{
			// notifies the user
			cout << "[GetBE] Shell Code Written to CreateServiceA" << endl;
		}
	}
	// waits for user to exit
	cin.get();
}