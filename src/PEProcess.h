#pragma once

#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <exception>

struct HModuleExt32
{
	IMAGE_DOS_HEADER dosHeaders;
	IMAGE_NT_HEADERS ntHeaders;
	MODULEENTRY32W hModule;
	std::wstring name;
	std::map<std::string, IMAGE_SECTION_HEADER> sections;
};

enum class ProcessType
{
	PROCESS_32,
	PROCESS_64
};

class PEProcess
{
public:
	PEProcess(DWORD processID);
	static PEProcess WaitForProcessAvailability(wchar_t* processName);
	void SetModule(wchar_t* moduleName);
	std::string ReadMemoryString(uintptr_t offset, int amount = 32);

private:
	wchar_t* processName;
	DWORD processID;
	HANDLE processHandle;
	ProcessType processType;
	std::map<std::wstring, HModuleExt32> hModules32;

	std::wstring* currentModuleName;
	HModuleExt32* currentHModule = nullptr;

	static ProcessType IdentifyProcess();
	static DWORD GetProcess32(wchar_t* processName);
	void CheckModule(std::string section);
	LPVOID CheckAddress(uintptr_t offset);
	void GetHModules();
	void GetHModules32();
	void ProcessHModule32(MODULEENTRY32W hModule);
};
