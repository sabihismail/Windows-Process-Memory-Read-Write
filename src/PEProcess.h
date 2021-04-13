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

enum class EndianType
{
	LITTLE_ENDIAN,
	BIG_ENDIAN
};

class PEProcess
{
public:
	PEProcess(DWORD processID);
	static PEProcess WaitForProcessAvailability(wchar_t* processName, int* toCheck);
	int StillAlive();
	void SetModule(wchar_t* moduleName);
	void SetEndianness(EndianType endian);
	LPVOID ReadMemoryAddressChain(uintptr_t firstAddress, int* offsets, uint16_t offsetCount, EndianType endianFlip = EndianType::LITTLE_ENDIAN);
	std::string ReadMemoryStringFromAddress(uintptr_t offset, int amount = 32, int directAddress = 0, EndianType endianFlip = EndianType::LITTLE_ENDIAN);
	LPVOID ReadMemoryAddress(LPVOID address, EndianType endian = EndianType::LITTLE_ENDIAN);
	LPVOID ReadMemoryAddress(uintptr_t offset, int directAddress = 0, EndianType endian = EndianType::LITTLE_ENDIAN);
	std::string ReadMemoryString(LPVOID address, int length = 32);
	std::string ReadMemoryString(uintptr_t offset, int length = 32, int directAddress = 0);
	int ReadMemoryStruct(LPVOID address, void* obj, SIZE_T size);

private:
	wchar_t* processName;
	DWORD processID;
	HANDLE processHandle;
	ProcessType processType;
	EndianType endianType = EndianType::LITTLE_ENDIAN;
	std::map<std::wstring, HModuleExt32> hModules32;

	std::wstring* currentModuleName;
	HModuleExt32* currentHModule = nullptr;

	static ProcessType IdentifyProcess();
	static DWORD GetProcess32(wchar_t* processName);
	void CheckModule(std::string section);
	LPVOID CheckAddress(uintptr_t address, int directAddress);
	void GetHModules();
	void GetHModules32();
	void ProcessHModule32(MODULEENTRY32W hModule);
};
