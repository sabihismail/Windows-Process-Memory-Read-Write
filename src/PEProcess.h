#pragma once

#include <Windows.h>
#include <tchar.h>
#include <cstdio>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <exception>

struct HModuleExt32
{
	MODULEENTRY32 hModule;
	std::map<std::string, IMAGE_SECTION_HEADER> sections;

	[[maybe_unused]] IMAGE_DOS_HEADER dosHeaders;
	[[maybe_unused]] IMAGE_NT_HEADERS ntHeaders;
	[[maybe_unused]] std::string name;
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

class [[maybe_unused]] PEProcess
		{
		public:
			explicit PEProcess(DWORD processID);
			std::string ReadMemoryString(uintptr_t offset, int length = 32, int* result = nullptr, bool directAddress = false);
			LPVOID ReadMemoryAddress(uintptr_t offset, bool directAddress = false, EndianType endian = EndianType::LITTLE_ENDIAN);

			[[maybe_unused]] static PEProcess WaitForProcessAvailability(const char* processName, const int* toCheck);
			[[maybe_unused]] int StillAlive();
			[[maybe_unused]] void SetModule(const char* moduleName);
			[[maybe_unused]] void SetEndianness(EndianType endian);
			[[maybe_unused]] LPVOID ReadMemoryAddressChain(uintptr_t firstAddress, int* offsets, uint16_t offsetCount, EndianType endianFlip = EndianType::LITTLE_ENDIAN);
			[[maybe_unused]] std::string ReadMemoryStringFromAddress(uintptr_t offset, int length = 32, int* result = nullptr, bool directAddress = false, EndianType endianFlip = EndianType::LITTLE_ENDIAN);
			[[maybe_unused]] LPVOID ReadMemoryAddress(LPVOID address, EndianType endian = EndianType::LITTLE_ENDIAN);
			[[maybe_unused]] std::string ReadMemoryString(LPVOID address, int length = 32, int* result = nullptr, int offset = 0);
			[[maybe_unused]] int ReadMemoryStruct(LPVOID address, void* obj, SIZE_T size, int offset = 0);

			template<class T>
			[[maybe_unused]] T ReadMemoryStruct(LPVOID address, int offset = 0, int* success = nullptr);

		private:
			[[maybe_unused]] wchar_t* processName{};
			DWORD processID;
			HANDLE processHandle;
			ProcessType processType;
			EndianType endianType = EndianType::LITTLE_ENDIAN;
			std::map<std::string, HModuleExt32> hModules32;

			std::string currentModuleName{};
			HModuleExt32* currentHModule = nullptr;

			static ProcessType IdentifyProcess();
			static DWORD GetProcess32(const char* processName);

	[[maybe_unused]] void CheckModule(const std::string& section);
			LPVOID CheckAddress(uintptr_t address, bool directAddress);
			void GetHModules();
			void GetHModules32();
			void ProcessHModule32(MODULEENTRY32 hModule);
		};

template<class T>
		[[maybe_unused]] T PEProcess::ReadMemoryStruct(LPVOID address, int offset, int* success)
		{
			T obj{};

			uintptr_t ptr = (uintptr_t)address + offset;
			auto addr = (LPCVOID)ptr;

			int result = ReadProcessMemory(processHandle, addr, &obj, sizeof(T), nullptr);

			if (success)
			{
				*success = result;
			}

			return obj;
		}
