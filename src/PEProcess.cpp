#include "PEProcess.h"

PEProcess::PEProcess(DWORD processID)
{
	this->processID = processID;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	processType = IdentifyProcess();

	GetHModules();
}

[[maybe_unused]] PEProcess PEProcess::WaitForProcessAvailability(const char* processName, const int* toCheck)
{
	ProcessType processType = IdentifyProcess();

	DWORD processID = NULL;

	while (processID == NULL && *toCheck)
	{
		if (processType == ProcessType::PROCESS_32)
		{
			processID = GetProcess32(processName);
		}

		if (processID != NULL)
		{
			Sleep(1000);
		}
	}

	if (!*toCheck)
	{
		throw std::exception("Quitting...");
	}

	return PEProcess(processID);
}

[[maybe_unused]] int PEProcess::StillAlive()
{
	DWORD ret = WaitForSingleObject(processHandle, 0);

	return ret == WAIT_TIMEOUT;
}

[[maybe_unused]] void PEProcess::SetModule(const char* moduleName)
{
	std::string name(moduleName);
	std::transform(name.begin(), name.end(), name.begin(), ::tolower);

	if (processType == ProcessType::PROCESS_32)
	{
		if (hModules32.find(name) == hModules32.end())
		{
			throw std::exception("Module not found.");
		}

		currentModuleName = name;
		currentHModule = &hModules32[currentModuleName];
	}
}

[[maybe_unused]] void PEProcess::SetEndianness(EndianType endian)
{
	endianType = endian;
}

[[maybe_unused]] void PEProcess::CheckModule(const std::string& section)
{
	if (currentHModule == nullptr || currentModuleName.empty())
	{
		throw std::exception("No module set.");
	}

	if (currentHModule->sections.find(section) == currentHModule->sections.end())
	{
		throw std::exception("Section not found.");
	}
}

LPVOID PEProcess::CheckAddress(uintptr_t offset, bool directAddress)
{
	if (directAddress)
	{
		return (LPVOID)offset;
	}

	auto moduleBaseAddress = (uintptr_t)currentHModule->hModule.modBaseAddr;
	uintptr_t address = moduleBaseAddress + offset;

	uintptr_t maxModuleAddress = moduleBaseAddress + currentHModule->hModule.modBaseSize;

	// basic insecure check, probably need to fix
	if (address < moduleBaseAddress || address >= maxModuleAddress)
	{
		throw std::exception("Address is out of current module bounds.");
	}

	return (LPVOID)address;
}

[[maybe_unused]] LPVOID PEProcess::ReadMemoryAddressChain(uintptr_t firstAddress, int* offsets, uint16_t offsetCount, EndianType endianFlip)
{
	uintptr_t currentAddress = firstAddress;
	for (uint16_t i = 0; i <= offsetCount; i++)
	{
		LPVOID address = ReadMemoryAddress(currentAddress, currentAddress != firstAddress, endianFlip);
		currentAddress = (uintptr_t)address;

		if (i != offsetCount)
		{
			currentAddress += *offsets++;
		}
	}

	return (LPVOID)currentAddress;
}

[[maybe_unused]] int PEProcess::ReadMemoryStruct(LPVOID address, void* obj, SIZE_T size, int offset)
{
	uintptr_t ptr = (uintptr_t)address + offset;
	auto addr = (LPCVOID)ptr;

	return ReadProcessMemory(processHandle, addr, obj, size, nullptr);
}

[[maybe_unused]] std::string PEProcess::ReadMemoryStringFromAddress(uintptr_t offset, int length, int* result, bool directAddress, EndianType endianness)
{
	LPVOID address = ReadMemoryAddress(offset, false, endianness);
	auto addressConv = (uintptr_t)address;
	std::string str = ReadMemoryString(addressConv, length, result, directAddress);

	return str;
}

[[maybe_unused]] LPVOID PEProcess::ReadMemoryAddress(LPVOID address, EndianType endianness)
{
	return ReadMemoryAddress((uintptr_t)address, true, endianness);
}

LPVOID PEProcess::ReadMemoryAddress(uintptr_t offset, bool directAddress, EndianType endianness)
{
	LPVOID address = CheckAddress(offset, directAddress);

	if (processType == ProcessType::PROCESS_32)
	{
		LPVOID buffer{};
		bool result = ReadProcessMemory(processHandle, address, &buffer, sizeof(buffer), nullptr);

		if (!result)
		{
			throw std::exception("ReadMemoryAddress Failed.");
		}

		if (endianness == EndianType::BIG_ENDIAN || endianType == EndianType::BIG_ENDIAN)
		{
			auto val = (unsigned long long)buffer;

			val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
			val = (val << 16) | (val >> 16);

			buffer = (LPVOID)val;
		}

		return buffer;
	}
	else if (processType == ProcessType::PROCESS_64)
	{

	}

	throw std::exception("Invalid architecture type.");
}

[[maybe_unused]] std::string PEProcess::ReadMemoryString(LPVOID address, int length, int* result, int offset)
{
	if (address == nullptr)
	{
		return "";
	}

	uintptr_t addr = (uintptr_t)address + offset;

	return ReadMemoryString(addr, length, result, true);
}

std::string PEProcess::ReadMemoryString(uintptr_t offset, int length, int* result, bool directAddress)
{
	LPVOID address = CheckAddress(offset, directAddress);

	SIZE_T totalRead = 0;
	std::string str;
	do
	{
		char buffer[256]{};

		SIZE_T read = 0;
		int curResult = ReadProcessMemory(processHandle, address, &buffer, sizeof(buffer), &read);
		totalRead += read;

		if (curResult)
		{
			for (auto c : buffer)
			{
				if (c == '\0')
				{
					return str;
				}

				str += c;
			}

			address = (LPVOID)((unsigned long long)address + read);
		}
		else
		{
			if (result)
			{
				*result = 0;
			}

			return "";
		}
	} while (totalRead < length);

	if (result)
	{
		*result = 1;
	}

	return str;
}

DWORD PEProcess::GetProcess32(const char* processName)
{
	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, processName) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}

	return NULL;
}

ProcessType PEProcess::IdentifyProcess()
{
#if _WIN32
	return ProcessType::PROCESS_32;
#endif

#if _WIN64 // Not implemented so just exit
	exit(-1);
	return ProcessType::PROCESS_64;
#endif
}

void PEProcess::GetHModules()
{
	switch (processType)
	{
		case ProcessType::PROCESS_32:
			GetHModules32();
			break;
		case ProcessType::PROCESS_64:
			break;
	}
}

void PEProcess::GetHModules32()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 moduleEntry32{};
		moduleEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &moduleEntry32))
		{
			do
			{
				ProcessHModule32(moduleEntry32);
			} while (Module32Next(hSnapshot, &moduleEntry32));
		}
		CloseHandle(hSnapshot);
	}
}

void PEProcess::ProcessHModule32(MODULEENTRY32 hModule)
{
	auto addr = (unsigned long long)hModule.modBaseAddr;

	IMAGE_DOS_HEADER dosHeaders{};
	ReadProcessMemory(processHandle, (LPCVOID)addr, &dosHeaders, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (dosHeaders.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}

	addr += dosHeaders.e_lfanew;

	IMAGE_NT_HEADERS ntHeaders{};
	ReadProcessMemory(processHandle, (LPCVOID)addr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr);

	if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		return;
	}

	addr += sizeof(ntHeaders);

	std::map<std::string, IMAGE_SECTION_HEADER> sections;
	for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER section{};
		ReadProcessMemory(processHandle, (LPCVOID)addr, &section, sizeof(IMAGE_SECTION_HEADER), nullptr);

		std::string name(reinterpret_cast<char*>(section.Name));

		sections[name] = section;

		addr += sizeof(IMAGE_SECTION_HEADER);
	}

	std::string name(hModule.szModule);
	std::transform(name.begin(), name.end(), name.begin(), ::tolower);

	HModuleExt32 obj
	{
		hModule = hModule,
		sections = sections,
		dosHeaders = dosHeaders,
		ntHeaders = ntHeaders,
		name = name,
	};

	hModules32[name] = obj;
}
