#include "PEProcess.h"

PEProcess::PEProcess(DWORD processID)
{
    this->processID = processID;

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    processType = IdentifyProcess();

    GetHModules();
}

PEProcess PEProcess::WaitForProcessAvailability(const wchar_t* processName, int* toCheck)
{
    ProcessType processType = IdentifyProcess();

    DWORD processID = NULL;

    while (processID == NULL && *toCheck)
    {
        processID = GetProcess(processName);

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

int PEProcess::StillAlive()
{
    DWORD ret = WaitForSingleObject(processHandle, 0);

    return ret == WAIT_TIMEOUT;
}

void PEProcess::SetModule(const wchar_t* moduleName)
{
    std::wstring name(moduleName);
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    if (hModules32.find(name) == hModules32.end())
    {
        throw std::exception("Module not found.");
    }

    currentModuleName = &name;
    currentHModule = &hModules32[name];
}

void PEProcess::SetEndianness(EndianType endian)
{
    endianType = endian;
}

void PEProcess::CheckModule(std::string section)
{
    if (currentHModule == nullptr || currentModuleName == nullptr || currentModuleName->empty())
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
    if (currentHModule == nullptr)
    {
        throw std::exception("SetModule was not run/is invalid.");
    }

    if (directAddress)
    {
        return (LPVOID)offset;
    }

    uintptr_t moduleBaseAddress = (uintptr_t)currentHModule->hModule.modBaseAddr;
    uintptr_t address = moduleBaseAddress + offset;

    uintptr_t maxModuleAddress = moduleBaseAddress + currentHModule->hModule.modBaseSize;

    // basic insecure check, probably need to fix
    if (address < moduleBaseAddress || address >= maxModuleAddress)
    {
        throw std::exception("Address is out of current module bounds.");
    }

    return (LPVOID)address;
}

LPVOID PEProcess::ReadMemoryAddressChain(uintptr_t firstAddress, int* offsets, uint16_t offsetCount, EndianType endianFlip)
{
    uintptr_t currentAddress = firstAddress;
    for (uint16_t i = 0; i <= offsetCount; i++)
    {
        LPVOID address = ReadMemoryAddress(currentAddress, currentAddress == firstAddress ? 0 : 1, endianFlip);
        currentAddress = (uintptr_t)address;

        if (i != offsetCount)
        {
            currentAddress += *offsets++;
        }
    }

    return (LPVOID)currentAddress;
}

int PEProcess::ReadMemoryStruct(LPVOID address, void* obj, SIZE_T size, int offset)
{
    uintptr_t ptr = (uintptr_t)address + offset;
    LPCVOID addr = (LPCVOID)ptr;

    return ReadProcessMemory(processHandle, addr, obj, size, NULL);
}

std::string PEProcess::ReadMemoryStringFromAddress(uintptr_t offset, int length, int* result, bool directAddress, EndianType endianness)
{
    LPVOID address = ReadMemoryAddress(offset, 0, endianness);
    uintptr_t addressConv = (uintptr_t)address;
    std::string str = ReadMemoryString(addressConv, length, result, directAddress);

    return str;
}

LPVOID PEProcess::ReadMemoryAddress(LPVOID address, EndianType endianness)
{
    return ReadMemoryAddress((uintptr_t)address, 1, endianness);
}

LPVOID PEProcess::ReadMemoryAddress(uintptr_t offset, bool directAddress, EndianType endianness)
{
    LPVOID address = CheckAddress(offset, directAddress);

    if (processType == ProcessType::PROCESS_32)
    {
        LPVOID buffer{};
        bool result = ReadProcessMemory(processHandle, address, &buffer, sizeof(buffer), NULL);

        if (endianness == EndianType::BIG_ENDIAN || endianType == EndianType::BIG_ENDIAN)
        {
            unsigned long val = (unsigned long)buffer;

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

std::string PEProcess::ReadMemoryString(LPVOID address, SIZE_T length, int* result, int offset)
{
    if (address == 0)
    {
        return "";
    }

    uintptr_t addr = (uintptr_t)address + offset;

    return ReadMemoryString(addr, length, result, 1);
}

std::string PEProcess::ReadMemoryString(uintptr_t offset, SIZE_T length, int* result, bool directAddress)
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

            address = (LPVOID)((unsigned long)address + read);
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

DWORD PEProcess::GetProcess(const wchar_t* processName)
{
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    HANDLE hProcess = nullptr;
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, processName) == 0)
            {
                return entry.th32ProcessID;
            }
        }
    }

    return NULL;
}

ProcessType PEProcess::IdentifyProcess()
{
#if _WIN64
    return ProcessType::PROCESS_64;
#endif

#if _WIN32
    return ProcessType::PROCESS_32;
#endif
}

void PEProcess::GetHModules()
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
                ProcessHModule(moduleEntry32);
            } while (Module32Next(hSnapshot, &moduleEntry32));
        }
        CloseHandle(hSnapshot);
    }
}

void PEProcess::ProcessHModule(MODULEENTRY32W hModule)
{
    unsigned long long addr = (unsigned long long)hModule.modBaseAddr;

    IMAGE_DOS_HEADER dosHeaders{};
    ReadProcessMemory(processHandle, (LPCVOID)addr, &dosHeaders, sizeof(IMAGE_DOS_HEADER), 0);
    if (dosHeaders.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return;
    }

    addr += dosHeaders.e_lfanew;

    IMAGE_NT_HEADERS ntHeaders{};
    ReadProcessMemory(processHandle, (LPCVOID)addr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), 0);

    if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        return;
    }

    addr += sizeof(ntHeaders);

    std::map<std::string, IMAGE_SECTION_HEADER> sections;
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER section{};
        ReadProcessMemory(processHandle, (LPCVOID)addr, &section, sizeof(IMAGE_SECTION_HEADER), 0);

        std::string name(reinterpret_cast<char*>(section.Name));

        sections[name] = section;

        addr += sizeof(IMAGE_SECTION_HEADER);
    }

    std::wstring name(hModule.szModule);
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    HModuleExt32 obj
    {
        dosHeaders = dosHeaders,
        ntHeaders = ntHeaders,
        hModule = hModule,
        name = name,
        sections = sections
    };

    hModules32[name] = obj;
}
