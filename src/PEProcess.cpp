#include "PEProcess.h"

PEProcess::PEProcess(DWORD processID)
{
    this->processID = processID;

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    processType = IdentifyProcess();

    GetHModules();
}

PEProcess PEProcess::WaitForProcessAvailability(wchar_t* processName)
{
    ProcessType processType = IdentifyProcess();

    DWORD processID = NULL;

    while (processID == NULL)
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

    return PEProcess(processID);
}

void PEProcess::SetModule(wchar_t* moduleName)
{
    std::wstring name(moduleName);
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    if (processType == ProcessType::PROCESS_32)
    {
        if (hModules32.find(name) == hModules32.end())
        {
            throw new std::exception("Module not found.");
        }

        currentModuleName = &name;
        currentHModule = &hModules32[name];
    }
}

void PEProcess::CheckModule(std::string section)
{
    if (currentHModule == nullptr || currentModuleName == nullptr || currentModuleName->empty())
    {
        throw new std::exception("No module set.");
    }

    if (currentHModule->sections.find(section) == currentHModule->sections.end())
    {
        throw new std::exception("Section not found.");
    }
}

LPVOID PEProcess::CheckAddress(uintptr_t offset)
{
    uintptr_t moduleBaseAddress = (uintptr_t)currentHModule->hModule.modBaseAddr;
    uintptr_t address = moduleBaseAddress + offset;

    uintptr_t maxModuleAddress = moduleBaseAddress + currentHModule->hModule.modBaseSize;

    // basic insecure check, probably need to fix
    if (address < moduleBaseAddress || address >= maxModuleAddress)
    {
        throw new std::exception("Address is out of current module bounds.");
    }

    return (LPVOID)address;
}

std::string PEProcess::ReadMemoryString(uintptr_t offset, int amount)
{
    LPVOID address = CheckAddress(offset);

    int totalRead = 0;
    std::string str;
    do
    {
        char buffer[256]{};

        SIZE_T read = 0;
        bool result = ReadProcessMemory(processHandle, address, &buffer, sizeof(buffer), &read);
        totalRead += read;

        if (result)
        {
            str += buffer;
        }
        else
        {
            throw new std::exception("Error reading memory.");
        }
    } while (totalRead < amount);

    return str;
}

DWORD PEProcess::GetProcess32(wchar_t* processName)
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

void PEProcess::ProcessHModule32(MODULEENTRY32W hModule)
{
    unsigned long addr = (unsigned long)hModule.modBaseAddr;

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
