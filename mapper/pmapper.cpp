#include "pmapper.h"

auto g_mapper::g_memory::get_process_id(const char* name) -> DWORD
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hDump = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hDump, &pe32))
    {
        do {
            if (!strcmp(name, pe32.szExeFile))
            {
                CloseHandle(hDump);
                return pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hDump, &pe32));
    }

    return 0;
}

auto g_mapper::g_memory::get_process(const char* name) -> HANDLE
{
    return OpenProcess(PROCESS_ALL_ACCESS, true, get_process_id(name));
}

auto g_mapper::g_memory::get_module_base(HANDLE process, const char* mod_name) -> uint32_t
{
    MODULEENTRY32 me;
    me.dwSize = sizeof me;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));

    if (!snapshot)
        return 0;

    for (Module32First(snapshot, &me); Module32Next(snapshot, &me);)
    {
        if (!strcmp(me.szModule, mod_name))
            break;
    }

    return reinterpret_cast<uint32_t>(me.modBaseAddr);
}

template<typename T>
T g_mapper::g_memory::read(uintptr_t address)
{
    T buffer;
    ReadProcessMemory(process, LPVOID(address), &buffer, sizeof(buffer), 0);
    return buffer;
}

template<typename T>
void g_mapper::g_memory::write(uintptr_t address, T value)
{
    WriteProcessMemory(process, LPVOID(address), &value, sizeof(value), 0);
}

auto g_mapper::parse_imports(BYTE* allocated_pe, IMAGE_OPTIONAL_HEADER* optional_header) -> void
{
    if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(allocated_pe + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDescr->Name)
        {
            char* szMod = reinterpret_cast<char*>(allocated_pe + pImportDescr->Name);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(allocated_pe + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(allocated_pe + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                {
                    g_Import imp;

                    imp.rva = reinterpret_cast<BYTE*>(reinterpret_cast<BYTE*>(pFuncRef) - allocated_pe);
                    imp.mod_name = szMod;
                    imp.func_name = reinterpret_cast<const char*>(*pThunkRef & 0xFFFF);

                    g_Imports.push_back(imp);
                }
                else
                {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(allocated_pe + (*pThunkRef));

                    g_Import imp;

                    imp.rva = reinterpret_cast<BYTE*>(reinterpret_cast<BYTE*>(pFuncRef) - allocated_pe);
                    imp.mod_name = szMod;
                    imp.func_name = pImport->Name;

                    g_Imports.push_back(imp);
                }
            }

            ++pImportDescr;
        }
    }

    // don't ask

    vector<const char*> g_dlls = { "KERNEL32.dll", "USER32.dll", "VCRUNTIME140.dll", "WS2_32.dll", "ADVAPI32.dll", "MSVCP140.dll", "UCRTBASE.dll", "GDI32.dll", "WININET.dll", "NTDLL.dll", "IMM32.dll", "KERNELBASE.dll", "WINTRUST.dll", "XINPUT_1_4.dll", "SHELL32.dll", "D3DX9_43.dll", "DBGHELP.dll", "DXGI.dll", "COMBASE.dll", "SSPICLI.dll", "api-ms-win-crt-runtime-l1-1-0.dll" };
    vector<const char*> g_final_dlls = { "KERNEL32.DLL", "USER32.dll", "VCRUNTIME140.dll", "WS2_32.dll", "ADVAPI32.dll", "MSVCP140.dll", "ucrtbase.dll", "GDI32.dll", "WININET.dll", "ntdll.dll", "IMM32.DLL", "KERNELBASE.dll", "wintrust.dll", "XInput1_4.dll", "SHELL32.dll", "d3dx9_43.dll", "dbghelp.dll", "dxgi.dll", "combase.dll", "SspiCli.dll", "ucrtbase.dll" };

    for (auto& imp : g_Imports)
    {
        for (int i = 0; i < g_dlls.size(); i++)
        {
            if (strstr(imp.mod_name, g_dlls[i]))
            {
                imp.mod_name = g_final_dlls[i];
            }
            else if (strstr(imp.mod_name, "api-ms"))
            {
                imp.mod_name = "ucrtbase.dll";
            }
        }
    }
}

auto g_mapper::parse_relocs(BYTE* allocated_pe, IMAGE_OPTIONAL_HEADER* optional_header) -> void
{
    if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(allocated_pe + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
        {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
            {
                if (((*pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW))
                {
                    g_Reloc reloc;
                    reloc.rva = reinterpret_cast<BYTE*>(pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));

                    g_Relocs.push_back(reloc);
                }
            }

            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }
}

#pragma section(".mapper")
auto g_mapper::processing() -> void
{
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(binary)->e_magic != 0x5a4d)
        return;

    // anti-hook

    {
        uint32_t wrm = reinterpret_cast<uint32_t>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtWriteVirtualMemory"));
        BYTE data = *(BYTE*)wrm;

        if (data != 0xB8)
        {
            MessageBoxA(NULL, "injection failed [0]", "error", MB_ICONERROR);
            return;
        }
    }

    {
        uint32_t wrm = reinterpret_cast<uint32_t>(GetProcAddress(LoadLibraryA("kernel32.dll"), "WriteProcessMemory"));
        BYTE data = *(BYTE*)wrm;

        if (data != 0x8B)
        {
            MessageBoxA(NULL, "injection failed [1]", "error", MB_ICONERROR);
            return;
        }
    }

    // parsing sections data

    IMAGE_NT_HEADERS* nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(binary + reinterpret_cast<IMAGE_DOS_HEADER*>(binary)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
    IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;

    // allocating image data with pe header

    BYTE* allocated_pe = reinterpret_cast<BYTE*>(VirtualAlloc(0, optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!allocated_pe)
        return;

    // writing data only for pe header

    if (!WriteProcessMemory(GetCurrentProcess(), allocated_pe, binary, 0x1000, nullptr))
    {
        VirtualFree(allocated_pe, 0, MEM_RELEASE);
        return;
    }

    // writing sections data

    {
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(nt_header);
        for (UINT i = 0; i != file_header->NumberOfSections; ++i, ++pSectionHeader)
        {
            if (pSectionHeader->SizeOfRawData)
            {
                if (!WriteProcessMemory(GetCurrentProcess(), allocated_pe + pSectionHeader->VirtualAddress, binary + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
                {
                    VirtualFree(allocated_pe, 0, MEM_RELEASE);
                    return;
                }
            }
        }
    }

    // creating junk pe header bytes

    unsigned char junk[0x1000];

    for (int i = 0; i < 0x1000; i++)
    {
        if (binary[i] == 0x00)
            junk[i] = binary[i + 1] + rand();
        else
            junk[i] = binary[i - 1] - time(0);
    }

    // allocating image data without pe headers

    BYTE* allocated = reinterpret_cast<BYTE*>(VirtualAllocEx(process, 0, optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!allocated)
        return;

    // writing junk pe header data code

    if (!WriteProcessMemory(process, allocated, junk, 0x1000, nullptr))
    {
        VirtualFreeEx(process, allocated, 0, MEM_RELEASE);
        return;
    }

    // writing sections data

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(nt_header);
    for (UINT i = 0; i != file_header->NumberOfSections; ++i, ++pSectionHeader)
    {
        if (pSectionHeader->SizeOfRawData)
        {
            if (!WriteProcessMemory(process, allocated + pSectionHeader->VirtualAddress, binary + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
            {
                VirtualFreeEx(process, allocated, 0, MEM_RELEASE);
                return;
            }
        }
    }

    // parsing imports to fix

    parse_imports(allocated_pe, optional_header);

    // fixing iat addresses

    for (auto& imp : g_Imports)
    {
        const LPVOID nt_open_file = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtOpenFile");
        if (nt_open_file)
        {
            char original_bytes[5];
            memcpy(original_bytes, nt_open_file, 5);
            WriteProcessMemory(process, nt_open_file, original_bytes, 5, nullptr);
        }

        auto* loc = VirtualAllocEx(process, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(process, loc, imp.mod_name, strlen(imp.mod_name) + 1, nullptr);
        auto* const h_thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);

        if (h_thread) CloseHandle(h_thread);

        uint32_t address = reinterpret_cast<uint32_t>(imp.rva + (uint32_t)allocated);
        uint32_t address_rva = (uint32_t)GetProcAddress(LoadLibraryA(imp.mod_name), imp.func_name) - (uint32_t)LoadLibraryA(imp.mod_name);

        g_memory::write<uint32_t>(address, (uint32_t)(address_rva + g_memory::get_module_base(process, imp.mod_name)));
    }

    // parsing relocs to fix

    parse_relocs(allocated_pe, optional_header);

    // fixing relocs addresses

    uint32_t reloc_delta = (uint32_t)allocated - optional_header->ImageBase;

    for (auto& reloc : g_Relocs)
    {
        uint32_t address = reinterpret_cast<uint32_t>(reloc.rva + (uint32_t)allocated);
        uint32_t input = g_memory::read<uint32_t>(address);

        g_memory::write<uint32_t>(address, (uint32_t)(input + reloc_delta));
    }

    DWORD dwOldProtect;

    // https://github.com/auth12/loader/blob/master/client/src/injection/mapper.cpp#L131

    static std::vector<uint8_t> shellcode = { 0x55, 0x89, 0xE5, 0x6A, 0x00, 0x6A, 0x01, 0x68, 0xEF, 0xBE,
    0xAD, 0xDE, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0, 0x89, 0xEC, 0x5D, 0xC3 };

    // setting shellcode addresses

    *reinterpret_cast<uint32_t*>(&shellcode[8]) = (uint32_t)allocated;
    *reinterpret_cast<uint32_t*>(&shellcode[13]) = (uint32_t)allocated + optional_header->AddressOfEntryPoint;

    // allocating memory for shellcode

    BYTE* allocated_shellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(process, 0, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!allocated_shellcode)
        return;

    // writing shellcode

    if (!WriteProcessMemory(process, allocated_shellcode, shellcode.data(), shellcode.size(), nullptr))
    {
        VirtualFree(allocated_shellcode, 0, MEM_RELEASE);
        return;
    }

    // creating shellcode thread

    HANDLE shellcode_thread = CreateRemoteThread(process, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(allocated_shellcode), 0, 0, 0);

    if (!shellcode_thread)
        return;

    // detaching thread

    CloseHandle(shellcode_thread);
    Sleep(2500);

    // clearing memory

    VirtualProtectEx(process, allocated, IMAGE_FIRST_SECTION(nt_header)->VirtualAddress, PAGE_READONLY, &dwOldProtect);

    WriteProcessMemory(GetCurrentProcess(), allocated_pe, 0x0, optional_header->SizeOfImage, 0);
    VirtualFree(allocated_pe, 0, MEM_RELEASE);

    WriteProcessMemory(process, allocated_shellcode, 0x0, shellcode.size(), 0);
    VirtualFreeEx(process, allocated_shellcode, 0, MEM_RELEASE);

    // detaching process

    CloseHandle(process);
}