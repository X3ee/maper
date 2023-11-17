#include <iostream>
#include <windows.h>

#include <fstream>
#include <sstream>
#include <algorithm>

#include <tlhelp32.h>
#include <vector>

#include "pmapper.h"

using namespace std;

auto open_binary(std::string m_sSource, std::vector< std::uint8_t >& m_aData) -> void
{
    std::ifstream m_strFile(m_sSource, std::ios::binary);
    m_strFile.unsetf(std::ios::skipws);
    m_strFile.seekg(0, std::ios::end);

    const auto m_iSize = m_strFile.tellg();

    m_strFile.seekg(0, std::ios::beg);
    m_aData.reserve(static_cast<uint32_t>(m_iSize));
    m_aData.insert(m_aData.begin(), std::istream_iterator< std::uint8_t >(m_strFile), std::istream_iterator< std::uint8_t >());
    m_strFile.close();
}


void memory_scan(MEMORY_BASIC_INFORMATION mbi)
{
	/*lazy*/if ((mbi.State & MEM_COMMIT))
		MessageBox(nullptr, "DLL PAGE DETECT 1", "ERROR", MB_ICONERROR);
	/*lazy*/if (mbi.State & MEM_RELEASE)
		MessageBox(nullptr, "ATTEMPTED 2", "ERROR", MB_ICONERROR);
	/*lazy*/if (mbi.Type == MEM_IMAGE)
		MessageBox(nullptr, "DLL PAGE DETECT 3", "ERROR", MB_ICONERROR);
	/*lazy*/if (mbi.Protect == PAGE_NOACCESS || mbi.Protect & PAGE_GUARD)
		MessageBox(nullptr, "DLL PAGE DETECT 4 ", "ERROR", MB_ICONERROR);
	/*lazy*/if (mbi.Protect == PAGE_EXECUTE_READWRITE)
		MessageBox(nullptr, "DLL PAGE DETECT 5", "ERROR", MB_ICONERROR);
	/*lazy*/if (mbi.State == PAGE_EXECUTE_READWRITE)
		MessageBox(nullptr, "DLL PAGE DETECT 5", "ERROR", MB_ICONERROR);

	SYSTEM_INFO sys_information;
	GetSystemInfo(&sys_information);

	PBYTE pCurAddr = (PBYTE)sys_information.lpMinimumApplicationAddress;
	PBYTE pMaxAddr = (PBYTE)sys_information.lpMaximumApplicationAddress;




}
MEMORY_BASIC_INFORMATION mbi;
int main()
{
	memory_scan(mbi);

    vector<uint8_t> binary{};
    open_binary("hake.dll", binary);

    HANDLE procces = g_mapper::g_memory::get_process("");

    g_mapper::process = procces;
    g_mapper::binary = binary.data();
    g_mapper::binary_size = binary.size();

    g_mapper::processing();

    Sleep(0xFFFFFFFF);
}