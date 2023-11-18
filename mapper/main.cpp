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


int main()
{
    vector<uint8_t> binary{};
    open_binary("hake.dll", binary);

    HANDLE procces = g_mapper::g_memory::get_process("");

    g_mapper::process = procces;
    g_mapper::binary = binary.data();
    g_mapper::binary_size = binary.size();

    g_mapper::processing();

    Sleep(0xFFFFFFFF);
}
