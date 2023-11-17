#pragma once

#include <iostream>
#include <windows.h>

#include <Psapi.h>
#include <signal.h>
#include <Shlwapi.h>
#include <winternl.h>

#include <tlhelp32.h>
#include <vector>

using namespace std;

namespace g_mapper
{
	namespace g_memory
	{
		auto get_process_id(const char* name) -> DWORD;
		auto get_process(const char* name) -> HANDLE;
		auto get_module_base(HANDLE process, const char* mod_name) -> uint32_t;

		template<typename T>
		T read(uintptr_t address);

		template<typename T>
		void write(uintptr_t address, T value);
	}

	inline HANDLE process;
	inline BYTE* binary;
	inline size_t binary_size;

	struct g_Import
	{
		const char* mod_name;
		const char* func_name;
		BYTE* rva;
	};

	struct g_Reloc
	{
		BYTE* rva;
	};

	inline vector<g_Import> g_Imports;
	inline vector<g_Reloc> g_Relocs;

	auto parse_imports(BYTE* allocated_pe, IMAGE_OPTIONAL_HEADER* optional_header) -> void;
	auto parse_relocs(BYTE* allocated_pe, IMAGE_OPTIONAL_HEADER* optional_header) -> void;
	auto processing() -> void;
}