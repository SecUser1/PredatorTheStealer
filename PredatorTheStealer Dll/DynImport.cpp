#include <Windows.h>
#include <winternl.h>

#include "prototypes.h"
#include "DynImport.h"

char *_strchr(char *s, char c)
{
	char *ret = s;

	do
	{
		if (*ret == c) break;
		ret++;
	} while (*ret);

	return (*ret == c) ? ret : NULL;
}

unsigned int hash_uppercaseW(const wchar_t * wstring)
{
	unsigned int hash = 0;
	wchar_t* p = (wchar_t*)wstring;
	while (*p != NULL)
	{
		hash ^= (hash << 5) + (hash >> 2) + ((*p >= 'a' && *p <= 'z') ? *p - 0x20 : *p);
		p++;
	}

	return hash;
}

HMODULE get_kernel32_handle()
{
	try
	{
		PPEB peb = (PPEB)__readfsdword(XorInt(0x30));

		typedef struct _LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY     LoadOrder;
			LIST_ENTRY     MemoryOrder;
			LIST_ENTRY     InitializationOrder;
			PVOID          ModuleBaseAddress;
			PVOID          EntryPoint;
			ULONG          ModuleSize;
			UNICODE_STRING FullModuleName;
			UNICODE_STRING ModuleName;
			ULONG          Flags;
			USHORT         LoadCount;
			USHORT         TlsIndex;
			union
			{
				LIST_ENTRY Hash;
				struct
				{
					PVOID SectionPointer;
					ULONG CheckSum;
				};
			};
			ULONG TimeStamp;
		} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

		LIST_ENTRY* headEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
		PLDR_DATA_TABLE_ENTRY data;
		for (LIST_ENTRY* listEntry = headEntry; listEntry != headEntry->Blink; listEntry = listEntry->Flink)
		{
			data = (PLDR_DATA_TABLE_ENTRY)((PBYTE)listEntry - XorInt(8));
			if (hash_uppercaseW(data->ModuleName.Buffer) == XorInt(0xE131018A))
				return (HMODULE)data->ModuleBaseAddress;
		}
		return (HMODULE)0;
	}
	catch (...) { return (HMODULE)0; }
}

HMODULE get_module_handle(const char* moduleName)
{
	try
	{
		typedef HMODULE(WINAPI *pGetModuleHandle)(LPCSTR lpModuleName);
		return ((pGetModuleHandle)(get_proc_address(get_kernel32_handle(), XorStr("GetModuleHandleA"))))(moduleName);
	}
	catch (...) { return (HMODULE)0; }
}

void* get_proc_address(HMODULE module, const char* proc_name)
{
	try
	{
		char* modb = (char*)module;

		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)modb;
		IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(modb + dos_header->e_lfanew);
		IMAGE_OPTIONAL_HEADER* opt_header = &nt_headers->OptionalHeader;
		IMAGE_DATA_DIRECTORY* exp_entry = (IMAGE_DATA_DIRECTORY*)(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		IMAGE_EXPORT_DIRECTORY* exp_dir = (IMAGE_EXPORT_DIRECTORY*)(modb + exp_entry->VirtualAddress);
		void** func_table = (void**)(modb + exp_dir->AddressOfFunctions);
		WORD* ord_table = (WORD*)(modb + exp_dir->AddressOfNameOrdinals);
		char** name_table = (char**)(modb + exp_dir->AddressOfNames);
		void* address = NULL;

		DWORD i;
		if (((DWORD)proc_name >> XorInt(16)) == 0)
		{
			WORD ordinal = LOWORD(proc_name);
			DWORD ord_base = exp_dir->Base;
			if (ordinal < ord_base || ordinal > ord_base + exp_dir->NumberOfFunctions)
				return NULL;
			address = (void*)(modb + (DWORD)func_table[ordinal - ord_base]);
		}
		else
		{
			for (i = 0; i < exp_dir->NumberOfNames; ++i)
				if (strcmp(proc_name, modb + (DWORD)name_table[i]) == 0)
					address = (void*)(modb + (DWORD)func_table[ord_table[i]]);
		}

		if ((char*)address >= (char*)exp_dir && (char*)address < (char*)exp_dir + exp_entry->Size)
		{
			char* dll_name = _strdup((char*)address);
			if (!dll_name)
				return NULL;
			address = NULL;
			char* func_name = _strchr(dll_name, '.');
			*func_name++ = 0;

			HMODULE frwd_module = get_module_handle(dll_name);
			if (!frwd_module)
				frwd_module = LoadLibraryA(dll_name);
			else
				address = get_proc_address(frwd_module, func_name);

			free(dll_name);
		}

		return address;
	}
	catch (...) { return 0; }
}

ULONG_PTR dyn_call(char* dll, const char* func)
{
	try
	{
		HMODULE module = get_module_handle((const char*)dll);
		if (!module)
		{
			module = LoadLibraryA(dll);
			if (!module)
				return 0;
		}

		return (ULONG_PTR)get_proc_address(module, func);
	}
	catch (...) { return 0; }
}