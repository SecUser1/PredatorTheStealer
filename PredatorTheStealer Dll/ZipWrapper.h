#include <string>
#include <Windows.h>

#include "zip.h"
#include "xor.h"
#include "DynImport.h"

using std::string;	

#pragma once

#define MAXSIZE 104857600
#define MEGABYTE 1048576

class ZipWrapper
{
	HZIP zip;
	void* buff;
	string path;

	void zipFolder(const string & path, const string & dir = "");
public:
	ZipWrapper();
	ZipWrapper(const string & arch);
	ZipWrapper(size_t memory, const string & arch);
	~ZipWrapper();
	void addFileMemory(const string & fileName, const string & data);
	void addFile(const string & fileName, const string & destName);
	void addFolder(const string & folderName);
	void addFolderRecursive(const string & folderName);
	unsigned long data(void ** ret);
};