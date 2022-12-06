#pragma once
#include <string>
#include <vector>

using std::string;
using std::vector;

typedef unsigned char byte;

vector<byte> ConvertHexStringToByteArray(const string & hexString);

int StringToInt(const string & str);