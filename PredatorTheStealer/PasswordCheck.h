#pragma once
#include <string>

using std::string;

class PasswordCheck
{
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
				res += temp * (1 << (4 * (str.size() - i - 1)));
			}
			return res;
		}
		catch (...) { return 0; }
	}
public:
	string EntrySalt;
	string Passwordcheck;

	PasswordCheck(const string & DataToParse)
	{
		try
		{
			int entrySaltLen = StringToInt(DataToParse.substr(2, 2)) * 2;
			this->EntrySalt = DataToParse.substr(6, entrySaltLen);
			int left = DataToParse.size() - (entrySaltLen + 6 + 36);
			this->Passwordcheck = DataToParse.substr(10 + entrySaltLen + left);
		}
		catch (...) { return; }
	}
};