#include "ByteHelper.h"

vector<byte> ConvertHexStringToByteArray(const string & hexString)
{
	try
	{
		if (hexString.size() % 2 != 0)
			return vector<byte>();
		vector<byte> arr(hexString.size() / 2);
		for (int i = 0; i < arr.size(); ++i)
		{
			string s = hexString.substr(i * 2, 2);
			arr[i] = StringToInt(s);
		}
		return arr;
	}
	catch (...) { return vector<byte>(); }
}

int StringToInt(const string & str)
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