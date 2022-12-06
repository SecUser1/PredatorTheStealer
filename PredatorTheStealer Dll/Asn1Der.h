#pragma once
#include <vector>
#include <string>

#include "xor.h"
#define XOR(x) XorStr(x)

using std::string;
using std::vector;

typedef unsigned char byte;

enum Type
{
	Sequence = 48,
	Integer = 2,
	BitString,
	OctetString,
	Null,
	ObjectIdentifier
};

class Asn1DerObject
{
public:
	int Length;
	vector<Asn1DerObject> objects;
	vector<byte> Data;

	Asn1DerObject()
	{
		objects = vector<Asn1DerObject>();
		Length = 0;
	}
};

class Asn1Der
{
	void ArrayCopy(const vector<byte> & src, int sourceIndex, vector<byte> & dest, int destIndex, int length) const
	{
		try
		{
			while (length--) dest[destIndex++] = src[sourceIndex++];
		}
		catch (...) { return; }
	}
public:
	const Asn1DerObject Parse(const vector<byte> & dataToParse) const
	{
		try
		{
			Asn1DerObject asn1DerObject;
			for (int i = 0; i < dataToParse.size(); ++i)
			{
				Type type = (Type)dataToParse[i];
				if (type == Type::Integer || type == Type::OctetString || type == Type::ObjectIdentifier)
				{
					Asn1DerObject obj;
					obj.Length = (int)dataToParse[i + 1];
					asn1DerObject.objects.push_back(obj);
					vector<byte> arr((unsigned int)dataToParse[i + 1]);
					int length;
					if (i + 2 + (int)dataToParse[i + 1] > dataToParse.size())
						length = dataToParse.size() - (i + 2);
					else
						length = (int)dataToParse[i + 1];
					ArrayCopy(dataToParse, i + 2, arr, 0, length);
					asn1DerObject.objects[asn1DerObject.objects.size() - 1].Data = arr;
					i = i + 1 + asn1DerObject.objects[asn1DerObject.objects.size() - 1].Length;
				}
				else if (type == Type::Sequence)
				{					
					vector<byte> arr;
					if (asn1DerObject.Length == 0)
					{
						asn1DerObject.Length = dataToParse.size() - (i + 2);
						arr = vector<byte>(asn1DerObject.Length);
					}
					else
					{
						Asn1DerObject obj;
						obj.Length = (int)dataToParse[i + 1];
						asn1DerObject.objects.push_back(obj);
						arr = vector<byte>((int)dataToParse[i + 1]);
					}

					int num;
					if (arr.size() > dataToParse.size() - (i + 2))
						num = dataToParse.size() - (i + 2);
					else
						num = arr.size();
					ArrayCopy(dataToParse, i + 2, arr, 0, arr.size());
					asn1DerObject.objects.push_back(this->Parse(arr));
					i = i + 1 + (int)dataToParse[i + 1];
				}
			}

			return asn1DerObject;
		}
		catch (...) { return Asn1DerObject(); }
	}
};
