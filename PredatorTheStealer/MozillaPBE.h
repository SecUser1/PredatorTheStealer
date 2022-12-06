#pragma once
#include <string>
#include <vector>

#include "sha.h"
#include "hmac.h"

using std::string;
using std::vector;

typedef unsigned char byte;

class MozillaPBE
{
	vector<byte> SHA1Compute(const vector<byte> & buffer) const
	{
		try
		{
			uint8_t key[SHA_DIGEST_LENGTH];
			SHA1_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, buffer.data(), buffer.size());
			SHA1_Final(key, &ctx);
			vector<byte> res;
			for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
				res.push_back(key[i]);
			return res;
		}
		catch (...) { return vector<byte>(); }
	}

	vector<byte> HMACCompute(const vector<byte> & buffer, const vector<byte> & key) const
	{
		try
		{
			unsigned char buf[200];
			size_t size = 200;
			vector<byte> res;
			hmac_sha1(key.data(), key.size(), buffer.data(), buffer.size(), (uint8_t*)buf, &size);
			for (int i = 0; i < size; ++i)
				res.push_back(buf[i]);
			return res;
		}
		catch (...) { return vector<byte>(); }
	}
	
	void ArrayCopy(const vector<byte> & src, int sourceIndex, vector<byte> & dest, int destIndex, int length) const
	{
		try
		{
			while (length--) dest[destIndex++] = src[sourceIndex++];
		}
		catch (...) { return; }
	}
public:
	vector<byte> GlobalSalt;
	vector<byte> MasterPassword;
	vector<byte> EntrySalt;
	vector<byte> Key;
	vector<byte> IV;

	MozillaPBE(const vector<byte> & GlobalSalt, const vector<byte> & MasterPassword, const vector<byte> & EntrySalt)
	{
		try
		{
			this->GlobalSalt = GlobalSalt;
			this->MasterPassword = MasterPassword;
			this->EntrySalt = EntrySalt;
		}
		catch (...) { return; }
	}

	void Compute()
	{
		try
		{
			vector<byte> arr(this->GlobalSalt.size() + this->MasterPassword.size());
			ArrayCopy(this->GlobalSalt, 0, arr, 0, this->GlobalSalt.size());
			ArrayCopy(this->MasterPassword, 0, arr, this->GlobalSalt.size(), this->MasterPassword.size());
			vector<byte> arr2 = SHA1Compute(arr);
			vector<byte> arr3(arr2.size() + this->EntrySalt.size());
			ArrayCopy(arr2, 0, arr3, 0, arr2.size());
			ArrayCopy(this->EntrySalt, 0, arr3, arr2.size(), this->EntrySalt.size());
			vector<byte> key = SHA1Compute(arr3);
			vector<byte> arr4(this->EntrySalt.size());
			ArrayCopy(this->EntrySalt, 0, arr4, 0, this->EntrySalt.size());
			for (int i = this->EntrySalt.size(); i < 20; ++i)
				arr4[i] = 0;
			vector<byte> arr5(arr4.size() + this->EntrySalt.size());
			ArrayCopy(arr4, 0, arr5, 0, 20);
			ArrayCopy(this->EntrySalt, 0, arr5, arr4.size(), this->EntrySalt.size());
			vector<byte> arr6;
			vector<byte> arr9;
			arr6 = HMACCompute(arr5, key);
			vector<byte> arr7 = HMACCompute(arr4, key);
			vector<byte> arr8(arr7.size() + this->EntrySalt.size());
			ArrayCopy(arr7, 0, arr8, 0, arr7.size());
			ArrayCopy(this->EntrySalt, 0, arr8, arr7.size(), this->EntrySalt.size());
			arr9 = HMACCompute(arr8, key);
			vector<byte> arr10(arr6.size() + arr9.size());
			ArrayCopy(arr6, 0, arr10, 0, arr6.size());
			ArrayCopy(arr9, 0, arr10, arr6.size(), arr9.size());
			this->Key = vector<byte>(24);
			for (int j = 0; j < this->Key.size(); ++j)
				this->Key[j] = arr10[j];
			this->IV = vector<byte>(8);
			int num = 7;
			for (int k = arr10.size() - 1; k >= arr10.size() - 8; --k)
			{
				this->IV[num] = arr10[k];
				--num;
			}
		}
		catch (...) { return; }
	}
};