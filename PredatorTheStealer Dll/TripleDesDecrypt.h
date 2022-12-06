#pragma once
#include <string>
#include <vector>
#include <Windows.h>

#include "DynImport.h"
#include "xor.h"

#define XOR(x) XorStr(x)

using std::string;
using std::vector;

class TripleDes
{	
public:
	static string DecryptAsString(const vector<byte> & key, const vector<byte> & iv, const vector<byte> & input)
	{
		try
		{
			HCRYPTPROV hProv;
			char* advapi = XOR("Advapi32.dll");
			if (FNC(CryptAcquireContextA, advapi)(&hProv, NULL, NULL, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT))
			{
				HCRYPTKEY hKey;
				typedef struct
				{
					BLOBHEADER hdr;
					DWORD cbKeySize;
					BYTE rgbKeyData[24];
				} KEYBLOB;
				KEYBLOB keyBlob;
				memset(&keyBlob, 0, sizeof(keyBlob));
				keyBlob.cbKeySize = 24;
				keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
				keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
				keyBlob.hdr.aiKeyAlg = CALG_3DES;
				memcpy(keyBlob.rgbKeyData, key.data(), 24);
				string res = "";
				if (FNC(CryptImportKey, advapi)(hProv, (const BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
				{
					DWORD dwMode = CRYPT_MODE_CBC;
					if (FNC(CryptSetKeyParam, advapi)(hKey, KP_MODE, (BYTE*)&dwMode, 0))
					{
						if (FNC(CryptSetKeyParam, advapi)(hKey, KP_IV, (BYTE*)iv.data(), 0))
						{
							vector<byte> dup = input;
							DWORD len = dup.size();
							if (FNC(CryptDecrypt, advapi)(hKey, NULL, TRUE, 0, (BYTE*)dup.data(), &len))
							{
								for (int i = 0; i < len; ++i)
									res += dup[i];
								FNC(CryptDestroyKey, advapi)(hKey);
							}							
						}						
					}
				}				
				FNC(CryptDestroyKey, advapi)(hKey);
				FNC(CryptReleaseContext, advapi)(hProv, 0);
				FNC(CryptReleaseContext, advapi)(hProv, 0);
				return res;
			}

			return string();
		}
		catch (...) { return string(); }
	}
};