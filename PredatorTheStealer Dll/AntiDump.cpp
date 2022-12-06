#include "AntiDump.h"

PVOID AntiDump::GetProcessPEB()
{
#ifdef _WIN64
	return (PVOID)__readgsqword(0x60);
#else
	return (PVOID)__readfsdword(0x30);
#endif
}

void AntiDump::HideInLoadOrderLinks(HMODULE dllBase)
{
	try
	{
		PPEB peb = (PPEB)GetProcessPEB();
		if (!peb)
			return;
		PLIST_ENTRY OrderModuleHead, OrderModuleTail;
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
		OrderModuleHead = OrderModuleTail = peb->Ldr->InLoadOrderModuleList.Blink;
		do
		{
			pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (pLdrDataEntry->DllBase == NULL)
				break;
			if (pLdrDataEntry->DllBase == dllBase)
				RemoveEntryList(OrderModuleHead);
			OrderModuleHead = OrderModuleHead->Blink;
		} while (OrderModuleHead != OrderModuleTail);
	}
	catch (...) { return; }
}

void AntiDump::HideInMemoryOrderLinks(HMODULE dllBase)
{
	try
	{
		PPEB peb = (PPEB)GetProcessPEB();
		if (!peb)
			return;
		PLIST_ENTRY OrderModuleHead, OrderModuleTail;
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
		OrderModuleHead = OrderModuleTail = peb->Ldr->InMemoryOrderModuleList.Blink;
		do
		{
			pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (pLdrDataEntry->DllBase == NULL)
				break;
			if (pLdrDataEntry->DllBase == dllBase)			
				RemoveEntryList(OrderModuleHead);
			OrderModuleHead = OrderModuleHead->Blink;
		} while (OrderModuleHead != OrderModuleTail);
	}
	catch (...) { return; }
}

void AntiDump::HideInInitializationOrderLinks(HMODULE dllBase)
{
	try
	{
		PPEB peb = (PPEB)GetProcessPEB();
		if (!peb)
			return;
		PLIST_ENTRY OrderModuleHead, OrderModuleTail;
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
		OrderModuleHead = OrderModuleTail = peb->Ldr->InInitializationOrderModuleList.Blink;
		do
		{
			pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(OrderModuleHead, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
			if (pLdrDataEntry->DllBase == NULL)
				break;
			if (pLdrDataEntry->DllBase == dllBase)
				RemoveEntryList(OrderModuleHead);
			OrderModuleHead = OrderModuleHead->Blink;
		} while (OrderModuleHead != OrderModuleTail);
	}
	catch (...) { return; }
}