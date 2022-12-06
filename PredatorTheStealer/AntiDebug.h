#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <vector>
#include <windows.h>
#include <ImageHlp.h>
#include <Shlwapi.h>
#include <Softpub.h>
#include <tchar.h>

#include "ldasm.h"
#include "crc32.h"
#include "DynImport.h"
#include "xor.h"

#ifndef _WIN64
#include "wow64ext.h"
#endif

#define FLAG_CHECKSUM_CODESECTION (0x0002)
#define FLAG_DETECT_DEBUGGER (0x0004)
#define FLAG_DETECT_HARDWAREBREAKPOINT (0x0008)
#define FLAG_FULLON (FLAG_CHECKSUM_CODESECTION | FLAG_DETECT_DEBUGGER | FLAG_DETECT_HARDWAREBREAKPOINT)
#define XOR(x) XorStr(x)

typedef enum _AD_STATUS
{
	AD_OK,
	AD_ERROR_OPENNTOS,
	AD_ERROR_MODULEHANDLE,
	AD_ERROR_OPENNTDLL,
	AD_ERROR_NTAPI,
	AD_ERROR_ALLOCMEM,
	AD_ERROR_FILEOFFSET
} AD_STATUS;

typedef DWORD64(WINAPI *fn_SysCall64)(
	DWORD64 processHandle,
	DWORD64 processClass,
	PDWORD64 processInfo,
	DWORD64 length,
	PDWORD64 returnLength
	);

typedef DWORD(WINAPI *fn_SysCall32)(
	DWORD processHandle,
	DWORD processClass,
	PDWORD processInfo,
	DWORD length,
	PDWORD returnLength
	);

typedef struct _CODE_CRC32
{
	PVOID m_va;
	DWORD m_size;
	DWORD m_crc32;
} CODE_CRC32;


typedef enum _MYOBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation, // OBJECT_BASIC_INFORMATION
	ObjectNameInformation, // OBJECT_NAME_INFORMATION
	ObjectTypeInformation, // OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation,
	ObjectSessionObjectInformation,
	MaxObjectInfoClass
} MYOBJECT_INFORMATION_CLASS;

typedef struct _MYOBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} MYOBJECT_HANDLE_FLAG_INFORMATION, *PMYOBJECT_HANDLE_FLAG_INFORMATION;

typedef NTSTATUS(WINAPI *fnNtSetInformationObject)(
	_In_ HANDLE Handle,
	_In_ MYOBJECT_INFORMATION_CLASS ObjectInformationClass,
	_In_ PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength
	);

class AntiDebug
{
public:
	AntiDebug(HMODULE moduleHandle, BOOL** pCodeInt, BOOL** pWasCalled);
	~AntiDebug();

	AD_STATUS Initialize();
	BOOL Detect();
	VOID StartThread();

	BOOL _isSetHWBP;
	BOOL _isLoadStrongOD;
	
private:
	BOOL _isCodeSectionFailed;
	BOOL _wasCalled;

	HMODULE _moduleHandle;
	DWORD _flags;

	BOOL _initialized;
	DWORD _major;
	DWORD _minor;
	BOOL _isArch64;
	BOOL _isWow64;
	BOOL _isWow64FsReDriectory;

	DWORD _pageSize;
	PVOID _pagePtr;
	DWORD _pageCrc32;

	CHAR _ntosPath[MAX_PATH];
	std::vector<CODE_CRC32> _codeCrc32;

	DWORD64 _MyQueryInfomationProcess;
	DWORD _eax;
	fn_SysCall32 _pfnSyscall32;
	fn_SysCall64 _pfnSyscall64;
};