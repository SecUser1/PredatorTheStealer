#include "AntiDebug.h"

BOOL safeWow64DisableDirectory(PVOID & arg)
{
	typedef BOOL WINAPI fntype_Wow64DisableWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64DisableWow64FsRedirection = (fntype_Wow64DisableWow64FsRedirection*)
		get_proc_address(get_kernel32_handle(), XOR("Wow64DisableWow64FsRedirection"));

	if (pfnWow64DisableWow64FsRedirection)
	{
		(*pfnWow64DisableWow64FsRedirection)(&arg);
		return TRUE;
	}
	else
		return FALSE;
}

BOOL safeWow64ReverDirectory(PVOID & arg)
{
	typedef BOOL WINAPI fntype_Wow64RevertWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64RevertWow64FsRedirection = (fntype_Wow64RevertWow64FsRedirection*)
		get_proc_address(get_kernel32_handle(), XOR("Wow64RevertWow64FsRedirection"));

	if (pfnWow64RevertWow64FsRedirection)
	{
		(*pfnWow64RevertWow64FsRedirection)(&arg);
		return TRUE;
	}
	else
		return FALSE;
}

VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
	if (NULL == lpSystemInfo)
		return;
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo =
		(LPFN_GetNativeSystemInfo)get_proc_address(get_kernel32_handle(), XOR("GetNativeSystemInfo"));

	if (NULL != fnGetNativeSystemInfo)
		fnGetNativeSystemInfo(lpSystemInfo);
	else
		FNC(GetSystemInfo, XOR("Kernel32.dll"))(lpSystemInfo);
}

volatile void __stdcall HardwareBreakpointRoutine(PVOID xAntiDbgClass)
{
	__debugbreak();
	return;
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
	{
#ifdef _WIN64
		AntiDebug *antiDbg = (AntiDebug*)pExceptionInfo->ContextRecord->Rcx;
		if (pExceptionInfo->ContextRecord->Dr0 != 0 ||
			pExceptionInfo->ContextRecord->Dr1 != 0 ||
			pExceptionInfo->ContextRecord->Dr2 != 0 ||
			pExceptionInfo->ContextRecord->Dr3 != 0)
		{
			antiDbg->_isSetHWBP = TRUE;
			pExceptionInfo->ContextRecord->Dr0 = 0;
			pExceptionInfo->ContextRecord->Dr1 = 0;
			pExceptionInfo->ContextRecord->Dr2 = 0;
			pExceptionInfo->ContextRecord->Dr3 = 0;
		}

		pExceptionInfo->ContextRecord->Rip = pExceptionInfo->ContextRecord->Rip + 1;
#else
		AntiDebug *antiDbg = (AntiDebug *)(*(DWORD*)(pExceptionInfo->ContextRecord->Esp + 4));
		if (pExceptionInfo->ContextRecord->Dr0 != 0 ||
			pExceptionInfo->ContextRecord->Dr1 != 0 ||
			pExceptionInfo->ContextRecord->Dr2 != 0 ||
			pExceptionInfo->ContextRecord->Dr3 != 0)
		{
			antiDbg->_isSetHWBP = TRUE;

			pExceptionInfo->ContextRecord->Dr0 = 0;
			pExceptionInfo->ContextRecord->Dr1 = 0;
			pExceptionInfo->ContextRecord->Dr2 = 0;
			pExceptionInfo->ContextRecord->Dr3 = 0;
		}

		pExceptionInfo->ContextRecord->Eip = pExceptionInfo->ContextRecord->Eip + 1;
#endif

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#ifdef _WIN64
#define GetProcAddress64         GetProcAddress
#define GetModuleHandle64        GetModuleHandleW
#define getMem64(dest,src,size)  memcpy(dest,src,size)
#endif

#define NTDLL XOR("ntdll.dll")
#define PAGESIZE XorInt(0x1000)
#define MAXOPCODE XorInt(0x64)

AntiDebug::AntiDebug(HMODULE moduleHandle, BOOL** pCodeInt, BOOL** pWasCalled)
{
	_initialized = FALSE;
	_isArch64 = FALSE;
	_isWow64 = FALSE;
	_isWow64FsReDriectory = FALSE;
	_pagePtr = 0;
	_pageSize = 0;
	_pageCrc32 = 0;
	_pfnSyscall32 = NULL;
	_pfnSyscall64 = NULL;
	_isLoadStrongOD = FALSE;
	_isSetHWBP = FALSE;
	_isCodeSectionFailed = FALSE;
	_wasCalled = FALSE;
	
	*pCodeInt = &_isCodeSectionFailed;
	*pWasCalled = &_wasCalled;

	_moduleHandle = moduleHandle;

	SYSTEM_INFO si;
	RTL_OSVERSIONINFOW osVer;
	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		_isArch64 = TRUE;

	typedef LONG(__stdcall *fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
	fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)get_proc_address(get_module_handle(XOR("ntdll.dll")), XOR("RtlGetVersion"));

	if (pRtlGetVersion)
		pRtlGetVersion(&osVer);

	_major = osVer.dwMajorVersion;
	_minor = osVer.dwMinorVersion;

	FNC(IsWow64Process, XOR("Kernel32.dll"))((HANDLE)-1, &_isWow64);

	if (_isArch64 && _isWow64)
		_isWow64FsReDriectory = TRUE;

	_pageSize = si.dwPageSize;

	typedef NTSTATUS(NTAPI* fnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ DWORD_PTR ThreadInformationClass,
		_In_ PVOID ThreadInformation,
		_In_ ULONG ThreadInformationLength
		);

	fnNtSetInformationThread pfnNtSetInformationThread = (fnNtSetInformationThread)get_proc_address(get_module_handle(NTDLL), XOR("NtSetInformationThread"));
	if (pfnNtSetInformationThread)
	{
#ifdef RELEASE_BUILD
		LONG status;

		pfnNtSetInformationThread((HANDLE)-2, XorInt(0x11), NULL, NULL);
		status = pfnNtSetInformationThread((HANDLE)-2, XorInt(0x11), (PVOID)sizeof(PVOID), sizeof(PVOID));
		if (status == 0)
			_isLoadStrongOD = TRUE;
		//for (size_t i = 0; i < 55000; ++i)
			//FNC(OutputDebugStringA, XOR("Kernel32.dll"))("");
#else
		_isLoadStrongOD = TRUE;
#endif
	}
}

AntiDebug::~AntiDebug()
{
	if (_pagePtr)
		FNC(VirtualFreeEx, XOR("Kernel32.dll"))((HANDLE)-1, reinterpret_cast<LPVOID>(_pagePtr), 0, XorInt(MEM_RELEASE));
}

AD_STATUS AntiDebug::Initialize()
{
	try
	{
		if (_initialized)
			return AD_OK;

		PIMAGE_DOS_HEADER dosHead;
		PIMAGE_NT_HEADERS ntHead;
		PIMAGE_SECTION_HEADER secHead;
		CODE_CRC32 codeSection;

		if (FNC(IsBadReadPtr, XOR("Kernel32.dll"))(_moduleHandle, sizeof(void*)) == 0)
		{
			dosHead = (PIMAGE_DOS_HEADER)_moduleHandle;

			if (dosHead == NULL || dosHead->e_magic != IMAGE_DOS_SIGNATURE)
				return AD_ERROR_MODULEHANDLE;

			ntHead = FNC(ImageNtHeader, XOR("Dbghelp.dll"))(dosHead);
			if (ntHead == NULL || ntHead->Signature != IMAGE_NT_SIGNATURE)
				return AD_ERROR_MODULEHANDLE;

			secHead = IMAGE_FIRST_SECTION(ntHead);
			_codeCrc32.clear();

			for (size_t Index = 0; Index < ntHead->FileHeader.NumberOfSections; ++Index)
			{
				if ((secHead->Characteristics & IMAGE_SCN_MEM_READ) && !(secHead->Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					codeSection.m_va = (PVOID)((DWORD_PTR)_moduleHandle + secHead->VirtualAddress);
					codeSection.m_size = secHead->Misc.VirtualSize;
					codeSection.m_crc32 = crc32(codeSection.m_va, codeSection.m_size);
					_codeCrc32.push_back(codeSection);
				}
				++secHead;
			}
		}

		if (_isArch64)
		{
#ifndef _WIN64
			InitWow64Ext();
#endif
			_MyQueryInfomationProcess = (DWORD64)GetProcAddress64(GetModuleHandle64(NTDLL), XOR("ZwQueryInformationProcess"));
			if (_MyQueryInfomationProcess == NULL)
				return AD_ERROR_NTAPI;
			_MyQueryInfomationProcess -= (DWORD64)GetModuleHandle64(NTDLL);
		}
		else
		{
			_MyQueryInfomationProcess = (DWORD)get_proc_address(get_module_handle(NTDLL), XOR("ZwQueryInformationProcess"));
			if (_MyQueryInfomationProcess == NULL)
				return AD_ERROR_NTAPI;
			_MyQueryInfomationProcess -= (DWORD)get_module_handle(NTDLL);
		}

		DWORD fileOffset = 0;
		if (_isArch64)
		{
			unsigned char pehead[PAGESIZE];
			getMem64(pehead, GetModuleHandle64(NTDLL), PAGESIZE);

			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)pehead;
			if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
				return AD_ERROR_FILEOFFSET;

			PIMAGE_NT_HEADERS64	pNtHead = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHead + pDosHead->e_lfanew);
			if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
				return AD_ERROR_FILEOFFSET;

			PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
				(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);

			for (size_t i = 0; i < pNtHead->FileHeader.NumberOfSections; ++i)
			{
				if (pSection->VirtualAddress <= _MyQueryInfomationProcess && _MyQueryInfomationProcess <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))
					break;
				++pSection;
			}
			fileOffset = (DWORD)(_MyQueryInfomationProcess - pSection->VirtualAddress + pSection->PointerToRawData);
		}
		else
		{
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)get_module_handle(NTDLL);
			if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
				return AD_ERROR_FILEOFFSET;

			PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((char*)pDosHead + pDosHead->e_lfanew);
			if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
				return AD_ERROR_FILEOFFSET;

			PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
				(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pNtHead);
			for (size_t i = 0; i < pNtHead->FileHeader.NumberOfSections; ++i)
			{
				if (pSection->VirtualAddress <= _MyQueryInfomationProcess && _MyQueryInfomationProcess <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))
					break;
				++pSection;
			}
			fileOffset = (DWORD)(_MyQueryInfomationProcess - pSection->VirtualAddress + pSection->PointerToRawData);
		}

		if (fileOffset == 0)
			return AD_ERROR_FILEOFFSET;
#ifndef _WIN64
		PVOID _wow64FsReDirectory;
#endif
		unsigned char opcode[MAXOPCODE];
		DWORD readd;
		TCHAR sysDir[MAX_PATH] = { 0 };
		HANDLE hFile;
		FNC(GetSystemDirectoryA, XOR("Kernel32.dll"))(sysDir, MAX_PATH);
		_tcscat(sysDir, _T(XOR("\\ntdll.dll")));

#ifndef _WIN64
		if (_isWow64FsReDriectory)
			safeWow64DisableDirectory(_wow64FsReDirectory);
#endif 

		hFile = FNC(CreateFileA, XOR("Kernel32.dll"))(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return AD_ERROR_OPENNTDLL;

		FNC(SetFilePointer, XOR("Kernel32.dll"))(hFile, fileOffset, NULL, FILE_CURRENT);
		FNC(ReadFile, XOR("Kernel32.dll"))(hFile, opcode, MAXOPCODE, &readd, NULL);
		FNC(CloseHandle, XOR("Kernel32.dll"))(hFile);

		ldasm_data ld;
		unsigned char *pEip = opcode;
		size_t len;
		while (TRUE)
		{
			len = ldasm(pEip, &ld, _isArch64);
			if (len == XorInt(5) && pEip[0] == XorInt(0xB8)) // mov eax,xxxxxx
			{
				_eax = *(DWORD*)(&pEip[1]);
				break;
			}
			pEip += len;
		}

#ifndef _WIN64
		if (_isWow64FsReDriectory)
			safeWow64ReverDirectory(_wow64FsReDirectory);
#endif 
		unsigned char shellSysCall32[] =
		{
			XorInt(0xB8), XorInt(0x0), XorInt(0x0), XorInt(0x0), XorInt(0x0),   // mov eax,NtQueryInformationProcess
			XorInt(0xE8), XorInt(0x3), XorInt(0x0), XorInt(0x0), XorInt(0x0),   // call sysentry
			XorInt(0xC2), XorInt(0x14), XorInt(0x0),            // ret 0x14
			// sysenter:
			XorInt(0x8B), XorInt(0xD4),                 // mov edx,esp
			XorInt(0x0F), XorInt(0x34),                 // sysenter
			XorInt(0xC3)                        // retn
		};

		unsigned char shellSysCall64[] =
		{
			XorInt(0xB8), XorInt(0x0), XorInt(0x0), XorInt(0x0), XorInt(0x0),   // mov eax,NtQueryInformationProcess
			XorInt(0x4C), XorInt(0x8B), XorInt(0xD1),           // mov r10,rcx
			XorInt(0x0F), XorInt(0x05),                 // syscall
			XorInt(0xC3)                        // retn
		};

		_pagePtr = FNC(VirtualAllocEx, XOR("Kernel32.dll"))((HANDLE)-1, 0, _pageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (_pagePtr == NULL)
			return AD_ERROR_ALLOCMEM;

		size_t random;
		ULONG_PTR pSysCall;

		srand(FNC(GetTickCount, XOR("Kernel32.dll"))());
		unsigned char *pRandChar = (unsigned char *)_pagePtr;
		for (size_t i = 0; i < _pageSize; ++i)
			pRandChar[i] = LOBYTE(rand());

		random = rand() % (_pageSize - (sizeof(shellSysCall32) + sizeof(shellSysCall64)));

		memcpy(&shellSysCall32[1], &_eax, 4);
		memcpy(&shellSysCall64[1], &_eax, 4);

		pSysCall = (ULONG_PTR)_pagePtr + random;

		_pfnSyscall32 = (fn_SysCall32)pSysCall;
		memcpy((void*)pSysCall, shellSysCall32, sizeof(shellSysCall32));
		pSysCall += sizeof(shellSysCall32);

		_pfnSyscall64 = (fn_SysCall64)pSysCall;
		memcpy((void*)pSysCall, shellSysCall64, sizeof(shellSysCall64));

		_pageCrc32 = crc32(_pagePtr, _pageSize);

		return AD_OK;
	}
	catch (...) { return AD_ERROR_ALLOCMEM; }
}

BOOL AntiDebug::Detect()
{
	char* kernel = XOR("Kernel32.dll");

	if (_isLoadStrongOD)
		return TRUE;

	BOOL result = FALSE;

	for (size_t i = 0; i < _codeCrc32.size() && !_isCodeSectionFailed; ++i)
	{
		if (crc32(_codeCrc32[i].m_va, _codeCrc32[i].m_size) != _codeCrc32[i].m_crc32)
			_isCodeSectionFailed = TRUE;
	}

	BOOL pebBeingDebugger = FALSE;
	__asm
	{
		mov eax, fs:[0x30]
		movzx eax, [eax + 2]
		mov pebBeingDebugger, eax
	}
	if (pebBeingDebugger)
		return TRUE;

	BOOL debugging = XorInt(FALSE);
	if (FNC(CheckRemoteDebuggerPresent, kernel)((HANDLE)(XorInt(-1)), &debugging))
	{
		if (debugging)
			return XorInt(TRUE);
	}

	/*HANDLE processHandle1, processHandle2;
	fnNtSetInformationObject pfnNtSetInformationObject = (fnNtSetInformationObject)get_proc_address(get_module_handle(NTDLL), XOR("ZwSetInformationObject"));
	MYOBJECT_HANDLE_FLAG_INFORMATION objInfo = { 0 };
	objInfo.Inherit = false;
	objInfo.ProtectFromClose = true;

	__try
	{
		processHandle1 = FNC(GetCurrentProcess, kernel)();
		FNC(DuplicateHandle, kernel)(processHandle1, processHandle1, processHandle1, &processHandle2, 0, XorInt(FALSE), 0);
		pfnNtSetInformationObject(processHandle2, (MYOBJECT_INFORMATION_CLASS)XorInt((int)ObjectHandleFlagInformation), &objInfo, XorInt(sizeof(objInfo)));
		FNC(DuplicateHandle, kernel)(processHandle1, processHandle2, processHandle1, &processHandle2, 0, XorInt(FALSE), XorInt(DUPLICATE_CLOSE_SOURCE));
	}
	__except (XorInt(EXCEPTION_EXECUTE_HANDLER))
	{
		return XorInt(TRUE);
	}

	__try
	{
		FNC(CloseHandle, kernel)((HANDLE)XorInt(0xBAADA555));
	}
	__except (XorInt(EXCEPTION_EXECUTE_HANDLER))
	{
		return XorInt(TRUE);
	}*/

	if (_isArch64)
	{
		DWORD64	processInformation;
		DWORD64	returnLength;
		DWORD64 status;
#ifndef _WIN64
		status = X64Call(
			(DWORD64)_pfnSyscall64,
			XorInt(5),
			(DWORD64)-1,
			(DWORD64)XorInt(0x1E),
			(DWORD64)&processInformation,
			(DWORD64)XorInt(8),
			(DWORD64)&returnLength);
#else
		status = _pfnSyscall64(
			(DWORD64)-1,
			(DWORD64)0x1E,
			(PDWORD64)&processInformation,
			(DWORD64)8,
			(PDWORD64)&returnLength);
#endif

		if (status != XorInt(0xC0000353)) //STATUS_PORT_NOT_SET			
			return TRUE;
		if (status == XorInt(0xC0000353) && processInformation != 0)
			return TRUE;
		if (crc32(_pagePtr, _pageSize) != _pageCrc32)
			return TRUE;

		DWORD64	bugCheck;
#ifndef _WIN64
		status = X64Call(
			(DWORD64)_pfnSyscall64,
			XorInt(5),
			(DWORD64)-1,
			(DWORD64)XorInt(0x1E),
			(DWORD64)&bugCheck,
			(DWORD64)XorInt(8),
			(DWORD64)&bugCheck);
#else
		status = _pfnSyscall64(
			(DWORD64)-1,
			(DWORD64)0x1E,
			(PDWORD64)&bugCheck,
			(DWORD64)8,
			(PDWORD64)&bugCheck);
#endif 
		if (status == XorInt(0xC0000353) && bugCheck != XorInt(8))
			return TRUE;
	}
	else
	{
		DWORD processInformation;
		DWORD returnLength;
		DWORD status;

		status = _pfnSyscall32(
			(DWORD)-1,
			(DWORD)XorInt(0x1E),
			&processInformation,
			(DWORD)XorInt(4),
			&returnLength);

		if (status != XorInt(0xC0000353)) //STATUS_PORT_NOT_SET 
			return TRUE;
		if (status == XorInt(0xC0000353) && processInformation != 0)
			return TRUE;
		if (crc32(_pagePtr, _pageSize) != _pageCrc32)
			return TRUE;

		DWORD bugCheck;
		status = _pfnSyscall32(
			(DWORD)-1,
			(DWORD)XorInt(0x1E),
			&bugCheck,
			(DWORD)XorInt(4),
			&bugCheck);
		if (status == XorInt(0xC0000353) && bugCheck != XorInt(4))
			return TRUE;
	}

	CONTEXT	ctx = { 0 };
	ctx.ContextFlags = XorInt(CONTEXT_DEBUG_REGISTERS);
	if (FNC(GetThreadContext, kernel)((HANDLE)-2, &ctx))
	{
		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
			return TRUE;
	}

	FNC(AddVectoredExceptionHandler, kernel)(0, VectoredExceptionHandler);

	typedef void(__stdcall *fnMakeException)(PVOID lparam);
	fnMakeException pfnMakeException = (fnMakeException)HardwareBreakpointRoutine;
	pfnMakeException(this);

	FNC(RemoveVectoredExceptionHandler, kernel)(VectoredExceptionHandler);

	if (_isSetHWBP)
		return TRUE;

	_wasCalled = TRUE;
	return FALSE;
}

VOID __stdcall ThreadRoutine(LPVOID pAdbg)
{
	try
	{
		AntiDebug* adbg = (AntiDebug*)pAdbg;
		while (true)
		{
			if (adbg->Detect())
				FNC(ExitProcess, XOR("Kernel32.dll"))(XorInt(0));
			FNC(Sleep, XOR("Kernel32.dll"))(XorInt(5000));
		}
	}
	catch (...) { return; }
}

VOID AntiDebug::StartThread()
{
	try
	{
		FNC(CreateThread, XOR("Kernel32.dll"))(0, 0, (LPTHREAD_START_ROUTINE)ThreadRoutine, (LPVOID)this, 0, 0);
	}
	catch (...) { return; }
}