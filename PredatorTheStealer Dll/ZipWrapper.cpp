#include "ZipWrapper.h"

void ZipWrapper::zipFolder(const string & path, const string & dir)
{
	try
	{
		WIN32_FIND_DATA data;
		HANDLE hFile = FNC(FindFirstFileA, XorStr("Kernel32.dll"))((path + "\\*").c_str(), &data);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			do
			{
				const string file_name = data.cFileName;
				if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (file_name != "." && file_name != "..")
					{
						ZipAddFolder(zip, ((dir == "" ? "" : dir + '\\') + file_name).c_str());
						zipFolder(path + '\\' + file_name, (dir == "" ? "" : dir + '\\') + file_name);
					}
				}
				else
					ZipAdd(zip, ((dir == "" ? dir : dir + '\\') + file_name).c_str(), (path + '\\' + file_name).c_str());
			} while (FNC(FindNextFileA, XorStr("Kernel32.dll"))(hFile, &data));
		}
		FNC(FindClose, XorStr("Kernel32.dll"))(hFile);
	}
	catch (...) { return; }
}

ZipWrapper::ZipWrapper()
{
}

ZipWrapper::ZipWrapper(const string & arch)
{
	try
	{
		path = arch;
		this->buff = malloc(MAXSIZE); // 255 megabytes
		if (this->buff == nullptr)
			this->zip = CreateZip(path.c_str(), 0);
		else
			this->zip = CreateZip(this->buff, MAXSIZE, 0); // 255 megabytes
	}
	catch (...) { }
}

ZipWrapper::ZipWrapper(size_t memory, const string & arch)
{
	try
	{
		path = arch;
		this->buff = malloc(memory);
		if (this->buff == nullptr)
			this->zip = CreateZip(path.c_str(), 0);
		else
			this->zip = CreateZip(this->buff, memory, 0);
	}
	catch (...) { }
}

ZipWrapper::~ZipWrapper()
{
	try
	{
		if (this->buff != nullptr)
		{
			//free(this->buff);
			this->buff = nullptr;
		}
		else
			FNC(DeleteFileA, XorStr("Kernel32.dll"))(path.c_str());
		if (this->zip != nullptr)
			CloseZip(this->zip);
	}
	catch(...) { }
}

void ZipWrapper::addFileMemory(const string & fileName, const string & data)
{
	try
	{
		ZipAdd(this->zip, fileName.c_str(), (void*)data.c_str(), data.size());
	}
	catch (...) { return; }
}

void ZipWrapper::addFile(const string & fileName, const string & destName)
{
	try
	{
		ZipAdd(this->zip, destName.c_str(), fileName.c_str());
	}
	catch (...) { return; }
}

void ZipWrapper::addFolder(const string & folderName)
{
	try
	{
		ZipAddFolder(this->zip, folderName.c_str());
	}
	catch (...) { return; }
}

void ZipWrapper::addFolderRecursive(const string & folderName)
{
	try
	{
		zipFolder(folderName);
	}
	catch (...) { return; }
}

unsigned long ZipWrapper::data(void ** ret)
{
	try
	{
		unsigned long len = 0;
		ZipGetMemory(this->zip, ret, &len);
		return len;
	}
	catch (...) { return 0; }
}