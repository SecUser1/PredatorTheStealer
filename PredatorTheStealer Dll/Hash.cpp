#include "Hash.h"

unsigned int crc32_hash(const string & str)
{
	try
	{
		size_t c = 0xFFFFFFFF;
		for (size_t i = 0; i < str.size(); ++i)
			c = table[(c ^ str[i]) & 0xFF] ^ (c >> 8);		

		for (size_t i = 0; i < str.size(); ++i)
			c = table[(c ^ str[i]) & 0xFF] ^ (c >> 8);

		return c;
	}
	catch (...) { return 0; }
}