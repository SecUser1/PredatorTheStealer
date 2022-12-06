#pragma once
#include <string>

using std::string;

unsigned int crc32_hash(const string & str);

constexpr unsigned int table[256] = 
{
	0x0,
	0x41047A6A, 0x8208F4D4, 0xC30C8EBE, 0xDF60EFDF, 0x9E6495B5,
	0x5D681B0B, 0x1C6C6161, 0x65B0D9C9, 0x24B4A3A3, 0xE7B82D1D,
	0xA6BC5777, 0xBAD03616, 0xFBD44C7C, 0x38D8C2C2, 0x79DCB8A8,
	0xCB61B392, 0x8A65C9F8, 0x49694746, 0x86D3D2C, 0x14015C4D,
	0x55052627, 0x9609A899, 0xD70DD2F3, 0xAED16A5B, 0xEFD51031,
	0x2CD99E8F, 0x6DDDE4E5, 0x71B18584, 0x30B5FFEE, 0xF3B97150,
	0xB2BD0B3A, 0x4DB26153, 0xCB61B39, 0xCFBA9587, 0x8EBEEFED,
	0x92D28E8C, 0xD3D6F4E6, 0x10DA7A58, 0x51DE0032, 0x2802B89A,
	0x6906C2F0, 0xAA0A4C4E, 0xEB0E3624, 0xF7625745, 0xB6662D2F,
	0x756AA391, 0x346ED9FB, 0x86D3D2C1, 0xC7D7A8AB, 0x4DB2615,
	0x45DF5C7F, 0x59B33D1E, 0x18B74774, 0xDBBBC9CA, 0x9ABFB3A0,
	0xE3630B08, 0xA2677162, 0x616BFFDC, 0x206F85B6, 0x3C03E4D7,
	0x7D079EBD, 0xBE0B1003, 0xFF0F6A69, 0x9B64C2A6, 0xDA60B8CC,
	0x196C3672, 0x58684C18, 0x44042D79, 0x5005713, 0xC60CD9AD,
	0x8708A3C7, 0xFED41B6F, 0xBFD06105, 0x7CDCEFBB, 0x3DD895D1,
	0x21B4F4B0, 0x60B08EDA, 0xA3BC0064, 0xE2B87A0E, 0x50057134,
	0x11010B5E, 0xD20D85E0, 0x9309FF8A, 0x8F659EEB, 0xCE61E481,
	0xD6D6A3F, 0x4C691055, 0x35B5A8FD, 0x74B1D297, 0xB7BD5C29,
	0xF6B92643, 0xEAD54722, 0xABD13D48, 0x68DDB3F6, 0x29D9C99C,
	0xD6D6A3F5, 0x97D2D99F, 0x54DE5721, 0x15DA2D4B, 0x9B64C2A,
	0x48B23640, 0x8BBEB8FE, 0xCABAC294, 0xB3667A3C, 0xF2620056,
	0x316E8EE8, 0x706AF482, 0x6C0695E3, 0x2D02EF89, 0xEE0E6137,
	0xAF0A1B5D, 0x1DB71067, 0x5CB36A0D, 0x9FBFE4B3, 0xDEBB9ED9,
	0xC2D7FFB8, 0x83D385D2, 0x40DF0B6C, 0x1DB7106, 0x7807C9AE,
	0x3903B3C4, 0xFA0F3D7A, 0xBB0B4710, 0xA7672671, 0xE6635C1B,
	0x256FD2A5, 0x646BA8CF, 0xEDB8833B, 0xACBCF951, 0x6FB077EF,
	0x2EB40D85, 0x32D86CE4, 0x73DC168E, 0xB0D09830, 0xF1D4E25A,
	0x88085AF2, 0xC90C2098, 0xA00AE26, 0x4B04D44C, 0x5768B52D,
	0x166CCF47, 0xD56041F9, 0x94643B93, 0x26D930A9, 0x67DD4AC3,
	0xA4D1C47D, 0xE5D5BE17, 0xF9B9DF76, 0xB8BDA51C, 0x7BB12BA2,
	0x3AB551C8, 0x4369E960, 0x26D930A, 0xC1611DB4, 0x806567DE,
	0x9C0906BF, 0xDD0D7CD5, 0x1E01F26B, 0x5F058801, 0xA00AE268,
	0xE10E9802, 0x220216BC, 0x63066CD6, 0x7F6A0DB7, 0x3E6E77DD,
	0xFD62F963, 0xBC668309, 0xC5BA3BA1, 0x84BE41CB, 0x47B2CF75,
	0x6B6B51F, 0x1ADAD47E, 0x5BDEAE14, 0x98D220AA, 0xD9D65AC0,
	0x6B6B51FA, 0x2A6F2B90, 0xE963A52E, 0xA867DF44, 0xB40BBE25,
	0xF50FC44F, 0x36034AF1, 0x7707309B, 0xEDB8833, 0x4FDFF259,
	0x8CD37CE7, 0xCDD7068D, 0xD1BB67EC, 0x90BF1D86, 0x53B39338,
	0x12B7E952, 0x76DC419D, 0x37D83BF7, 0xF4D4B549, 0xB5D0CF23,
	0xA9BCAE42, 0xE8B8D428, 0x2BB45A96, 0x6AB020FC, 0x136C9854,
	0x5268E23E, 0x91646C80, 0xD06016EA, 0xCC0C778B, 0x8D080DE1,
	0x4E04835F, 0xF00F935, 0xBDBDF20F, 0xFCB98865, 0x3FB506DB,
	0x7EB17CB1, 0x62DD1DD0, 0x23D967BA, 0xE0D5E904, 0xA1D1936E,
	0xD80D2BC6, 0x990951AC, 0x5A05DF12, 0x1B01A578, 0x76DC419,
	0x4669BE73, 0x856530CD, 0xC4614AA7, 0x3B6E20CE, 0x7A6A5AA4,
	0xB966D41A, 0xF862AE70, 0xE40ECF11, 0xA50AB57B, 0x66063BC5,
	0x270241AF, 0x5EDEF907, 0x1FDA836D, 0xDCD60DD3, 0x9DD277B9,
	0x81BE16D8, 0xC0BA6CB2, 0x3B6E20C, 0x42B29866, 0xF00F935C,
	0xB10BE936, 0x72076788, 0x33031DE2, 0x2F6F7C83, 0x6E6B06E9,
	0xAD678857, 0xEC63F23D, 0x95BF4A95, 0xD4BB30FF, 0x17B7BE41,
	0x56B3C42B, 0x4ADFA54A, 0xBDBDF20, 0xC8D7519E, 0x89D32BF4
};

constexpr unsigned int simpleHash(const char * s)
{
	// ��������� ������ ������
	constexpr unsigned int A = 54059;
	constexpr unsigned int B = 76963;
	constexpr unsigned int C = 86969;

	unsigned int h = 37;
	while (*s)
	{
		h = (h * A) ^ (s[0] * B);
		s++;
	}

	return h % C;
}

constexpr unsigned int crc32(const char * s)
{
	unsigned int c = 0xFFFFFFFF;
	const char* ss = s;
	
	while (*s)
	{
		c = table[(c ^ s[0]) & 0xFF] ^ (c >> 8);
		++s;
	}
	
	while (*ss)
	{
		c = table[(c ^ ss[0]) & 0xFF] ^ (c >> 8);
		++ss;
	}

	return c;
}