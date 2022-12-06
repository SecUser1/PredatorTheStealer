#pragma once
#include <array>
#include <cstdarg>

namespace XorCompileTime
{
	template<int F, size_t N, int K>
	struct XorString;

	constexpr auto time = __TIME__;
	constexpr auto seed =
		static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10
		+ static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600
		+ static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

	template <int N>
	struct RandomGeneratorXor
	{
	private:
		static constexpr unsigned a = 16811;
		static constexpr unsigned m = 2147483647;
		static constexpr unsigned s = RandomGeneratorXor<N - 1>::value;
		static constexpr unsigned lo = a * (s & 0xFFFF);
		static constexpr unsigned hi = a * (s >> 16);
		static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);
		static constexpr unsigned hi2 = hi >> 16;
		static constexpr unsigned lo3 = lo2 + hi;
	public:
		static constexpr unsigned max = m;
		static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
	};

	template <>
	struct RandomGeneratorXor<0>
	{
		static constexpr unsigned value = seed;
	};

	template <int N, int M>
	struct RandomInt
	{
		static constexpr auto value = RandomGeneratorXor<N + 1>::value % M;
	};

	template <int N>
	struct RandomChar
	{
		static const char value = static_cast<char>(1 + RandomInt<N, 0x7F - 1>::value);
	};

	template <size_t N, int K>
	struct XorString<0, N, K>
	{
	private:
		const char _key;
		std::array<char, N + 1> _encrypted;
		constexpr char enc(char c) const
		{
			return c ^ _key;
		}

		char dec(char c) const
		{
			return c ^ _key;
		}
	public:
		template < size_t... Is >
		constexpr __forceinline XorString(const char* str, std::index_sequence<Is...>)
			: _key(RandomChar<K>::value), _encrypted{enc(str[Is])...} { }

		__forceinline decltype(auto) decrypt(void)
		{
			for (size_t i = 0; i < N; ++i)
				_encrypted[i] = dec(_encrypted[i]);
			_encrypted[N] = '\0';
			return _encrypted.data();
		}
	};

	template <size_t N, int K>
	struct XorString<1, N, K>
	{
	private:
		const char _key;
		std::array<char, N + 1> _encrypted;
		constexpr char enc(char c) const
		{
			return c + (_key % 16);
		}

		char dec(char c) const
		{
			return c - (_key % 16);
		}
	public:
		template < size_t... Is >
		constexpr __forceinline XorString(const char* str, std::index_sequence<Is...>)
			: _key(RandomChar<K>::value), _encrypted{enc(str[Is])...} { }

		__forceinline decltype(auto) decrypt(void)
		{
			for (size_t i = 0; i < N; ++i)
				_encrypted[i] = dec(_encrypted[i]);
			_encrypted[N] = '\0';
			return _encrypted.data();
		}
	};

	template <size_t N, int K>
	struct XorStringW
	{
	private:
		std::array<wchar_t, N + 1> _encrypted;
		constexpr wchar_t enc(wchar_t c) const
		{
			return ~c;
		}

		wchar_t dec(wchar_t c) const
		{
			return ~c;
		}
	public:
		template < size_t... Is >
		constexpr __forceinline XorStringW(const wchar_t* str, std::index_sequence<Is...>)
			: _encrypted{ enc(str[Is])... } { }

		__forceinline decltype(auto) decrypt(void)
		{
			for (size_t i = 0; i < N; ++i)
				_encrypted[i] = dec(_encrypted[i]);
			_encrypted[N] = '\0';
			return _encrypted.data();
		}
	};

	volatile constexpr __forceinline int getInt(volatile int a)
	{
		return a;
	}

#ifdef RELEASE_BUILD
#define XorStr(s) (XorCompileTime::XorString< \
	XorCompileTime::RandomInt<__COUNTER__, 2>::value, sizeof(s) - 1, __COUNTER__>(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())
#define XorStrW(s) (XorCompileTime::XorStringW<sizeof(s) / 2 - 1, __COUNTER__>(s, std::make_index_sequence<(sizeof(s) / 2 - 1)>()).decrypt())
#define XorIntP(n, b) (XorCompileTime::getInt(XorCompileTime::RandomInt<b, 2048>::value ^ n) ^ XorCompileTime::RandomInt<b, 2048>::value)
#define XorInt(n) XorIntP(n, __COUNTER__)
#else
#define XorStr(x) (char*)x
#define XorStrW(x) (wchar_t*)x
#define XorInt(n) n
#endif
}