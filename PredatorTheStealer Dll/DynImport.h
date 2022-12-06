#pragma once
#include "prototypes.h"
#include "xor.h"

char *_strchr(char *s, char c);
unsigned int hash_uppercaseW(const wchar_t * wstring);

void* get_proc_address(HMODULE module, const char* proc_name);

HMODULE get_module_handle(const char* dll_name);
HMODULE get_kernel32_handle();

ULONG_PTR dyn_call(char* dll, const char* func);

#define MAKESTR(x) # x 
#define FNC(func, lib) ((PROTO_##func) dyn_call(lib, XorStr(MAKESTR(func))))