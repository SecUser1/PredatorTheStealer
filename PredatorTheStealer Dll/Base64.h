#pragma once
#include <string>

#include "xor.h"

using std::string;

bool is_base64(unsigned char c);
string base64_decode(const string & encoded_string);
string base64_encode(const string & pure_string);