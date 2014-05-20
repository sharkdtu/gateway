#ifndef UTIL_HH
#define UTIL_HH 1

#include <string>

namespace rusv
{

int str_to_hex(char* str, unsigned char* buf, int len);

void hex_to_str(char* str, unsigned char* buf, int len);

std::string mac_to_str(unsigned char* mac, const char seg = ':');

int str_to_mac(const std::string str, unsigned char* mac);

}// namespace rusv

#endif
