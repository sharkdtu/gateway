#include "util.hh"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace rusv
{

int str_to_hex(char* str, unsigned char* buf, int len)
{
	char high, low;
	int i = 0;
	for (int j = 0; j < len; j += 2) 
	{
		high = str[j];
		low = str[j+1];

		if(high >= '0' && high <= '9')
			high = high - '0';
		else if(high >= 'A' && high <= 'F')
			high = high - 'A' + 10;
		else if(high >= 'a' && high <= 'f')
			high = high - 'a' + 10;
		else
			return -1;

		if(low >= '0' && low <= '9')
			low = low - '0';
		else if(low >= 'A' && low <= 'F')
			low = low - 'A' + 10;
		else if(low >= 'a' && low <= 'f')
			low = low - 'a' + 10;
		else
			return -1;

		buf[i++] = high<<4 | low;
	}

	return 0;
}

void hex_to_str(char* str, unsigned char* buf, int len)
{
	for(int i = 0; i < len; i++)
	{
		sprintf(str, "%02x", buf[i]);
		str += 2;
	}
}

std::string mac_to_str(unsigned char* mac, const char seg/* = ':'*/)
{
	char format[] = "%02X:%02X:%02X:%02X:%02X:%02X";
	int len = strlen(format);
	if (seg != ':')
	{
		for (int i = 4; i < len; i += 5)
		{
			format[i] = seg;
		}
	}
	char tmp[32] = {0};
	sprintf(tmp, format, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	std::string mac_str(tmp);
	return mac_str;
}

int str_to_mac(const std::string str, unsigned char* mac)
{
	char high, low;
	int len = str.size();
	int i = 0;
	for (int j = 0; j < len; j += 3) 
	{
		high = str[j];
		low = str[j+1];

		if(high >= '0' && high <= '9')
			high = high - '0';
		else if(high >= 'A' && high <= 'F')
			high = high - 'A' + 10;
		else if(high >= 'a' && high <= 'f')
			high = high - 'a' + 10;
		else
			return -1;

		if(low >= '0' && low <= '9')
			low = low - '0';
		else if(low >= 'A' && low <= 'F')
			low = low - 'A' + 10;
		else if(low >= 'a' && low <= 'f')
			low = low - 'a' + 10;
		else
			return -1;

		mac[i++] = high<<4 | low;
	}

	return 0;
}

} // namespace rusv
