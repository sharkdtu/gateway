#include "string.hh"

#include <stdlib.h>
#include <stdio.h>

#define NOT_REACHED() abort()

namespace rusv
{

void
string_vprintf(std::string& string, const char* format, va_list args)
{
    char buffer[128];

    va_list args2;
    va_copy(args2, args);
    int n = vsnprintf(buffer, sizeof buffer, format, args2);
    va_end(args2);

    if (n >= sizeof buffer)
    {
        string.resize(string.size() + n);
        va_copy(args2, args);
        vsnprintf(&string[string.size()], n + 1, format, args2);
        va_end(args2);
    }
    else if (n >= 0)
    {
        string += buffer;
    }
    else
    {
        NOT_REACHED();
    }
}

void
string_printf(std::string& string, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    string_vprintf(string, format, args);
    va_end(args);
}

std::string
string_format(const char* format, ...)
{
    std::string string;

    va_list args;
    va_start(args, format);
    string_vprintf(string, format, args);
    va_end(args);

    return string;
}

} // namespace rusv
