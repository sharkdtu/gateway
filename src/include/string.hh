#ifndef STRING_HH
#define STRING_HH 1

#include <stdarg.h>
#include <string>

namespace rusv
{

void string_printf(std::string&, const char* format, ...)
__attribute__((format(printf, 2, 3)));
void string_vprintf(std::string&, const char* format, va_list args)
__attribute__((format(printf, 2, 0)));
std::string string_format(const char* format, ...)
__attribute__((format(printf, 1, 2)));

} // namespace rusv

#endif /* string.hh */
