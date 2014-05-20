#ifndef HASH_FUNC_HH
#define HASH_FUNC_HH

#include <string>

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 1)
#include <tr1/functional>
#else /* G++ before 4.2 */
#include <ext/hash_fun.h>

namespace __gnu_cxx
{

template <class T>
struct hash<T*>
{
    size_t operator()(const T* t) const
    {
        return (uintptr_t) t;
    }
};

template <>
struct hash<std::string>
{
    size_t operator()(const std::string& s) const
    {
        return hash<const char*>()(s.c_str());
    }
};

} // namespace __gnu_cxx
#endif /* G++ before 4.2 */

#endif /* hash_func.hh */
