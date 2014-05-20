#ifndef HASH_SET_HH
#define HASH_SET_HH 1

#include "hash.hh"

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 1)
#include <tr1/unordered_set>

namespace rusv
{
template < class Value,
         class Hash = std::tr1::hash<Value>,
         class Equal = std::equal_to<Value>,
         class Allocator = std::allocator<Value> >
class hash_set
    : public std::tr1::unordered_set<Value, Hash, Equal, Allocator>
{
};
} // namespace vigil
#else /* G++ before 4.2 */
#include "hash_func.hh"
#include <ext/hash_set>
#include <stdint.h>

namespace rusv
{
template < class Value,
         class Hash = __gnu_cxx::hash<Value>,
         class Equal = std::equal_to<Value>,
         class Allocator = std::allocator<Value> >
class hash_set
    : public __gnu_cxx::hash_set<Value, Hash, Equal, Allocator>
{
};
} // namespace rusv

#endif /* G++ before 4.2 */

#endif /* hash-set.hh */
