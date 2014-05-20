#ifndef HASH_MAP_HH
#define HASH_MAP_HH 1

#include "hash.hh"

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 1)
#include <tr1/unordered_map>
#include <utility>

namespace rusv
{
template < class Key,
         class Tp,
         class Hash = std::tr1::hash<Key>,
         class Equal = std::equal_to<Key>,
         class Allocator = std::allocator<std::pair<const Key, Tp> > >
class hash_map
    : public std::tr1::unordered_map<Key, Tp, Hash, Equal, Allocator>
{
};
} // namespace vigil
#else /* G++ before 4.2 */
#include "hash_func.hh"
#include <ext/hash_map>
#include <stdint.h>

namespace rusv
{
template < class Key,
         class Tp,
         class Hash = __gnu_cxx::hash<Key>,
         class Equal = std::equal_to<Key>,
         class Allocator = std::allocator<Key> >
class hash_map
    : public __gnu_cxx::hash_map<Key, Tp, Hash, Equal, Allocator>
{
};
} // namespace rusv
#endif /* G++ before 4.2 */

#endif /* hash-map.hh */
