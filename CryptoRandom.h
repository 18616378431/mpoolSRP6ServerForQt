#ifndef MPOOL_CRYPTORANDOM_H
#define MPOOL_CRYPTORANDOM_H

#include <array>

#include "types.h"

namespace mpool::Crypto
{
    void GetRandomBytes(uint8* buf, size_t len);

    template <typename Container>
    void GetRandomBytes(Container& c)
    {
        GetRandomBytes(std::data(c), std::size(c));
    }

    template <size_t S>
    std::array<uint8, S> GetRandomBytes()
    {
        std::array<uint8, S> arr;
        GetRandomBytes(arr);
        return arr;
    }
}


#endif //MPOOL_CRYPTORANDOM_H
