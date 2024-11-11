#ifndef MPOOL_CRYPTOHASH_H
#define MPOOL_CRYPTOHASH_H

#include <array>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <utility>

#include "types.h"


namespace mpool::Crypto
{
struct Constants
{
    static constexpr size_t MD5_DIGEST_LENGTH_BYTES = 16;
    static constexpr size_t SHA1_DIGEST_LENGTH_BYTES = 20;
    static constexpr size_t SHA256_DIGEST_LENGTH_BYTES = 32;
};
}

class BigNumber;

namespace mpool::Impl
{
    struct GenericHashImpl
    {
        typedef EVP_MD const* (*HashCreator)();

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L
        static EVP_MD_CTX* MakeCTX() noexcept { return EVP_MD_CTX_create(); }
        static void DestroyCTX(EVP_MD_CTX* ctx) {EVP_MD_CTX_destroy(ctx); }
#else
    static EVP_MD_CTX* MakeCTX() noexcept { return EVP_MD_CTX_new(); }
    static void DestroyCTX(EVP_MD_CTX* ctx) { EVP_MD_CTX_free(ctx); }
#endif
    };

    template<GenericHashImpl::HashCreator HashCreator, size_t DigestLength>
    class GenericHash
    {
    public:
        static constexpr size_t DIGEST_LENGTH = DigestLength;
        using Digest = std::array<uint8, DIGEST_LENGTH>;

        static Digest GetDigestOf(uint8 const* data, size_t len)
        {
            GenericHash hash;
            hash.UpdateData(data, len);
            hash.Finalize();
            return hash.GetDigest();
        }

        template <typename... Ts>
        static auto GetDigestOf(Ts&&... pack) -> std::enable_if_t<!(std::is_integral_v<std::decay_t<Ts>> || ...), Digest>
        {
            GenericHash hash;
            (hash.UpdateData(std::forward<Ts>(pack)), ...);
            hash.Finalize();
            return hash.GetDigest();
        }

        GenericHash() : _ctx(GenericHashImpl::MakeCTX())
        {
            int result = EVP_DigestInit_ex(_ctx, HashCreator(), nullptr);
        }

        GenericHash(GenericHash const& right) : _ctx(GenericHashImpl::MakeCTX())
        {
            *this = right;
        }

        GenericHash(GenericHash&& right) noexcept
        {
            *this = std::move(right);
        }

        ~GenericHash()
        {
            if (!_ctx)
                return ;
            GenericHashImpl::DestroyCTX(_ctx);
            _ctx = nullptr;
        }

        GenericHash& operator= (GenericHash const& right)
        {
            if (this == &right)
                return *this;
            int result = EVP_MD_CTX_copy_ex(_ctx, right._ctx);
            _digest = right._digest;
            return *this;
        }

        GenericHash& operator= (GenericHash&& right) noexcept
        {
            if (this == &right)
                return *this;
            _ctx = std::exchange(right._ctx, GenericHashImpl::MakeCTX());
            _digest = std::exchange(right._digest, Digest{});
            return *this;
        }

        void UpdateData(uint8 const* data, size_t len)
        {
            int result = EVP_DigestUpdate(_ctx, data, len);
        }
        void UpdateData(std::string_view str) { UpdateData(reinterpret_cast<uint8 const*>(str.data()), str.size()); }
        void UpdateData(std::string const& str) { UpdateData(std::string_view(str)); }
        void UpdateData(char const* str) { UpdateData(std::string_view(str)); }

        template <typename Container>
        void UpdateData(Container const& c) { UpdateData(std::data(c), std::size(c)); }

        void Finalize()
        {
            uint32 length;
            int result = EVP_DigestFinal_ex(_ctx, _digest.data(), &length);
        }

        Digest const& GetDigest() const { return _digest; }
    private:
        EVP_MD_CTX* _ctx{};
        Digest _digest{};
    };
}

namespace mpool::Crypto
{
    using MD5 = mpool::Impl::GenericHash<EVP_md5, Constants::MD5_DIGEST_LENGTH_BYTES>;
    using SHA1 = mpool::Impl::GenericHash<EVP_sha1, Constants::SHA1_DIGEST_LENGTH_BYTES>;
    using SHA256 = mpool::Impl::GenericHash<EVP_sha256, Constants::SHA256_DIGEST_LENGTH_BYTES>;
}

#endif //MPOOL_CRYPTOHASH_H
