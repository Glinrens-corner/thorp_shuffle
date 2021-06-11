#pragma once
#include <type_traits>
#include <array>
#include <cstring>
#include <vector>
#include <numeric>
#include <cassert>
#include <limits>
#include <iostream>
#include <functional>
#include <sodium.h>

namespace thorpe {
    using byte_t = unsigned char;

    constexpr inline uint64_t passes_per_round(uint64_t max_message)noexcept;

   





    class ThorpeObfuscator {
    private:
       // static constexpr uint64_t half_max = max_message_ / 2+1;
    public:
        static constexpr uint64_t key_length = randombytes_SEEDBYTES;
    public:
        ThorpeObfuscator(std::array<byte_t,key_length> key, uint64_t max_message, uint64_t nrounds);
        static ThorpeObfuscator from_uint64(uint64_t key_number, uint64_t max_message);
        uint64_t encrypt(uint64_t plaintext)const;
        uint64_t decrypt(uint64_t cyphertext) const;
    private:
       
        static constexpr std::array<byte_t, sizeof(uint64_t)> generate_message(uint64_t);
        static bool generate_random_bit(uint64_t, const byte_t*, unsigned long long)noexcept;
    private:
        std::array<byte_t, key_length> key_;
        uint64_t nrounds_;
        uint64_t max_message_;
    };

    
    inline ThorpeObfuscator::ThorpeObfuscator(std::array<byte_t,key_length> key,uint64_t max_message, uint64_t nrounds)
        :key_{ key }    
        , nrounds_{ nrounds }
        , max_message_{max_message}{
        assert(max_message % 2 == 1);// Thorpe can only handle even message_spaces
    }


    inline constexpr std::array<byte_t, sizeof(uint64_t)> ThorpeObfuscator::generate_message(uint64_t message)
    {
        std::array<byte_t, sizeof(uint64_t)>message_out{};
        static_assert(sizeof(uint64_t) == 8, "need 8 byte integers");
        static_assert(CHAR_BIT == 8, "need 8 bit characters");
        constexpr uint64_t mask = std::numeric_limits<byte_t>::max();
        for (int ibyte = 0; ibyte < 8; ++ibyte) {
            message_out[ibyte] = static_cast<byte_t>((message >> 8 * ibyte) & mask);
        };
        return message_out;
    }


    inline ThorpeObfuscator ThorpeObfuscator::from_uint64(uint64_t key_number, uint64_t max_message)
    {
        std::array<byte_t, key_length>key{};
        for (auto& elem : key) elem = 0;
        static_assert(key_length >= 8, "too short key length");
        static_assert(CHAR_BIT == 8, "need 8 bit characters");
        constexpr uint64_t mask = std::numeric_limits<byte_t>::max();
        for (int ibyte = 0; ibyte < 8; ++ibyte) {
            key[ibyte] = static_cast<byte_t>((key_number >> 8 * ibyte) & mask);
        };
        return ThorpeObfuscator{key, max_message,8};
    }


    inline uint64_t ThorpeObfuscator::encrypt(uint64_t plaintext) const
    {
    auto passkey_ptr_fn =         [](
            const std::vector<byte_t>& random_data,
            uint64_t iround,
            uint64_t npasses_per_round,
            uint64_t ipass) {
                uint64_t offset = (iround * npasses_per_round + ipass) * crypto_generichash_KEYBYTES_MIN;
                return random_data.data() + offset; };
    uint64_t message = plaintext;
    const uint64_t npasses_per_round = passes_per_round(max_message_);
    const uint64_t npasskeys = npasses_per_round * this->nrounds_;
    const uint64_t npasskeys_bytes = npasskeys * crypto_generichash_KEYBYTES_MIN;
    const uint64_t half_max = this->max_message_ / 2 + 1;
    std::vector<byte_t> random_data(npasskeys_bytes, 0);
    assert(this->key_.size() >= randombytes_SEEDBYTES);// randombytes_buf_deterministic takes a unsigned char[randombytes_SEEDBYTES]
    randombytes_buf_deterministic(random_data.data(), npasskeys_bytes, this->key_.data());
    for (uint64_t iround = 0; iround < this->nrounds_; ++iround) {
        for (uint64_t ipass = 0; ipass < npasses_per_round; ++ipass) {
            uint64_t leading_bit = message / half_max;
            uint64_t remainder = message % half_max;
            const byte_t* const key_ptr = passkey_ptr_fn(random_data, iround, npasses_per_round, ipass);
            bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);
            message = remainder * 2 + leading_bit ^ (random_bit ? 1ull : 0ull);
        };
    };
    return message;
    }

    inline uint64_t ThorpeObfuscator::decrypt(uint64_t cyphertext) const
    {
        auto passkey_ptr_fn = [](
            const std::vector<byte_t>& random_data,
            uint64_t iround,
            uint64_t npasses_per_round,
            uint64_t ipass) {
                uint64_t offset = random_data.size()-(iround * npasses_per_round + ipass+1) * crypto_generichash_KEYBYTES_MIN;
                return random_data.data() + offset; };
        uint64_t message = cyphertext;
        const uint64_t npasses_per_round = passes_per_round(max_message_);
        const uint64_t npasskeys = npasses_per_round * this->nrounds_;
        const uint64_t npasskeys_bytes = npasskeys * crypto_generichash_KEYBYTES_MIN;
        std::vector<byte_t> random_data(npasskeys_bytes, 0);
        assert(this->key_.size() >= randombytes_SEEDBYTES);// randombytes_buf_deterministic takes a unsigned char[randombytes_SEEDBYTES]
        randombytes_buf_deterministic(random_data.data(), npasskeys_bytes, this->key_.data());
        const uint64_t half_max = this->max_message_ / 2 + 1;
        for (uint64_t iround = 0; iround < this->nrounds_; ++iround) {
            for (uint64_t ipass = 0; ipass < npasses_per_round; ++ipass) {
                uint64_t leading_bit = message %2;
                uint64_t remainder = message /2;
                const byte_t* const key_ptr = passkey_ptr_fn(random_data, iround, npasses_per_round, ipass);
                bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);

                message = remainder  + (leading_bit ^ (random_bit ? 1ull : 0ull))*half_max;
            };
        };
        return message;
    }


    inline bool ThorpeObfuscator::generate_random_bit(uint64_t remainder, const byte_t*pass_key, unsigned long long passkey_length) noexcept
    {
        std::array<byte_t, sizeof(uint64_t) > in_message = generate_message(remainder);
        std::array<byte_t, crypto_generichash_BYTES_MIN> out_message{};
        crypto_generichash(out_message.data(), out_message.size(),
            in_message.data(), in_message.size(),
            pass_key, crypto_generichash_KEYBYTES_MIN);
        byte_t reduced_output = std::accumulate(
            out_message.begin(), out_message.end(), 
            static_cast<byte_t>(0), 
            [](byte_t left, byte_t right) ->byte_t {return left ^ right; });
        reduced_output = reduced_output ^ (reduced_output >> 4);
        reduced_output = reduced_output ^ (reduced_output >> 2);
        reduced_output = reduced_output ^ (reduced_output >> 1);

        return static_cast<bool>(reduced_output & 1);
    }
    ;

    constexpr inline uint64_t passes_per_round(uint64_t max_message)noexcept
    {
        uint64_t carry = 0x01;
        bool larger_than = false;
        uint64_t bitfield = max_message;
        for (uint64_t ibit = 0; ibit <= 65; ++ibit) {
            uint64_t last_bit = bitfield & 0x01;
            uint64_t next_carry = last_bit & carry;
            last_bit = last_bit ^ carry;
            carry = next_carry;
            uint64_t remaining_bits = bitfield >> 1;
            if (remaining_bits > 0 || carry > 0) {
                if (last_bit == 1) {
                    larger_than = true;
                    bitfield = remaining_bits;

                }
                else {
                    bitfield = remaining_bits;
                };
            }

            else {
                if (last_bit == 1) {
                    return larger_than ? ibit + 1 : ibit;
                }
                else {
                    assert(false);
                };
            };
        };
        assert(false);
    };
}
