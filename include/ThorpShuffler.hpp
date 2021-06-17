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

//before trying to understand this code, please read the paper by
//  Ben Morris, Phillip Rogawayand and Till Stegers "How to Encipher Messages on a Small Domain" 2009.
//https://doi.org/10.1007/978-3-642-03356-8_17
// especially chaper 1 and 5 are assumed as known.

namespace thorp {
    // likely identical to std::byte_t;
    using byte_t = unsigned char;

    constexpr inline uint64_t nrounds_per_pass(uint64_t max_message)noexcept;

    // Old implementation. 
    class ThorpObfuscator {
    public:
        ThorpObfuscator(std::vector<byte_t> round_keys_data, uint64_t max_message, uint64_t npasses);
        static ThorpObfuscator from_uint64(uint64_t key_number, uint64_t max_message);
        static constexpr uint64_t round_keys_data_size(uint64_t npasses, uint64_t max_message);
        uint64_t encrypt(uint64_t plaintext)const;
        uint64_t decrypt(uint64_t cyphertext) const;
    private:
        static constexpr std::array<byte_t, sizeof(uint64_t)> generate_message(uint64_t);
        static bool generate_random_bit(uint64_t, const byte_t*, unsigned long long)noexcept;
    private:
        std::vector<byte_t> passkeys_data_;
        uint64_t npasses_;
        uint64_t max_message_;
    };

    constexpr inline uint64_t calculate_optimization_level_max() {
        // libsodium uses blake2d wich generates up to 512 bits.
        static_assert(crypto_generichash_BYTES_MAX * CHAR_BIT == 512, "unexpected hash length");
        //the largest number such that k*2^(k-1) <= bits in the hash.
        // see the paper chaper 5.
        return 7;
    };

    // more newerimplementation, incorporates the "5x" trick (which is here a up to 7x trick).
    class OptThorpObfuscator {
        static constexpr uint64_t hash_size_ = crypto_generichash_BYTES_MAX;
    public:
        static constexpr uint64_t optimization_level_max =  calculate_optimization_level_max();
    public:
        OptThorpObfuscator(std::vector<byte_t> round_keys_data, uint64_t max_message, uint64_t npasses, uint64_t optimization_lvl);
        static OptThorpObfuscator from_uint64(uint64_t key_number, uint64_t max_message);
        static constexpr uint64_t round_keys_data_size(uint64_t npasses, uint64_t max_message, uint64_t optimization_level);
        uint64_t encrypt(uint64_t plaintext)const;
        uint64_t decrypt(uint64_t cyphertext) const;
    private:
        std::vector<byte_t> round_keys_data_;
        uint64_t npasses_;
        uint64_t max_message_;
        uint64_t optimization_level_;

    };
}//thorp

namespace thorp{
    inline constexpr std::array<byte_t, sizeof(uint64_t)> ThorpObfuscator::generate_message(uint64_t message)
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
    // calculate the minimum number of bytes the ThorpObfuscator requires upon instanciation.
    inline constexpr uint64_t ThorpObfuscator::round_keys_data_size(uint64_t npasses, uint64_t max_message)
    {
        const uint64_t nrounds = nrounds_per_pass(max_message) * npasses;
        const uint64_t nroundkeys_bytes_sum = nrounds * crypto_generichash_KEYBYTES_MIN;
        return nroundkeys_bytes_sum;
    }

    // calculate the minimum number of bytes the OptThorpObfuscator requires upon instanciation.
    constexpr inline uint64_t OptThorpObfuscator::round_keys_data_size(uint64_t npasses, uint64_t max_message, uint64_t optimization_level)
    {
        const uint64_t nrounds = nrounds_per_pass(max_message) * npasses;
        const uint64_t nopt_rounds = nrounds / optimization_level + (nrounds % optimization_level > 0 ? 1 : 0);
        const uint64_t nroundkeys_bytes_sum = nrounds * crypto_generichash_KEYBYTES_MIN;
        return nroundkeys_bytes_sum;
    }
    
    
    // calculates the number of rounds needed per pass.
    // ceil(log_2(N_domain))
    constexpr inline uint64_t nrounds_per_pass(uint64_t max_message)noexcept
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
                    //assert(false);
                };
            };
        };
        //assert(false);
    };
}
