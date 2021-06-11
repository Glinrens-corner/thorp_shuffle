#include "ThorpeShuffler.hpp"

namespace thorpe {
    ThorpeObfuscator::ThorpeObfuscator(std::vector<byte_t> random_data, uint64_t max_message, uint64_t npasses)
        :random_data_{ std::move(random_data) }
        , npasses_{ npasses }
        , max_message_{ max_message }{
        const uint64_t nrounds = nrounds_per_pass(max_message) * this->npasses_;
        const uint64_t nroundkeys_bytes_sum = nrounds * crypto_generichash_KEYBYTES_MIN;
        assert(this->random_data_.size() >= nroundkeys_bytes_sum);
        assert(this->max_message_ % 2 == 1);// Thorpe can only handle even message_spaces
    }

    ThorpeObfuscator ThorpeObfuscator::from_uint64(uint64_t key_number, uint64_t max_message)
    {
        const uint64_t npasses = 8;
        std::array<byte_t, key_length>key{};
        for (auto& elem : key) elem = 0;
        static_assert(key_length >= 8, "too short key length");
        static_assert(CHAR_BIT == 8, "need 8 bit characters");
        constexpr uint64_t mask = std::numeric_limits<byte_t>::max();
        for (int ibyte = 0; ibyte < 8; ++ibyte) {
            key[ibyte] = static_cast<byte_t>((key_number >> 8 * ibyte) & mask);
        };
        std::vector<byte_t> round_keys_data(round_keys_data_size(npasses, max_message), 0);
        assert(key.size() >= randombytes_SEEDBYTES); // randombytes_buf_deterministic takes a unsigned char[randombytes_SEEDBYTES]
        randombytes_buf_deterministic(round_keys_data.data(), round_keys_data.size(), key.data());
        return ThorpeObfuscator{ round_keys_data, max_message,npasses };
    }


    bool ThorpeObfuscator::generate_random_bit(uint64_t remainder, const byte_t* pass_key, unsigned long long passkey_length) noexcept
    {
        std::array<byte_t, sizeof(uint64_t) > in_message = generate_message(remainder);
        std::array<byte_t, crypto_generichash_BYTES_MIN> out_message{};
        crypto_generichash(out_message.data(), out_message.size(),
            in_message.data(), in_message.size(),
            pass_key, passkey_length);
        byte_t reduced_output = std::accumulate(
            out_message.begin(), out_message.end(),
            static_cast<byte_t>(0),
            [](byte_t left, byte_t right) ->byte_t {return left ^ right; });
        reduced_output = reduced_output ^ (reduced_output >> 4);
        reduced_output = reduced_output ^ (reduced_output >> 2);
        reduced_output = reduced_output ^ (reduced_output >> 1);

        return static_cast<bool>(reduced_output & 1);
    }

    uint64_t ThorpeObfuscator::encrypt(uint64_t plaintext) const
    {
        const uint64_t nrounds_per_pass_ = nrounds_per_pass(this->max_message_);
        auto passkey_ptr_fn = [this, nrounds_per_pass_](
            uint64_t iround,
            uint64_t ipass) {
                uint64_t offset = (iround * nrounds_per_pass_ + ipass) * crypto_generichash_KEYBYTES_MIN;
                return this->random_data_.data() + offset; };

        uint64_t message = plaintext;
        const uint64_t half_max = this->max_message_ / 2 + 1;

        for (uint64_t iround = 0; iround < this->npasses_; ++iround) {
            for (uint64_t ipass = 0; ipass < nrounds_per_pass_; ++ipass) {
                uint64_t leading_bit = message / half_max;
                uint64_t remainder = message % half_max;
                const byte_t* const key_ptr = passkey_ptr_fn(iround, ipass);
                bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);
                message = remainder * 2 + leading_bit ^ (random_bit ? 1ull : 0ull);
            };
        };
        return message;
    }

    uint64_t ThorpeObfuscator::decrypt(uint64_t cyphertext) const
    {
        const uint64_t nrounds_per_pass_ = nrounds_per_pass(this->max_message_);
        auto passkey_ptr_fn = [this, nrounds_per_pass_](
            uint64_t iround,
            uint64_t ipass) {
                uint64_t offset = this->random_data_.size() - (iround * nrounds_per_pass_ + ipass + 1) * crypto_generichash_KEYBYTES_MIN;
                return this->random_data_.data() + offset; };
        uint64_t message = cyphertext;
        const uint64_t half_max = this->max_message_ / 2 + 1;

        for (uint64_t iround = 0; iround < this->npasses_; ++iround) {
            for (uint64_t ipass = 0; ipass < nrounds_per_pass_; ++ipass) {
                uint64_t leading_bit = message % 2;
                uint64_t remainder = message / 2;
                const byte_t* const key_ptr = passkey_ptr_fn(iround, ipass);
                bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);
                message = remainder + (leading_bit ^ (random_bit ? 1ull : 0ull)) * half_max;
            };
        };
        return message;
    }
} //thorpe
