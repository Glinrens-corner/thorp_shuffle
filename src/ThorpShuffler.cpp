#include "ThorpShuffler.hpp"

namespace thorpe {
    ThorpObfuscator::ThorpObfuscator(std::vector<byte_t> passkeys_data, uint64_t max_message, uint64_t npasses)
        :passkeys_data_{ std::move(passkeys_data) }
        , npasses_{ npasses }
        , max_message_{ max_message }{
        const uint64_t nrounds = nrounds_per_pass(max_message) * this->npasses_;
        const uint64_t nroundkeys_bytes_sum = nrounds * crypto_generichash_KEYBYTES_MIN;
        assert(this->passkeys_data_.size() >= nroundkeys_bytes_sum);
        assert(this->max_message_ % 2 == 1);// Thorpe can only handle even message_spaces
    }

    ThorpObfuscator ThorpObfuscator::from_uint64(uint64_t key_number, uint64_t max_message)
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
        return ThorpObfuscator{ round_keys_data, max_message,npasses };
    }


    bool ThorpObfuscator::generate_random_bit(uint64_t remainder, const byte_t* pass_key, unsigned long long passkey_length) noexcept
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

    uint64_t ThorpObfuscator::encrypt(uint64_t plaintext) const
    {
        auto passkey_ptr_fn = [this](
            uint64_t iround) {
                uint64_t offset = iround * crypto_generichash_KEYBYTES_MIN;
                return this->passkeys_data_.data() + offset; };

        uint64_t message = plaintext;
        const uint64_t half_max = this->max_message_ / 2 + 1;
        const uint64_t nrounds = nrounds_per_pass(this->max_message_) * this->npasses_;
        for (uint64_t iround = 0; iround < nrounds; ++iround) {
            uint64_t leading_bit = message / half_max;
            uint64_t remainder = message % half_max;
            const byte_t* const key_ptr = passkey_ptr_fn(iround);
            bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);
            message = remainder * 2 + leading_bit ^ (random_bit ? 1ull : 0ull);
        };
        return message;
    }

    uint64_t ThorpObfuscator::decrypt(uint64_t cyphertext) const
    {

        auto passkey_ptr_fn = [this](
            uint64_t iround) {
                uint64_t offset = (iround ) * crypto_generichash_KEYBYTES_MIN;
                return this->passkeys_data_.data() + offset; };
        uint64_t message = cyphertext;
        const uint64_t half_max = this->max_message_ / 2 + 1;

        const uint64_t nrounds = nrounds_per_pass(this->max_message_) * this->npasses_;
        for (uint64_t iround = 0; iround < nrounds; ++iround) {
                uint64_t leading_bit = message % 2;
                uint64_t remainder = message / 2;
                const byte_t* const key_ptr = passkey_ptr_fn(nrounds-iround-1);
                bool random_bit = generate_random_bit(remainder, key_ptr, crypto_generichash_KEYBYTES_MIN);
                message = remainder + (leading_bit ^ (random_bit ? 1ull : 0ull)) * half_max;
        };
        return message;
    }
} //thorpe
namespace {
    class OptimizedBitGenerator {
    private:
        using byte_t = thorpe::byte_t;
    public:
        static constexpr  uint64_t hash_size = crypto_generichash_BYTES_MAX;
        static constexpr uint64_t pass_key_size = crypto_generichash_KEYBYTES_MIN;

    public:
        OptimizedBitGenerator(
            const std::vector<byte_t>* pass_key_data,
            uint64_t max_message,
            uint64_t optimization_level
        );
        thorpe::byte_t generate_bit(uint64_t message, uint64_t iround);
        std::pair<uint64_t, uint64_t> opt_pass_parameters(uint64_t iround) const noexcept;
    private:
        byte_t generate_bit_core( uint64_t iopt_round, uint64_t iopt_pass, uint64_t selector);
        void update_hash(uint64_t remainder, uint64_t ipass);
        static constexpr std::array < byte_t, sizeof(uint64_t)> generate_message(uint64_t remainder);
    private:
        const std::vector<byte_t>* pass_key_data_;
        uint64_t max_message_;
        uint64_t optimization_level_;
        std::vector<byte_t> cached_hash_{};
        uint64_t cached_opt_round_{}; 
    };


    OptimizedBitGenerator::OptimizedBitGenerator(
        const std::vector<byte_t>* pass_key_data,
        uint64_t max_message,
        uint64_t optimization_level)
        :pass_key_data_{ pass_key_data }
        , max_message_{ max_message }
        , optimization_level_{ optimization_level }
    {
    };

    auto OptimizedBitGenerator::generate_bit(uint64_t message, uint64_t iround)->byte_t
    {
        // equiv x:= equivalent to x in Fig.6 ;
#pragma warning disable 65
        auto [iopt_pass, iopt_round] = this->opt_pass_parameters(iround); // equiv j,i
        const uint64_t projector = (this->max_message_ /2+1) >> (this->optimization_level_-1);  // equiv N/32
        const uint64_t remainder = (message >> iopt_pass)% projector;          // equiv  a
        const uint64_t hi = (message >> iopt_pass) / projector;                // equiv hi

        const uint64_t lo = message % (1ull << iopt_pass);                        // equiv lo
        const uint64_t selector = (hi << iopt_pass) + lo;                      // equic b
        if (this->cached_hash_.size() != hash_size || this->cached_opt_round_ != iopt_round) {
            this->update_hash(remainder, iopt_round);
        };
        return this->generate_bit_core(iopt_pass,  iopt_round, selector);
    }

    std::pair<uint64_t, uint64_t> OptimizedBitGenerator::opt_pass_parameters(uint64_t iround) const noexcept
    {
        const uint64_t iopt_pass = iround % this->optimization_level_; // equivalent to j in  Fig.6
        const uint64_t iopt_round = iround /this->optimization_level_; // equivalent to i in  Fig.6
        return std::pair<uint64_t, uint64_t>(iopt_pass, iopt_round);
    }

    thorpe::byte_t OptimizedBitGenerator::generate_bit_core(uint64_t iopt_pass,uint64_t iopt_round, uint64_t selector)
    {
        assert(this->cached_opt_round_ == iopt_round);
        assert(selector < (1ull << (this->optimization_level_ - 1)));
        const uint64_t ibit = iopt_pass * (1ull << (this->optimization_level_ - 1)) + selector;
        const byte_t selected_byte = this->cached_hash_[ibit / 8];
        return (selected_byte>> (ibit%8)) & 1;
    }

    void OptimizedBitGenerator::update_hash(uint64_t remainder, uint64_t iround)
    {
        std::array<byte_t, sizeof(uint64_t) > in_message = generate_message(remainder);
        this->cached_hash_.resize(hash_size, 0);
        const byte_t* pass_key_ptr= this->pass_key_data_->data() + pass_key_size * iround;

        crypto_generichash(this->cached_hash_.data(), this->cached_hash_.size(),
            in_message.data(), in_message.size(),
            pass_key_ptr, pass_key_size);
        this->cached_opt_round_ = iround;
    }

    /**
    * reformats  a uint64_t to an array of bytes suitable to pass it to the hash function.
    */
    constexpr  auto OptimizedBitGenerator::generate_message(uint64_t remainder)->std::array<byte_t,sizeof(uint64_t)>
    {

        std::array<byte_t, sizeof(uint64_t)>message_out{};
        static_assert(sizeof(uint64_t) == 8, "need 8 byte integers");
        static_assert(CHAR_BIT == 8, "need 8 bit characters");
        constexpr uint64_t mask = std::numeric_limits<byte_t>::max();
        for (int ibyte = 0; ibyte < 8; ++ibyte) {
            message_out[ibyte] = static_cast<byte_t>((remainder >> 8 * ibyte) & mask);
        };
        return message_out;
    }

}
namespace thorpe {
    OptThorpObfuscator::OptThorpObfuscator(std::vector<byte_t> passkeys_data, 
        uint64_t max_message, 
        uint64_t npasses, uint64_t optimization_level)
        :passkeys_data_{ std::move(passkeys_data) }
        , npasses_{ npasses }
        , max_message_{ max_message }
        , optimization_level_{optimization_level}{

        const uint64_t nrounds = nrounds_per_pass(max_message) * this->npasses_;
        const uint64_t nroundkeys_bytes_sum = nrounds * crypto_generichash_KEYBYTES_MIN;
        assert(this->passkeys_data_.size() >= nroundkeys_bytes_sum);
        assert(this->max_message_ % 2 == 1);// Thorpe can only handle even message_spaces
    }
    OptThorpObfuscator OptThorpObfuscator::from_uint64(uint64_t key_number, const uint64_t max_message){
    constexpr uint64_t key_length = randombytes_SEEDBYTES;
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
    return OptThorpObfuscator{ round_keys_data, max_message,npasses , 7};
    }
    ;

    uint64_t OptThorpObfuscator::encrypt(uint64_t plaintext) const
    {
        uint64_t message = plaintext;
        const uint64_t half_max = this->max_message_ / 2 + 1;
        const uint64_t nrounds = nrounds_per_pass(this->max_message_) * this->npasses_;
        OptimizedBitGenerator bit_generator(&this->passkeys_data_, this->max_message_, this->optimization_level_);
        for (uint64_t iround = 0; iround < nrounds; ++iround) {
            uint64_t leading_bit = message / half_max;
            uint64_t remainder = message % half_max;
            byte_t random_bit = bit_generator.generate_bit(message%half_max, iround);
            assert(random_bit == 1 || random_bit == 0);
            message = remainder * 2 + random_bit^leading_bit;
        };
        return message;
    }

    uint64_t OptThorpObfuscator::decrypt(uint64_t cyphertext) const
    {

        uint64_t message = cyphertext;
        const uint64_t half_max = this->max_message_ / 2 + 1;
        const uint64_t nrounds = nrounds_per_pass(this->max_message_) * this->npasses_;
        OptimizedBitGenerator bit_generator(&this->passkeys_data_, this->max_message_, this->optimization_level_);
        for (uint64_t iround = 0; iround < nrounds; ++iround) {
            uint64_t trailing_bit = message % 2;
            uint64_t remainder = message /2;
            byte_t random_bit = bit_generator.generate_bit(message>>1, (nrounds - 1 - iround));
            assert(random_bit == 1 || random_bit == 0);
            message = remainder + half_max*(random_bit^trailing_bit);
        };
        return message;
    }


};