#include <sodium.h>
#include <iostream>
#include "ThorpShuffler.hpp"
int main() {
    if (sodium_init() == -1) {
        return 1;
    };
    using shuffler_t = thorpe::ThorpObfuscator;
    using opt_shuffler_t = thorpe::OptThorpObfuscator;
    uint64_t key;

    std::cout << "please enter a key ( a number smaller than or equal to " << std::numeric_limits<uint64_t>::max() << "): " << std::flush;
    std::cin >> key ;
    const uint64_t max_message = std::numeric_limits<uint64_t>::max();
    shuffler_t shuffler = shuffler_t::from_uint64(key, max_message);
    opt_shuffler_t opt_shuffler = opt_shuffler_t::from_uint64(key, std::numeric_limits<uint64_t>::max()) ;
    uint64_t plaintext;
    std::cout << "please enter a message ( a number smaller than or equal to " << std::numeric_limits<uint64_t>::max() << "): " << std::flush;
    std::cin >> plaintext;
    std::cout <<    "from message: " << plaintext << std::endl;
    {
        const uint64_t cyphertext = shuffler.encrypt(plaintext);
        std::cout << " simple-encrypted: " << cyphertext << std::endl;

        std::cout << "simple-decrypted: " << shuffler.decrypt(cyphertext) << std::endl;
    };
    {
        const uint64_t cyphertext = opt_shuffler.encrypt(plaintext);
        std::cout << " optimized-encrypted: " << cyphertext << std::endl;

        std::cout << "optimized-decrypted: " << opt_shuffler.decrypt(cyphertext) << std::endl;
    };
    return 0;


};