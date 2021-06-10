#include <sodium.h>
#include <iostream>
#include "ThorpeShuffler.hpp"
int main() {
    if (sodium_init() == -1) {
        return 1;
    };
    using shuffler_t = thorpe::ThorpeObfuscator<std::numeric_limits<uint64_t>::max()>;

    uint64_t key;

    std::cout << "please enter a key ( a number smaller than or equal to " << std::numeric_limits<uint64_t>::max() << "): " << std::flush;
    std::cin >> key ;
    shuffler_t shuffler =shuffler_t::from_uint64(key);
    uint64_t plaintext;
    std::cout << "please enter a message ( a number smaller than or equal to " << std::numeric_limits<uint64_t>::max() << "): " << std::flush;
    std::cin >> plaintext;
    std::cout <<    "from message: " << plaintext << std::endl;
    const uint64_t cyphertext = shuffler.encrypt(plaintext);
    std::cout <<    "encrypted: " <<  cyphertext<< std::endl;

    std::cout << "decrypted: " << shuffler.decrypt(cyphertext) << std::endl;
    return 0;


};