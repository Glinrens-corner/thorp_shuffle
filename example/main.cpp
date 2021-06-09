#include <sodium.h>
#include <iostream>
#include "ThorpeShuffler.hpp"
int main() {
    if (sodium_init() == -1) {
        return 1;
    };
    using shuffler_t = thorpe::ThorpeObfuscator<0xFFFF>;
    std::array<thorpe::byte_t, shuffler_t::key_length> key{995};
    shuffler_t shuffler{ key,1 };
    const uint64_t plaintext{ 0xF1 };
    std::cout <<    " from message: " << plaintext << std::endl;
    const uint64_t cyphertext = shuffler.encrypt(plaintext);
    std::cout <<    "encrypted: " <<  cyphertext<< std::endl;

    std::cout << "decrypted: " << shuffler.decrypt(cyphertext) << std::endl;
    return 0;


};