#include "ThorpShuffler.hpp"
#include <doctest/doctest.h>


TEST_CASE("OptThorpObfuscator") {

	const uint64_t key = 4; // completely random I swear
	thorp::OptThorpObfuscator opt_obfuscator = thorp::OptThorpObfuscator::from_uint64(key, std::numeric_limits<uint64_t>::max());

	SUBCASE("roundtrip") {
		// decrypting an encrypted message should yield the original message.
		std::vector<uint64_t> test_vec{ 0,1,4,11,234112341,std::numeric_limits<uint64_t>::max() };
		for (auto elem : test_vec) {
			auto encrypted = opt_obfuscator.encrypt(elem);
			CHECK(encrypted != elem); // this is not strictly guaranteed but on a domain of 2**64 extemly unlikely. 
			CHECK(opt_obfuscator.decrypt(encrypted)==elem);
		};

	};

	SUBCASE("reverse") {
		// encrypting a decrypted message should yield the original message.
		std::vector<uint64_t> test_vec{ 0,1,4,11,234112341,std::numeric_limits<uint64_t>::max() };
		for (auto elem : test_vec) {
			auto decrypted = opt_obfuscator.decrypt(elem);
			CHECK(decrypted != elem); // this is not strictly guaranteed but on a domain of 2**64 extemly unlikely. 
			CHECK(opt_obfuscator.encrypt(decrypted)==elem);
		};

	};


};


TEST_CASE("ThorpObfuscator") {

	const uint64_t key = 4; // completely random I swear
	thorp::ThorpObfuscator obfuscator = thorp::ThorpObfuscator::from_uint64(key, std::numeric_limits<uint64_t>::max());

	SUBCASE("roundtrip") {
		// decrypting an encrypted message should yield the original message.
		std::vector<uint64_t> test_vec{ 0,1,4,11,234112341,std::numeric_limits<uint64_t>::max() };
		for (auto elem : test_vec) {
			auto encrypted = obfuscator.encrypt(elem);
			CHECK(encrypted != elem); // this is not strictly guaranteed but on a domain of 2**64 extemly unlikely. 
			CHECK(obfuscator.decrypt(encrypted) == elem);
		};

	};

	SUBCASE("reverse") {
		// encrypting a decrypted message should yield the original message.
		std::vector<uint64_t> test_vec{ 0,1,4,11,234112341,std::numeric_limits<uint64_t>::max() };
		for (auto elem : test_vec) {
			auto decrypted = obfuscator.decrypt(elem);
			CHECK(decrypted != elem); // this is not strictly guaranteed but on a domain of 2**64 extemly unlikely. 
			CHECK(obfuscator.encrypt(decrypted) == elem);
		};

	};


};