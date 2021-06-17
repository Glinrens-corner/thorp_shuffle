#include "ThorpShuffler.hpp"
#include <doctest/doctest.h>


TEST_CASE("OptThorpObfuscator") {
	sodium_init();
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
	SUBCASE("max_message=opt_level-1") {

		SUBCASE("opt_level=1") {
			std::vector<thorp::byte_t>key_vec(10000, 173);
			thorp::OptThorpObfuscator obfuscator2 = thorp::OptThorpObfuscator{ key_vec,1,2,1 };
			std::vector<uint64_t> test_vec{ 0,1 };
			for (auto elem : test_vec) {
				auto encrypted = obfuscator2.encrypt(elem);
				CHECK(encrypted <= 1);
				CHECK(obfuscator2.decrypt(encrypted) == elem);
			};
		};
		SUBCASE("opt_level=2") {
			std::vector<thorp::byte_t>key_vec(10000, 173);
			thorp::OptThorpObfuscator obfuscator2 = thorp::OptThorpObfuscator{ key_vec,3,2,2 };
			std::vector<uint64_t> test_vec{ 0,1,2,3 };
			for (auto elem : test_vec) {
				auto encrypted = obfuscator2.encrypt(elem);
				CHECK(encrypted <= 3);
				CHECK(obfuscator2.decrypt(encrypted) == elem);
			};
		};
		SUBCASE("opt_level=3") {
			std::vector<thorp::byte_t>key_vec(10000, 173);
			thorp::OptThorpObfuscator obfuscator2 = thorp::OptThorpObfuscator{ key_vec,7,2,3 };
			std::vector<uint64_t> test_vec{ 0,1, 2,3 ,4,5,6,7};
			for (auto elem : test_vec) {
				auto encrypted = obfuscator2.encrypt(elem);
				CHECK(encrypted <= 7);
				CHECK(obfuscator2.decrypt(encrypted) == elem);
			};
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
	sodium_init();

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

	SUBCASE("max_message=1") {

		const uint64_t key = 4; // completely random I swear
		thorp::ThorpObfuscator obfuscator2 = thorp::ThorpObfuscator::from_uint64(key, 1);
		std::vector<uint64_t> test_vec{ 0,1 };
		for (auto elem : test_vec) {
			auto encrypted = obfuscator2.encrypt(elem);
			CHECK(encrypted <= 1); 
			CHECK(obfuscator2.decrypt(encrypted) == elem);
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