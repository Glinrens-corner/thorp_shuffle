# Thorp Shuffle

Here in Glinrens-corner I am dedicated to bringing **you** state of the art technology, today by implementing  the paper of Ben Morris, Phillip Rogaway and Till Stegers "How to Encipher Messages on a Small Domain" from 2009 [link](https://doi.org/10.1007/978-3-642-03356-8_17).

In that paper the authors showed that the thorp shuffle can be used to encrypt very short messages(up to some hundreds of bits.)
In a shuffle every element associates two positions (the position before the shuffle and the position after the shuffle) by interpreting the position before the shuffle as message and the position after the shuffle as encrypted message we can use a shuffle algorithm as encryption algorithm if 
 * the algorithm is reversible (so we can decrypt an encrypted message).
 * the algorithm can calculate the shuffled position efficiently.
 * the algorithm is cryptographically secure. 
 
The thorp shuffle naturally fulfills the first two requirements. The mentioned paper show the third one. 


## Thorp as a Shuffle

One important difference between thorp and better known shuffling algorithms such as Fisher-Yates shuffle is that Fisher-Yates takes a list of elements and a number of random bits and returns a shuffled list.
Thorp takes an index of an element and source of randomness and calculates the shuffled position of that element. (Thorp can also be used to calculate from a shuffled index which element would be there .)
The algorithm is therefore very well suited for cases where the shuffled list should not actually be materialized.


## Thorp as Obfuscator
To be clear the Paper shows that the thorp shuffle is reasonably secure agains common types of attacks.However:
 * compared to other encryption algorithms thorp has not received much attention. It has not been subjected to the intense cyptoanalysis of other encryption algorithms.
 * this is literally the first time I have implemented a cryptoalgorithm and it has as of yet not been reviewed in any way.

For these reasons I do not recommend the current implementation to protect data of significant value. 

However if you just wish to e.g. avoid leaking information about the order in which your documents were created while still generationg sequential ids this implementation might be sufficient.


 ### Usage 
This repository uses xmake to build. 

The following wil build and run the tests.
Note that this project depends upon libsodium and doctest if you do not have them installed xmake will download them. 
````
xmake config --mode=release
xmake build test
xmake run test
````

After the configuration step you can also build and run a simple example cli program.
````
xmake build example
xmake run example
````

You can also use it as a static library
  
Just include the following in your xmake.lua.

````
add_repositories("glinren-experimental https://github.com/Glinrens-corner/experimental-repo.git")_
add_requires("thorpshuffle", "libsodium")_
...

target(...)
    ...
    add_packages("thorpshuffle", "libsodium")_
````

Ìn your code you should initialize libsodium before calling any function of the thorpshuffle:
````
#include <sodium.h>


int main(){
   if(sodium_init() == -1){
       return 1;
  };
...
}
````

Afterwards the shuffler can be instanciated:

in ``ThorpShuffler.hpp``:
```` 
thorp::ThorpObfuscator(
             std::vector<unsigned char> round_keys_data, 
             uint64_t max_message, 
             uint64_t number_of_passes)
thorp::OptThorpObfuscator(
             std::vector<unsigned char> round_keys_data, 
             uint64_t max_message, 
             uint64_t number_of_passes, 
             uint64_t optimization_level)
````
``round_keys_data`` takes an vector of random bytes used to encrypt and decrypt the message.
The minimum length can be calculated via 
````
thorp::ThorpObfuscator::round_keys_data_size(
            uint64_t number_of_passes,  
            uint64_t max_message)
thorp::OptThorpObfuscator::round_keys_data_size(
            uint64_t number_of_passes,  
            uint64_t max_message, 
            uint64_t optimization_level)
````

``max_message`` specifies the largest message this Obfuscator can encrypt.
In terms of a shuffle it is the position of the last element (so size -1).

Note that max_message must be odd and larger or equal to (2^optimization_level - 1) (at least 1 for the ``ThorpObfuscator``).
Yes that means this implementation can only shuffle vectors of even size.

``optimization_level``  is the factor to which the 5x trick from the paper is implemented.
The optimization level the required time and size of the pass\_keys\_data so if the domain allows it the maximum level should be choosen.
The maximum optimization\_level is 7 (libsodium uses hashes with larger digests. So the 5x trick becomes a 7x trick.)


Once instanciated the obfuscator can be used to encrypt and decrypt a message. 

````
uint64_t message = ...;
assert(obfuscator.decrypt(obfuscator.encrypt(message)) == message);
````

for shuffling:
````
class ShuffledVector{
 ...
  reference operator(std::size_t i)[]{
     this->base_vector[this->obfuscator.encrypt(i)];
  };
}
````


