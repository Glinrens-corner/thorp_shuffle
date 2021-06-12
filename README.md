# Thorp Shuffle

Here in Glinrens-corner I am dedicated to bringing **you** state of the art technology, today by implementing  the paper of Ben Morris, Phillip Rogaway and Till Stegers "How to Encipher Messages on a Small Domain" from 2007.

In that paper the authors showed that the thorp shuffle can be used to encrypt very short messages(up to some hundreds of bits.)
In a shuffle every element associates two positions (the position before the shuffle and the position after the shuffle) by interpreting the position before the shuffle as message and the position after the shuffle as encrypted message we can use a shuffle algorithm as encryption algorithm if 
 * the algorithm is reversible (so we can decrypt an encrypted message).
 * the algorithm can calculate the shuffled position efficiently.
 * the algorithm is cryptographically secure. 
 
The thorp shuffle naturally fulfills the first two requirements. The mentioned paper show the thrid one. 


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
Note that this project depends upon libsodium and doctest if you do not have them installed xmake will download and make them available. 
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

  