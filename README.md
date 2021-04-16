# 🚀 SHA-1
A (dummy) implementation of the SHA-1 encryption algorithm written for educational purposes. Includes a birthday attack which finds collisions on the first 32 bits of different output digests.

The accuracy is tested both using the official test arrays (available as resources in the repo) and Python's hashlib implementation of SHA-1.
There's also illustrated the avalanche effect - making use of the Hamming distance.
For the attack, the algorithm generates random strings of different lengths and hashes them until it finds two strings with the same first 32 bits of the digest.

Note: You should not use SHA-1 as a stable encryption method, since it's not considered safe anymore due to the possibility of finding full collisions at some point in the future.
