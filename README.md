This resource implements primitives which are useful for other resources

- libsodium_bindings: rust bindings for lib sodium 1.18 which provides many crypto primitives, in particular around the Curve 25519 and ShaSha
- aes_256_gcm: an api to use AES 256 GCM (which calls libsodium)
- primes: routines to extract prime numbers up to 2^400
- cs_prng: A cryptographically secure pseudo random generator that generates Big Int(s)
- brc_cprf: BRC, a constrained PRF (see below)
- aes_hash_mmo.rs: using the native implementation of AES 256 as a hash function.
- timed_cache: a thread safe memory cache where items expire after a certain time
- timed_caches: a WIP. Do not use for now



## Constrained PRF

This construct is a simple and efficient range-constrained PRF from the tree-based GGM PRF [GGM84].This instantiation has been described by Kiayiaset al.[KPTZ13](https://people.csail.mit.edu/stavrosp/papers/ccs2013/CCS13_DPRF.pdf) and is called best range cover (BRC).


![BRC](img/BRC.jpg)

### Benchmarks

Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz - 6400 bogomips . Single Threaded.

```
Bench of leaves generation from a node with varying depth (2500 rounds per depth)
Average: 76 nano per leave for depth: 4 (16 leaves)
Average: 79 nano per leave for depth: 5 (32 leaves)
Average: 79 nano per leave for depth: 6 (64 leaves)
Average: 81 nano per leave for depth: 7 (128 leaves)
Average: 80 nano per leave for depth: 8 (256 leaves)
Average: 79 nano per leave for depth: 9 (512 leaves)
Average: 78 nano per leave for depth: 10 (1024 leaves)
Average: 78 nano per leave for depth: 11 (2048 leaves)
Average: 77 nano per leave for depth: 12 (4096 leaves)
Average: 77 nano per leave for depth: 13 (8192 leaves)
Average: 76 nano per leave for depth: 14 (16384 leaves)
Average: 77 nano per leave for depth: 15 (32768 leaves)
Average: 77 nano per leave for depth: 16 (65536 leaves)
```

```
Bench of a trapdoor serialization/de-serialization averaged over 50000 rounds
   - 1 nodes: serialization/de-serialization 49/38 nanos)
   - 2 nodes: serialization/de-serialization 54/39 nanos)
   - 3 nodes: serialization/de-serialization 55/40 nanos)
   - 4 nodes: serialization/de-serialization 69/49 nanos)
   - 5 nodes: serialization/de-serialization 69/47 nanos)
   - 6 nodes: serialization/de-serialization 73/49 nanos)
   - 7 nodes: serialization/de-serialization 68/47 nanos)
   - 8 nodes: serialization/de-serialization 73/50 nanos)
   - 9 nodes: serialization/de-serialization 83/55 nanos)
   - 10 nodes: serialization/de-serialization 82/56 nanos)
```

## AES as a Hash Function

Using the native implementation of AES 256 as a hash function.

Implements the scheme of  S. Matyas, C. Meyer and J. Oseas
Hᵢ = E(Hᵢ₋₁, Xᵢ)^Xᵢ^Hᵢ₋₁ where the AES
encryption of plaintext X with key K will is denoted with E(K, X)

see https://www.esat.kuleuven.be/cosic/publications/article-48.pdf

Since the block size is 16 and we need to encrypt 32 bytes (top get a 256 bit hash)
we use AES in counter mode to encrypt two blocks of 16 bytes


### Benchmarks

The Sha256 implementation is that of libsodium.
The AES MMO implementation is particularly performing for data length
which are multiple of 32 bytes.

Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz - 4800 bogomips . Single Threaded.

```
Average over 500000 rounds of 16 data bytes: nano per hash aes: 107; sha256 325
Average over 500000 rounds of 32 data bytes: nano per hash aes: 111; sha256 326
Average over 500000 rounds of 48 data bytes: nano per hash aes: 188; sha256 323
Average over 500000 rounds of 64 data bytes: nano per hash aes: 192; sha256 629
Average over 500000 rounds of 80 data bytes: nano per hash aes: 270; sha256 628
Average over 500000 rounds of 96 data bytes: nano per hash aes: 270; sha256 624
Average over 500000 rounds of 112 data bytes: nano per hash aes: 346; sha256 623
Average over 500000 rounds of 128 data bytes: nano per hash aes: 351; sha256 885
Average over 500000 rounds of 144 data bytes: nano per hash aes: 428; sha256 887
Average over 500000 rounds of 160 data bytes: nano per hash aes: 430; sha256 885
Average over 500000 rounds of 176 data bytes: nano per hash aes: 505; sha256 886
Average over 500000 rounds of 192 data bytes: nano per hash aes: 511; sha256 1146
Average over 500000 rounds of 208 data bytes: nano per hash aes: 585; sha256 1150
Average over 500000 rounds of 224 data bytes: nano per hash aes: 592; sha256 1149
Average over 500000 rounds of 240 data bytes: nano per hash aes: 667; sha256 1147
Average over 500000 rounds of 256 data bytes: nano per hash aes: 670; sha256 1405
```