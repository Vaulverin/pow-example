# POW algorithms comparison research

This document provides a comprehensive comparison of some Proof of Work (PoW) algorithms. The goal is to find suitable algorithm for mitigating service abuse in public-facing applications.

## Table of Contents
1. [Introduction](#introduction)
2. [Choosing PoW Algorithms](#choosing-pow-algorithms)
3. [Benchmark Results](#benchmark-results)
   1. [Hash-based PoW difficulty benchmark](#hash-based-pow-difficulty-benchmark)
4. [Conclusion](#conclusion)

## Introduction
Proof of Work (PoW) algorithms are widely used in various applications to prevent abuse of network resources. By requiring users to perform a certain amount of computational work before accessing a service, PoW can effectively deter spam and denial-of-service attacks.

My research focuses on comparing different PoW algorithms in context of their suitability for public-facing applications.

## Choosing PoW Algorithms
There are certain constraints and requirements for the PoW algorithms to be used in public-facing applications:
- **Low Latency**: The algorithm should allow for quick verification to avoid user frustration.
- **Moderate Resource Usage**: It should not excessively tax the user's device.
- **Security**: The algorithm must be robust against various attack vectors.
- **Ease of Implementation**: The algorithm should be straightforward to implement in web applications.
- **Adaptability**: The algorithm should be adaptable to different levels of difficulty based on the application's needs.

| Algorithm            | Low Latency | Moderate Resource Usage | Security | Ease of Implementation | Adaptability | **Score** |
|----------------------|-------------|-------------------------|----------|------------------------|--------------|-----------|
| **Hashcash**         | 5 | 5 | 3 | 5 | 5 | **4.6** |
| **Blake3**           | 5 | 5 | 3 | 5 | 4 | **4.4** |
| **SHA3-256**         | 4 | 5 | 3 | 5 | 4 | **4.2** |
| **Scrypt**           | 4 | 4 | 3 | 4 | 4 | **3.8** |
| **Argon2id**         | 3 | 3 | 4 | 3 | 5 | **3.6** |
| **Cuckoo Cycle**     | 3 | 3 | 5 | 2 | 3 | **3.2** |
| **Balloon Hashing**  | 3 | 3 | 4 | 2 | 4 | **3.2** |
| **YesPower**         | 3 | 3 | 4 | 3 | 3 | **3.2** |
| **Equihash**         | 2 | 2 | 5 | 2 | 3 | **2.8** |
| **RandomX**          | 2 | 2 | 5 | 2 | 3 | **2.8** |
| **KawPow / ProgPoW** | 2 | 2 | 4 | 1 | 3 | **2.4** |
| **CryptoNight**      | 2 | 2 | 4 | 2 | 3 | **2.6** |
| **MTP**              | 2 | 2 | 5 | 1 | 3 | **2.6** |
| **Ethash**           | 1 | 1 | 5 | 1 | 2 | **2.0** |

**Score** is a normalized average (0–5) across all criteria.
All criteria are weighted equally at this stage to provide an unbiased
high-level comparison.

### Selected candidates for benchmarking

Based on the comparison above and the requirements of a public-facing
challenge-response PoW system, the following algorithms were selected
for empirical benchmarking:

- Hashcash (SHA-256)
- BLAKE3-256
- SHA3-256
- Scrypt
- Argon2id (memory-hard baseline)

These algorithms represent the best trade-offs between latency,
implementation simplicity, and resource usage.

## Benchmark Results
<details>
<summary><strong>Raw benchmark output</strong></summary>

```
goos: darwin
goarch: arm64
pkg: pow-example/pow-research/pow_algos
cpu: Apple M3 Pro
BenchmarkNewChallenge
BenchmarkNewChallenge/hashcash
BenchmarkNewChallenge/hashcash-12         	 3128229	       368.7 ns/op	     352 B/op	       6 allocs/op
BenchmarkNewChallenge/blake3
BenchmarkNewChallenge/blake3-12           	 3234890	       371.3 ns/op	     352 B/op	       6 allocs/op
BenchmarkNewChallenge/sha3_256
BenchmarkNewChallenge/sha3_256-12         	 3240117	       377.8 ns/op	     352 B/op	       6 allocs/op
BenchmarkNewChallenge/scrypt
BenchmarkNewChallenge/scrypt-12           	 1594244	       746.4 ns/op	     528 B/op	       9 allocs/op
BenchmarkNewChallenge/argon2id
BenchmarkNewChallenge/argon2id-12         	 1593422	       758.8 ns/op	     528 B/op	       9 allocs/op
BenchmarkVerify
BenchmarkVerify/hashcash
BenchmarkVerify/hashcash-12               	 6675550	       205.8 ns/op	     224 B/op	       6 allocs/op
BenchmarkVerify/blake3
BenchmarkVerify/blake3-12                 	 5773732	       208.2 ns/op	     224 B/op	       6 allocs/op
BenchmarkVerify/sha3_256
BenchmarkVerify/sha3_256-12               	 4201242	       282.3 ns/op	     224 B/op	       6 allocs/op
BenchmarkVerify/scrypt
BenchmarkVerify/scrypt-12                 	     259	   4622443 ns/op	 4200325 B/op	      34 allocs/op
BenchmarkVerify/argon2id
BenchmarkVerify/argon2id-12               	     291	   4101941 ns/op	 8394375 B/op	      36 allocs/op
BenchmarkSolve
BenchmarkSolve/hashcash
BenchmarkSolve/hashcash-12                	    2997	    422751 ns/op	  317258 B/op	   12037 allocs/op
BenchmarkSolve/blake3
BenchmarkSolve/blake3-12                  	    2848	    417814 ns/op	  301186 B/op	   11422 allocs/op
BenchmarkSolve/sha3_256
BenchmarkSolve/sha3_256-12                	    1909	    548306 ns/op	  329342 B/op	   12503 allocs/op
BenchmarkSolve/scrypt
BenchmarkSolve/scrypt-12                  	       1	2519409666 ns/op	2171485888 B/op	   18351 allocs/op
BenchmarkSolve/argon2id
BenchmarkSolve/argon2id-12                	       2	 670745375 ns/op	1347271828 B/op	    5966 allocs/op
PASS
```
Note: Benchmark identifiers such as `hashcash`, `blake3`, and `sha3_256` correspond to Hashcash (SHA-256), BLAKE3-256, and SHA3-256 respectively.
</details>

| Algorithm           | New Challenge (ns) | Verify (ns) | Solve (ns)    | (New + Verify)/Solve |
|---------------------|--------------------|-------------|---------------|----------------------|
| Hashcash (SHA-256)  | 368.7              | 205.8       | 422751        | 0.001359             |
| BLAKE3-256          | 371.3              | 208.2       | 417814        | 0.001387             |
| SHA3-256            | 377.8              | 282.3       | 548306        | 0.001204             |
| Scrypt              | 746.4              | 4622443     | 2519409666    | 0.001835             |
| Argon2id            | 758.8              | 4101941     | 670745375     | 0.006117             |

The benchmark results confirm the expected operational trade-offs.
Memory-hard algorithms (Argon2id, Scrypt) make both solving and verification
significantly more expensive than hash-based PoW, which makes them unsuitable
for high-throughput public services where the server must verify cheaply.

Hash-based PoW algorithms (Hashcash, BLAKE3-256, SHA3-256) provide a better
server/client asymmetry in this setting: verification stays in the sub-microsecond
range, while solving costs hundreds of microseconds (for the chosen target).

### Hash-based PoW difficulty benchmark
Difficulty is expressed as a target threshold derived from a base target.
Higher difficulty corresponds to a smaller target, making the success
probability per attempt lower. In these benchmarks, difficulty levels
(d=0…200) represent monotonically increasing target strictness and are
used for comparative scaling rather than absolute security calibration.

<details>
<summary><strong>Raw benchmark output</strong></summary>

```
goos: darwin
goarch: arm64
pkg: pow-example/pow-research/hash_pow_algos
cpu: Apple M3 Pro
BenchmarkHashPoW_Verify_ByDifficulty
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=0
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=0-12         	 5305082	       220.3 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=25
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=25-12        	 5199138	       221.7 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=50
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=50-12        	 5730175	       212.7 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=75
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=75-12        	 5695058	       209.0 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=100
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=100-12       	 5699052	       210.1 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=200
BenchmarkHashPoW_Verify_ByDifficulty/blake3-256/d=200-12       	 5665544	       213.6 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=0
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=0-12    	 5905555	       204.1 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=25
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=25-12   	 5978284	       201.8 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=50
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=50-12   	 6006084	       177.8 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=75
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=75-12   	 5985328	       198.9 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=100
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=100-12  	 6035236	       200.4 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=200
BenchmarkHashPoW_Verify_ByDifficulty/hashcash-sha256/d=200-12  	 5998066	       199.3 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=0
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=0-12           	 4232932	       283.6 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=25
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=25-12          	 4261369	       283.6 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=50
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=50-12          	 4201278	       284.1 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=75
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=75-12          	 4243518	       283.2 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=100
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=100-12         	 4196540	       283.4 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=200
BenchmarkHashPoW_Verify_ByDifficulty/sha3-256/d=200-12         	 4186954	       284.0 ns/op	     224 B/op	       6 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=0
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=0-12          	    2485	    436582 ns/op	  324517 B/op	   12318 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=25
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=25-12         	    1923	    548542 ns/op	  408483 B/op	   15541 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=50
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=50-12         	    1909	    629772 ns/op	  467425 B/op	   17805 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=75
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=75-12         	    1729	    747029 ns/op	  556597 B/op	   21229 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=100
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=100-12        	    1366	    928779 ns/op	  693871 B/op	   26498 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=200
BenchmarkHashPoW_Solve_ByDifficulty/blake3-256/d=200-12        	     999	   1306457 ns/op	  937874 B/op	   35854 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=0
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=0-12     	    3183	    416461 ns/op	  317155 B/op	   12034 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=25
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=25-12    	    2353	    525407 ns/op	  403255 B/op	   15341 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=50
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=50-12    	    1762	    613608 ns/op	  470108 B/op	   17908 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=75
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=75-12    	    1656	    715863 ns/op	  552535 B/op	   21074 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=100
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=100-12   	    1434	    827335 ns/op	  638829 B/op	   24388 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=200
BenchmarkHashPoW_Solve_ByDifficulty/hashcash-sha256/d=200-12   	    1160	   1265638 ns/op	  978367 B/op	   37411 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=0
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=0-12            	    2662	    514609 ns/op	  324025 B/op	   12299 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=25
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=25-12           	    2167	    631923 ns/op	  395597 B/op	   15047 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=50
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=50-12           	    1644	    743268 ns/op	  471528 B/op	   17962 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=75
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=75-12           	    1293	    893327 ns/op	  566495 B/op	   21609 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=100
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=100-12          	    1389	    970994 ns/op	  611606 B/op	   23341 allocs/op
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=200
BenchmarkHashPoW_Solve_ByDifficulty/sha3-256/d=200-12          	     772	   1574279 ns/op	  999102 B/op	   38190 allocs/op
PASS
```
Note: Benchmark identifiers such as `hashcash-sha256`, `blake3-256`,
and `sha3-256` correspond to Hashcash (SHA-256), BLAKE3-256, and
SHA3-256 respectively.
</details>

***Solve time growth (ns/op)***

| Algorithm           | d=0    | d=25   | d=50   | d=75   | d=100  | d=200   |
|---------------------|--------|--------|--------|--------|--------|---------|
| Hashcash (SHA-256)  | 416461 | 525407 | 613608 | 715863 | 827335 | 1265638 |
| BLAKE3-256          | 436582 | 548542 | 629772 | 747029 | 928779 | 1306457 |
| SHA3-256            | 514609 | 631923 | 743268 | 893327 | 970994 | 1574279 |

***Verify time stability (ns/op)***

| Algorithm           | d=0   | d=25  | d=50  | d=75  | d=100 | d=200 |
|---------------------|-------|-------|-------|-------|-------|-------|
| Hashcash (SHA-256)  | 204.1 | 201.8 | 177.8 | 198.9 | 200.4 | 199.3 |
| BLAKE3-256          | 220.3 | 221.7 | 212.7 | 209.0 | 210.1 | 213.6 |
| SHA3-256            | 283.6 | 283.6 | 284.1 | 283.2 | 283.4 | 284.0 |

***Cost asymmetry at high difficulty (d = 200)***

| Algorithm           | Solve (ns) | Verify (ns) | Solve/Verify |
|---------------------|------------|-------------|--------------|
| Hashcash (SHA-256)  | 1265638    | 199.3       | 6350.4       |
| BLAKE3-256          | 1306457    | 213.6       | 6116.4       |
| SHA3-256            | 1574279    | 284.0       | 5543.2       |


## Conclusion
The difficulty-scaling benchmarks show that all hash-based PoW algorithms
show solve-time increasing with stricter targets while keeping verification cost
effectively constant.

BLAKE3-256 and Hashcash (SHA-256) provide the best cost asymmetry at higher difficulties,
with verification remaining in the ~180–285 ns range while solve cost increases from hundreds of microseconds up to ~1–1.5 ms as the target becomes stricter. SHA3-256 demonstrates similar scaling behavior but with
consistently higher verification and solve latency.

These properties make hash-based PoW particularly suitable for public-facing
TCP services, where verification must remain extremely cheap under load.

Based on the benchmark results, the recommended default hash-based PoW is Hashcash (SHA-256): 
it offers the best solve/verify latency while keeping verification cost extremely low.