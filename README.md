# RC5 brute force

Tool to brute force 40-bit RC5 keys

### Example

Below is `worker.cpp` which calls `rc5.cpp` - the latter is a straightforward implementation of the cipher from the documentation. Here, we are attempting to crack the [RC5-32/12/5 contest issued by RSA Labs](https://web.archive.org/web/20071102044610/https://www.rsa.com/rsalabs/node.asp?id=2106)

```cpp
#include "rc5.cpp"

const BLOCK P1 = 0x54686520756e6b6eL; // first block of plaintext (see pseudocontests)
const BLOCK IV = 0x8a162f69e83798bcL; // given initialization vector
const BLOCK EXPECTED_PT = P1 ^ IV; // since encryption mode is CBC, this is the expected first block of plaintext
const BLOCK C1 = 0x1235136478d3da08L // given first block of ciphertext

int main() {
	int b1; // take in first byte of key from stdin
	cin >> b1;
	// brute force the rest of the 4 bytes of the key
	for (u64 b_rest = 0L; b_rest < 0xFFFFFFFFL; b_rest++) {
		if (b_rest % 10000000 == 0) {
			fprintf(stderr, "[+] b1: %d, progress: %ld/%ld\n", b1, b_rest, 0xFFFFFFFF);
		}
		KEY K = {
			b1,
			(b_rest & 0xFF000000L) >> 24,
			(b_rest & 0x00FF0000L) >> 16,
			(b_rest & 0x0000FF00L) >> 8,
			(b_rest & 0x000000FFL),
		};
		// if key found, print it out
		RC5 cipher(K);
		if (cipher.decrypt_block(C1) == EXPECTED_PT) {
			for (auto i: K) cout << (int)i << ",";
			cout << endl;
		}
	}
}
```

Compile above with `-o3` to `./worker`, run in parallel with quick shell script:
```sh
#!/bin/bash
set -e

NUM_CORES=6
for a in $(seq 0 $NUM_CORES 256); do
        b=$(($a+$NUM_CORES>256 ? 256 : $a+$NUM_CORES))
        for first_byte in $(seq $a $b); do
                (echo $first_byte | ./worker > "tmp$i.txt") &
        done
        wait
        cat tmp*.txt > "out$a.txt"
        rm tmp*.txt
done
```

and let run for about a day...
```
# many lines removed...
[+] b1: 253, progress: 4270000000/4294967295
[+] b1: 255, progress: 4280000000/4294967295
[+] b1: 254, progress: 4270000000/4294967295
[+] b1: 252, progress: 4260000000/4294967295
[+] b1: 256, progress: 4260000000/4294967295
[+] b1: 253, progress: 4280000000/4294967295
[+] b1: 255, progress: 4290000000/4294967295
[+] b1: 254, progress: 4280000000/4294967295
[+] b1: 252, progress: 4270000000/4294967295
[+] b1: 256, progress: 4270000000/4294967295
[+] b1: 253, progress: 4290000000/4294967295
[+] b1: 254, progress: 4290000000/4294967295
[+] b1: 252, progress: 4280000000/4294967295
[+] b1: 256, progress: 4280000000/4294967295
[+] b1: 252, progress: 4290000000/4294967295
[+] b1: 256, progress: 4290000000/4294967295

real    1045m15.383s
user    7252m11.766s
sys     1m22.594s
```

Remove all of the temporary files created, and it should find the key.

### Discussion
 - the encryption of each block takes approximately 2000 instructions with the vast majority being executed during key expansion ([link to instruction counts with callgrind](https://gist.github.com/epistemologist/d778888f4776b0b0ce075f75c1bb9dbe))
 - therefore, with an i7-7700HQ CPU @ 2.80GHz, we have as a first order approximation that a full search of the keyspace should take 

$$2^{40} \medspace \text{keys} \times 
\frac{ 1000 \medspace \text{instructions}  }{\text{decryption}} \times
\frac{ 1 second }{  2.8 \cdot 10^{9} \text{instructions} } \times 
$$
