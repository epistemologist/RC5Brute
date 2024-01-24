#include "rc5.cpp"

const BLOCK P1 = 0x54686520756e6b6eL;
const BLOCK IV = 0x8a162f69e83798bcL;
const BLOCK EXPECTED_PT = P1 ^ IV;
const BLOCK C1 = 0x1235136478d3da08L;

int main() {
	int b1;
	cin >> b1;
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
		RC5 cipher(K);
		if (cipher.decrypt_block(C1) == EXPECTED_PT) {
			for (auto i: K) cout << (int)i << ",";
			cout << endl;
		}
	}
}
