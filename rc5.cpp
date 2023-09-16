#include<iostream>
#include<cmath>
#include<cinttypes>
#include<array>
#include<vector>

using namespace std;

// RC5 parameters
#define w 32 // word size
#define r 16 // number of rounds
#define b 16 // key size

// Some type definitions for various integer sizes
// Note that instead of defining a BLOCK as two words, we pack them into one type

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

#if w == 16
typedef u16 WORD;
typedef u32 BLOCK;
#define SWAP_ENDIAN(X) __builtin_bswap16(X)
const WORD ALL_BITS = 0xFFFF;
const WORD P = 0xB7E1, Q = 0x9E37;
#elif w == 32
typedef u32 WORD;
typedef u64 BLOCK;
#define SWAP_ENDIAN(X) __builtin_bswap32(X)
const WORD ALL_BITS = 0xFFFFFFFF;
const WORD P = 0xB7E15163, Q = 0x9E3779B9;
#elif w == 64
typedef u64 WORD;
typedef u128 BLOCK;
#define SWAP_ENDIAN(X) __builtin_bswap64(X)
const WORD ALL_BITS = 0xFFFFFFFFFFFFFFFF;
const WORD P = 0xB7E151628AED2A6BL, Q = 0x9E3779B97F4A7C15L;
#endif

// Macros to get the two words packed in a block
#define GET_A(X) (((WORD)(X>>w)))
#define GET_B(X) (((WORD)((X<<w)>>w)))
// and a macro to create a block
#define CREATE_BLOCK(A,B) (((BLOCK) B) | (((BLOCK) A)<<w))
#define SWAP_ENDIAN_BLOCK(BLOCK) CREATE_BLOCK(SWAP_ENDIAN(GET_A(BLOCK)), SWAP_ENDIAN(GET_B(BLOCK)))

typedef unsigned char BYTE;
typedef array<BYTE, b> KEY;

// Define cyclic bit shifts
#define _ROTL(x,y) ((((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1))))) & ALL_BITS)
#define _ROTR(x,y) ((((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1))))) & ALL_BITS)
#define ROTL(x,y) ((WORD)_ROTL((WORD(x)),(WORD(y))))
#define ROTR(x,y) ((WORD)_ROTR((WORD)x,(WORD(y))))


const unsigned int c = max(1., ceil(8. * b / w));
const unsigned int t = 2*(r+1);

// Debug functions to print array


class RC5 {    
    public:
        WORD S[t] = {0};

        RC5(KEY K) {
            this->key_expansion(K);
            cout << "finished key expansion" << endl;
            for (int i = 0; i < t; i++) {
                printf("%.2X,", S[i]);
            }
            cout << endl;
        }
        
        inline void key_expansion(KEY K) {
            int i, j, k, u = w/8;
            WORD A, B, L[c] = {0};
            for(i = b-1, L[c-1] = 0; i != -1; i--) {
                cout << i << "," << i/u << endl;
                L[i/u] = ROTL(L[i/u], 8) + K[i];
            }
            for (int l = 0; l < c; l++) {
            }
            printf("\n");
            for(S[0] = P, i = 1; i < t; i++) {
                S[i] = S[i-1] + Q;
            }
            // Key mixing
            for(A=B=i=j=k=0; k<3*max(t,c); k++, i=(i+1)%t, j=(j+1)%c) {
                A = S[i] = ROTL(S[i]+(A+B), 3);
                B = L[j] = ROTL(L[j]+(A+B), (A+B)&(w-1));
            }
        }

        inline BLOCK encrypt_block(BLOCK pt) {
            pt = SWAP_ENDIAN_BLOCK(pt);
            WORD A = GET_A(pt), B = GET_B(pt);
            A += S[0]; B += S[1];
            printf("initial A = %.04X, B = %.04X\n", A, B);
            for (int i = 1; i <= r; i++) {
                A = ROTL(A^B, B) + S[2*i];
                B = ROTL(B^A, A) + S[2*i+1];
                printf("i = %d; A = %.04X; B = %.04X\n", i, A, B);
            }
            return SWAP_ENDIAN_BLOCK(CREATE_BLOCK(A,B));
        }

        inline BLOCK decrypt_block(BLOCK ct) {
            ct = SWAP_ENDIAN_BLOCK(ct);
            WORD A = GET_A(ct), B = GET_B(ct);
            for (int i = r; i > 0; i--) {
                B = ROTR(B - S[2*i+1], A) ^ A;
                A = ROTR(A - S[2*i], B) ^ B;
            }
            B -= S[1]; A -= S[0];
            return SWAP_ENDIAN_BLOCK(CREATE_BLOCK(A,B));
        }
};

int main() {
    KEY K = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };
    RC5 cipher(K);
    BLOCK pt = 0x1111111111111111L;
    BLOCK ct = cipher.encrypt_block(pt);
    printf("%lX\n", ct);
}
