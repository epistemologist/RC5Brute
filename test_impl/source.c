/*
// RC6 & RC5 block cipher supporting unusual block sizes. This
// implementation is designed only for testing interoperability.
//
// Written by Ted Krovetz (ted@krovetz.net). Modified April 10, 2018.
//
// RC6 and RC5 were both patented and trademarked around the time
// each was invented. The author of this code believes the patents
// have expired and that the trademarks may still be in force. Seek
// legal advice before using RC5 or RC6 in any project.
//
// This is free and unencumbered software released into the public
// domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a
// compiled binary, for any purpose, commercial or non-commercial,
// and by any means.
//
// In jurisdictions that recognize copyright laws, the author or
// authors of this software dedicate any and all copyright interest
// in the software to the public domain. We make this dedication for
// the benefit of the public at large and to the detriment of our
// heirs and successors. We intend this dedication to be an overt act
// of relinquishment in perpetuity of all present and future rights
// to this software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* set vectors non-zero to print intermediate setup/encrypt values */
static int vectors = 0;

/* bool variable to show subkey array */
static int show_subkeys = 0;

/* pbuf is used to print sequences of bytes from in memory         */
static void pbuf(const void *p, int len, const void *s)
{
    int i;
    if (s) printf("%s", (char *)s);
    for (i=0; i<len; i++) printf("%02X", ((unsigned char *)p)[i]);
    printf("\n");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * C O N S T A N T   D A T A   &   U T I L I T Y   F U N C T I O N S
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* 1024 bits of P_w/Q_w. For any w, grab w bits & set last bit 1.  */
/* WolframAlpha: IntegerPart[(e - 2) * 2^1024] to hex              */
static const unsigned char PP[] = {
    0xb7,0xe1,0x51,0x62,0x8a,0xed,0x2a,0x6a,0xbf,0x71,0x58,0x80,0x9c,
    0xf4,0xf3,0xc7,0x62,0xe7,0x16,0x0f,0x38,0xb4,0xda,0x56,0xa7,0x84,
    0xd9,0x04,0x51,0x90,0xcf,0xef,0x32,0x4e,0x77,0x38,0x92,0x6c,0xfb,
    0xe5,0xf4,0xbf,0x8d,0x8d,0x8c,0x31,0xd7,0x63,0xda,0x06,0xc8,0x0a,
    0xbb,0x11,0x85,0xeb,0x4f,0x7c,0x7b,0x57,0x57,0xf5,0x95,0x84,0x90,
    0xcf,0xd4,0x7d,0x7c,0x19,0xbb,0x42,0x15,0x8d,0x95,0x54,0xf7,0xb4,
    0x6b,0xce,0xd5,0x5c,0x4d,0x79,0xfd,0x5f,0x24,0xd6,0x61,0x3c,0x31,
    0xc3,0x83,0x9a,0x2d,0xdf,0x8a,0x9a,0x27,0x6b,0xcf,0xbf,0xa1,0xc8,
    0x77,0xc5,0x62,0x84,0xda,0xb7,0x9c,0xd4,0xc2,0xb3,0x29,0x3d,0x20,
    0xe9,0xe5,0xea,0xf0,0x2a,0xc6,0x0a,0xcc,0x93,0xed,0x87};
/* WolframAlpha: IntegerPart[(GoldenRatio - 1) * 2^1024] to hex    */
static const unsigned char QQ[] = {
    0x9e,0x37,0x79,0xb9,0x7f,0x4a,0x7c,0x15,0xf3,0x9c,0xc0,0x60,0x5c,
    0xed,0xc8,0x34,0x10,0x82,0x27,0x6b,0xf3,0xa2,0x72,0x51,0xf8,0x6c,
    0x6a,0x11,0xd0,0xc1,0x8e,0x95,0x27,0x67,0xf0,0xb1,0x53,0xd2,0x7b,
    0x7f,0x03,0x47,0x04,0x5b,0x5b,0xf1,0x82,0x7f,0x01,0x88,0x6f,0x09,
    0x28,0x40,0x30,0x02,0xc1,0xd6,0x4b,0xa4,0x0f,0x33,0x5e,0x36,0xf0,
    0x6a,0xd7,0xae,0x97,0x17,0x87,0x7e,0x85,0x83,0x9d,0x6e,0xff,0xbd,
    0x7d,0xc6,0x64,0xd3,0x25,0xd1,0xc5,0x37,0x16,0x82,0xca,0xdd,0x0c,
    0xcc,0xfd,0xff,0xbb,0xe1,0x62,0x6e,0x33,0xb8,0xd0,0x4b,0x43,0x31,
    0xbb,0xf7,0x3c,0x79,0x0d,0x94,0xf7,0x9d,0x47,0x1c,0x4a,0xb3,0xed,
    0x3d,0x82,0xa5,0xfe,0xc5,0x07,0x70,0x5e,0x4a,0xe6,0xe5};

#define MAXSZ ((int)sizeof(PP)) /* Defines max bytes allowed for W */

/* d[0..n-1] = a[0..n-1] xor b[0..n-1]                             */
static void eor(unsigned char d[], unsigned char a[],
        unsigned char b[], int n) {
    for ( ; n>0; n--) d[n-1] = a[n-1] ^ b[n-1];
}

/* d[0..n-1] = a[0..n-1] + b[0..n-1] (mod 2^8n)                    */
static void add(unsigned char d[], unsigned char a[],
        unsigned char b[], int n) {
    int tmp, carry = 0;
    for ( ; n>0; n--) {
        d[n-1] = tmp = a[n-1] + b[n-1] + carry;
        carry = tmp >> 8;
    }
}

/* d[0..n-1] = a[0..n-1] - b[0..n-1] (mod 2^8n)                    */
static void sub(unsigned char d[], unsigned char a[],
        unsigned char b[], int n) {
    int tmp, borrow = 0;
    for ( ; n>0; n--) {
        d[n-1] = tmp = a[n-1] - b[n-1] - borrow;
        borrow = (tmp < 0 ? 1 : 0);
    }
}

/* d[0..n-1] = a[0..n-1] * b[0..n-1] (mod 2^8n)                    */
static void mul(unsigned char d[], unsigned char a[],
        unsigned char b[], int n) {
    int i,j;
    unsigned char t[MAXSZ] = {0};
    for (i=0; i<n; i++) {
        int tmp, carry = 0;
        for (j=0; i+j<n; j++) {
            tmp = a[n-i-1] * b[n-j-1] + t[n-i-j-1] + carry;
            t[n-i-j-1] = tmp;
            carry = tmp >> 8;
        }
    }
    memcpy(d,t,n);
}

/* d[0..n-1] = a[0..n-1] rotated left r bits                       */
static void rotl(unsigned char d[], unsigned char a[], int r, int n){
    int i;
    unsigned char t[MAXSZ];
    for (i = 0; i < n; i++)
        t[i] = (a[(i+r/8)%n] << r%8) | (a[(i+r/8+1)%n] >> (8-r%8));
    memcpy(d,t,n);
}

/* Calculate floor(base-2 log of x) for any x>0.                   */
static int lg2(int x) {
    int ans=0;
    for ( ; x!=1; x>>=1)
        ans++;
    return ans;
}

/* Return last nbits of a[0..n-1] as int. Pre: 0 <= nbits <= 16.   */
static int bits(unsigned char a[], int n, int nbits) {
    int mask = ((1 << nbits) - 1);
    if (nbits <= 8) return a[n-1] & mask;
    else            return ((a[n-2] << 8) | a[n-1]) & mask;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * A R C 6   A N D   A R C 5   F U N C T I O N S
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Preconditions: 0 < w <=1024, w%8==0, 0 <= r < 256, 0 <= b < 256 */
static int setup(void *rkey, int rk_words,
        int w, int r, int b, void *key) {
    if (w<=0 || w>MAXSZ*8 || w%8!=0 || r<0 || r>255 || b<0 || b>255)
        return -1;
    else {
        unsigned char L[256+MAXSZ], Q[MAXSZ];
        unsigned char A[MAXSZ] = {0}, B[MAXSZ] = {0};
        unsigned char *rk = (unsigned char *)rkey;
        int i, mix_steps, n = w/8, lgw = lg2(w);
        int l_words = (b==0 ? 1 : (b+n-1)/n);
        memcpy(Q, QQ, n); Q[n-1] |= 1;         /* Load Q, make odd */
        /* Initialize rkey with specified P & Q constant values    */
        memcpy(rk, PP, n); rk[n-1] |= 1;       /* Load P, make odd */
        for (i=1; i<rk_words; i++)
            add(rk+i*n, rk+(i-1)*n, Q, n);
        /* Fill L: Zero last word, little-endian copy each word    */
        memset(L+(l_words-1)*n, 0, n);
        for (i=0; i<b; i++)
            L[i/n*n + n-1 - i%n] = ((unsigned char *)key)[i];
        if (vectors) {          /* Print initial values of L and S */
            for (i=0; i<l_words; i++)
            {printf("initial L[%3d] = ", i); pbuf((char *)L+i*n,n,0);}
            for (i=0; i<rk_words; i++)
            {printf("initial S[%3d] = ", i); pbuf((char *)rkey+i*n,n,0);}
        }
        /* Mix L and rkey                                          */
        mix_steps = 3 * (rk_words>l_words ? rk_words : l_words);
        for (i=0; i < mix_steps; i++) {
            unsigned rot_amt, ko = i%rk_words*n, lo = i%l_words*n;
            add(A,A,B,n); add(A,A,rk+ko,n); rotl(A,A,3,n);
            memcpy(rk+ko,A,n);
            add(B,B,A,n); rot_amt = bits(B,n,lgw);
            add(B,B,L+lo,n); rotl(B,B,rot_amt,n);
            memcpy(L+lo,B,n);
            if (vectors) {          /* Print new values of L and S */
                printf("S[%3d] = ", ko/n); pbuf(A,n,0);
                printf("L[%3d] = ", lo/n); pbuf(B,n,0);
            }
        }
        return 0;
    }
}
int rc5_setup(void *rkey, int w, int r, int b, void *key) {
    return setup(rkey, 2*r+2, w, r, b, key);
}
int rc6_setup(void *rkey, int w, int r, int b, void *key) {
    return setup(rkey, 2*r+4, w, r, b, key);
}

void rc5_encrypt(void *rkey, int w, int r, void *pt, void *ct) {
    unsigned char A[MAXSZ], B[MAXSZ];
    unsigned char *rk = (unsigned char *)rkey,
                  *p = (unsigned char *)pt,
                  *c = (unsigned char *)ct;
    int rot_amt, i, n = w/8, lgw = lg2(w);
    /* Read A and B in byte-reverse order */
    for (i=0; i<n; i++) { A[i] = p[n-i-1]; B[i] = p[2*n-i-1]; }
    add(A,A,rk,n);
    add(B,B,rk+n,n);
    if (vectors) { printf("initial"); pbuf(A,n,"A = "); pbuf(B,n,"B = "); }
    for (i=1; i<=r; i++) {
        rot_amt = bits(B,n,lgw);
        eor(A,A,B,n); rotl(A,A,rot_amt,n); add(A,A,rk+2*i*n,n);
        rot_amt = bits(A,n,lgw);
        eor(B,B,A,n); rotl(B,B,rot_amt,n); add(B,B,rk+2*i*n+n,n);
        if (vectors) { printf("i = %d\n", i); pbuf(A,n,"A = "); pbuf(B,n,"B = "); }
    }
    /* Write A and B in byte-reverse order */
    for (i=0; i<n; i++) { c[n-i-1] = A[i]; c[2*n-i-1] = B[i]; }
}

void rc5_decrypt(void *rkey, int w, int r, void *ct, void *pt) {
    unsigned char A[MAXSZ], B[MAXSZ];
    unsigned char *rk = (unsigned char *)rkey,
                  *p = (unsigned char *)pt,
                  *c = (unsigned char *)ct;
    int rot_amt, i, n = w/8, lgw = lg2(w);
    /* Read A and B in byte-reverse order */
    for (i=0; i<n; i++) { A[i] = c[n-i-1]; B[i] = c[2*n-i-1]; }
    for (i=r; i>0; i--) {
        rot_amt = bits(A,n,lgw);
        sub(B,B,rk+2*i*n+n,n); rotl(B,B,w-rot_amt,n); eor(B,B,A,n);
        rot_amt = bits(B,n,lgw);
        sub(A,A,rk+2*i*n,n); rotl(A,A,w-rot_amt,n); eor(A,A,B,n);
    }
    sub(B,B,rk+n,n);
    sub(A,A,rk,n);
    /* Write A and B in byte-reverse order */
    for (i=0; i<n; i++) { p[n-i-1] = A[i]; p[2*n-i-1] = B[i]; }
}

void rc6_encrypt(void *rkey, int w, int r, void *pt, void *ct) {
    unsigned char A[MAXSZ], B[MAXSZ], C[MAXSZ], D[MAXSZ];
    unsigned char t[MAXSZ], u[MAXSZ];
    unsigned char *rk = (unsigned char *)rkey,
                  *p = (unsigned char *)pt,
                  *c = (unsigned char *)ct;
    int rot_amt, i, n = w/8, lgw = lg2(w);
    /* Read A/B/C/D in byte-reverse order */
    for (i=0; i<n; i++) {
        A[i] = p[n-i-1];     B[i] = p[2*n-i-1];
        C[i] = p[3*n-i-1];   D[i] = p[4*n-i-1];
    }
    add(B,B,rk,n); add(D,D,rk+n,n);
    if (vectors) { pbuf(B,n,"B = "); pbuf(D,n,"D = "); }
    for (i=1; i<=r; i++) {
        rotl(t, B, 1, n); t[n-1] |= 1;       /* t = 2*B+1          */
        rotl(u, D, 1, n); u[n-1] |= 1;       /* u = 2*D+1          */
        mul(t, t, B, n); rotl(t, t, lgw, n); /* t = rotl(B*t, lgw) */
        mul(u, u, D, n); rotl(u, u, lgw, n); /* u = rotl(D*u, lgw) */
        rot_amt = bits(u,n,lgw);
        eor(A,A,t,n); rotl(A,A,rot_amt,n); add(A,A,rk+2*i*n,n);
        rot_amt = bits(t,n,lgw);
        eor(C,C,u,n); rotl(C,C,rot_amt,n); add(C,C,rk+2*i*n+n,n);
        if (vectors) { pbuf(A,n,"A = "); pbuf(C,n,"C = "); }
        memcpy(t,A,n);memcpy(A,B,n);memcpy(B,C,n);
        memcpy(C,D,n);memcpy(D,t,n);
    }
    add(A,A,rk+(2*r+2)*n,n); add(C,C,rk+(2*r+3)*n,n);
    if (vectors) { pbuf(A,n,"A = "); pbuf(C,n,"C = "); }
    /* Write A/B/C/D in byte-reverse order */
    for (i=0; i<n; i++) {
        c[n-i-1] = A[i];     c[2*n-i-1] = B[i];
        c[3*n-i-1] = C[i];   c[4*n-i-1] = D[i];
    }
}

void rc6_decrypt(void *rkey, int w, int r, void *ct, void *pt) {
    unsigned char A[MAXSZ], B[MAXSZ], C[MAXSZ], D[MAXSZ];
    unsigned char t[MAXSZ], u[MAXSZ];
    unsigned char *rk = (unsigned char *)rkey,
                  *p = (unsigned char *)pt,
                  *c = (unsigned char *)ct;
    int rot_amt, i, n = w/8, lgw = lg2(w);
    /* Read A/B/C/D in byte-reverse order */
    for (i=0; i<n; i++) {
        A[i] = c[n-i-1];     B[i] = c[2*n-i-1];
        C[i] = c[3*n-i-1];   D[i] = c[4*n-i-1];
    }
    sub(A,A,rk+(2*r+2)*n,n); sub(C,C,rk+(2*r+3)*n,n);
    for (i=r; i>=1; i--) {
        memcpy(t,D,n);memcpy(D,C,n);memcpy(C,B,n);
        memcpy(B,A,n);memcpy(A,t,n);
        rotl(t, B, 1, n); t[n-1] |= 1;       /* t = 2*B+1          */
        rotl(u, D, 1, n); u[n-1] |= 1;       /* u = 2*D+1          */
        mul(t, t, B, n); rotl(t, t, lgw, n); /* t = rotl(B*t, lgw) */
        mul(u, u, D, n); rotl(u, u, lgw, n); /* u = rotl(D*u, lgw) */
        rot_amt = bits(t,n,lgw);
        sub(C,C,rk+2*i*n+n,n); rotl(C,C,w-rot_amt,n); eor(C,C,u,n);
        rot_amt = bits(u,n,lgw);
        sub(A,A,rk+2*i*n,n); rotl(A,A,w-rot_amt,n); eor(A,A,t,n);
    }
    sub(B,B,rk,n); sub(D,D,rk+n,n);
    /* Write A/B/C/D in byte-reverse order */
    for (i=0; i<n; i++) {
        p[n-i-1] = A[i];     p[2*n-i-1] = B[i];
        p[3*n-i-1] = C[i];   p[4*n-i-1] = D[i];
    }
}
static void print_vector(int w, int r, int b) {
    if (w%8!=0 || w<8 || w/8>MAXSZ || r<0 || r>255 || b<0 || b>255) {
        printf("Unsupported w/r/b: %d/%d/%d\n", w, r, b);
    } else {
        int j, bpw=w/8, bpb=2*bpw;    /* bytes per: word and block */
        unsigned char *rkey = (unsigned char *)malloc((2*r+2)*bpw);
        unsigned char *key = (unsigned char *)malloc(b);
        unsigned char *buf = (unsigned char *)malloc(bpb);
        for (j=0; j<b; j++)   key[j]=j;
        for (j=0; j<bpb; j++) buf[j]=j;
        printf("RC5-%d/%d/%d\n",w,r,b);
        pbuf(key, b, "Key:          ");
        pbuf(buf, bpb, "Block input:  ");
        rc5_setup(rkey, w, r, b, key);
        if (show_subkeys) {
            printf("S_arr: ");
            for (int k = 0; k < (2*r+2)*bpw; k++) {
                printf("%.2x", rkey[k]);
                if(k%bpw == bpw-1) printf(",");
            }
            printf("\n");
        }
        rc5_encrypt(rkey, w, r, buf, buf);
        pbuf(buf, bpb, "Block output: ");
        free(rkey); free(key); free(buf);
    }
}
int main() {
    /*
    print_vector(8,12,4);    printf("\n");
    print_vector(16,16,8);   printf("\n");
    print_vector(32,20,16);  printf("\n");
    print_vector(64,24,24);  printf("\n");
    print_vector(128,28,32); printf("\n");
    vectors = 1;
    print_vector(24,4,0);    printf("\n");
    print_vector(80,4,12);
    return 0;
    */
//    vectors=1;
//    show_subkeys=1;
    print_vector(32, 20, 16);
    return 0;
}
