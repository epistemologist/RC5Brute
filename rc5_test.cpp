#include <iostream>
#include<string>

#include "cryptopp/cryptlib.h"
#include "cryptopp/rc5.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"

using namespace CryptoPP;
using namespace std;

// Compile with g++ rc5_test.cpp -Wall -Wextra -l:libcryptopp.a

int main()
{
    // Key - Modify this with your own key
    unsigned char key[RC5::DEFAULT_KEYLENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // Plain text to be encrypted
    string plainText = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

    // Initialize the RC5 encryption algorithm in ECB mode
    ECB_Mode<RC5>::Encryption rc5Encryption;
    rc5Encryption.SetKey(key, sizeof(key));

    // Encrypt the plain text
    string cipherText;
    StringSource(plainText, true,
        new StreamTransformationFilter(rc5Encryption,
            new StringSink(cipherText),
            StreamTransformationFilter::NO_PADDING
        )
    );

	string encoded;
	StringSource ss2( cipherText, true,
		new HexEncoder(
			new StringSink( encoded )
		) // HexEncoder
	);
    printf("w=32\n");
    printf("r=%d\n", RC5::DEFAULT_ROUNDS);
    printf("b=%d\n", RC5::DEFAULT_KEYLENGTH);
   
    // Print key, pt, and ct
    printf("key: 0x"); for (char c: key) { printf("%x", c); } printf("\n");
    printf("pt: 0x"); for (char c: plainText) { printf("%x", c); } printf("\n");
    printf("ct: 0x%s\n", encoded.c_str());
    return 0;
}

