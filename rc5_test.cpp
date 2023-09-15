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

int main()
{
    // Key - Modify this with your own key
    unsigned char key[RC5::DEFAULT_KEYLENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    // Plain text to be encrypted
    string plainText = "Hello, World!";

    // Initialize the RC5 encryption algorithm in ECB mode
    ECB_Mode<RC5>::Encryption rc5Encryption;
    rc5Encryption.SetKey(key, sizeof(key));

    // Encrypt the plain text
    string cipherText;
    StringSource(plainText, true,
        new StreamTransformationFilter(rc5Encryption,
            new StringSink(cipherText)
        )
    );

    for (auto c: cipherText) {
        cout << (unsigned int) c << endl;
    }
    return 0;
}

