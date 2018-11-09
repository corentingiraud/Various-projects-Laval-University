#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

using namespace std;
using namespace CryptoPP;

// Global variable
byte KEY[Weak::MD5::DIGESTSIZE];
string PASSWORD_WALLET_PATH = "password-wallet.enc";

void computeKey(string globalPassword, byte *digest)
{
    Weak::MD5 hash;
    hash.CalculateDigest(digest, (const byte *)globalPassword.c_str(), globalPassword.length());
}

void displayBytes(byte *b)
{
    HexEncoder encoder;
    string output;

    encoder.Attach(new StringSink(output));
    encoder.Put(b, sizeof(b));
    encoder.MessageEnd();

    cout << output << endl;
}

void addService(string service, string url, string name, string pwd)
{
    fstream file;
    file.open(PASSWORD_WALLET_PATH, ios_base::app);
    file << service << ":" << url << ":" << name << ":" << pwd << endl;
    file.close();
}

string crytp(string plainText)
{

}

string decrypt(string cryptedText)
{
}

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful

    string arg = argv[1];
    string globalPassword = argv[2];

    // Compute the key with MD5 hash algorithm
    computeKey(globalPassword, KEY);
    displayBytes(KEY);

    // Add new service
    if (arg == "-a")
    {
        string service = "?";
        string url, username, pwd;
        for (int i = 3; i < argc; i = i + 2)
        {
            cout << i << " " << argv[i] << " " << argv[i + 1] << endl;
            string arg = argv[i];
            if (arg == "-srv")
            {
                service = argv[i+1];
            }
            else if (arg == "-url")
            {
                url = argv[i+1];
            }
            else if (arg == "-user")
            {
                username = argv[i+1];
            }
            else if (arg == "-pwd")
            {
                pwd = argv[i+1];
            }
        }
        addService(service, url, username, pwd);
    }
    // List all services
    else if (arg == "-l")
    {
    }
    // Display specific service
    else if (arg == "-d")
    {
    }
    return 0;
}
