#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
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

string hexEncode(string text)
{
    string encoded;
    StringSource ss2(text, true,
                     new HexEncoder(
                         new StringSink(encoded)));
    return encoded;
}

string hexDecode(string text)
{
    string decoded;
    StringSource ss2(text, true,
                     new HexDecoder(
                         new StringSink(decoded)));
    return decoded;
}

string cryptAndEncode(string plainText)
{
    byte ctr[AES::BLOCKSIZE];
    AutoSeededRandomPool prng;
    prng.GenerateBlock(ctr, sizeof(ctr));
    string cipher, ctrString;
    StringSource s1(ctr, 16, true, new StringSink(ctrString));

    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(KEY, sizeof(KEY), ctr);

    StringSource ss1(plainText, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)));

    return hexEncode(ctrString) + "$" + hexEncode(cipher);
}

string decodeAndDecrypt(string text)
{
    // Split CTR and encodedCipherText
    string delimiter = "$";
    size_t pos = text.find(delimiter);
    string encodedCTR = text.substr(0, pos);
    text.erase(0, pos + delimiter.length());
    string encodedCipherText = text;

    // Decode encodedCipherText
    string cipherText;
    StringSource s1(encodedCipherText, true,
                     new HexDecoder(
                         new StringSink(cipherText)));

    // Decode and create CTR
    string ctrString;
    StringSource s2(encodedCTR, true,
                     new HexDecoder(
                         new StringSink(ctrString)));
    byte ctr[AES::BLOCKSIZE];
    for (int i = 0; i < AES::BLOCKSIZE; i++)
    {
        ctr[i] = ctrString[i];
    }

    // Decrypt
    CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(KEY, sizeof(KEY), ctr);
    string decrypted;
    StringSource s3(cipherText, true,
                     new StreamTransformationFilter(d,
                                                    new StringSink(decrypted)));

    return decrypted;
}

void addService(string service, string url, string name, string pwd)
{
    fstream file;
    file.open(PASSWORD_WALLET_PATH, ios_base::app);
    file << cryptAndEncode(service) << ":" << cryptAndEncode(url)
         << ":" << cryptAndEncode(name) << ":" << cryptAndEncode(pwd) << endl;
    file.close();
}

void displayLine(string line, int lineIndex, bool displayUser, bool displayPwd)
{
    string delimiter = ":";
    size_t pos = 0;
    vector<string> tokens;
    while ((pos = line.find(delimiter)) != std::string::npos)
    {
        tokens.push_back(line.substr(0, pos));
        line.erase(0, pos + delimiter.length());
    }
    tokens.push_back(line);

    tokens[0] = decodeAndDecrypt(tokens[0]);
    tokens[1] = decodeAndDecrypt(tokens[1]);
    tokens[2] = displayUser ? decodeAndDecrypt(tokens[2]) : "*****";
    tokens[3] = displayUser ? decodeAndDecrypt(tokens[3]) : "*****";

    cout << setw(10) << left << lineIndex
         << setw(30) << left << tokens[0]
         << setw(30) << left << tokens[1]
         << setw(30) << left << tokens[2]
         << setw(30) << left << tokens[3]
         << endl;
}

void displayHeader()
{
    cout << setw(10) << left << "ligne"
         << setw(30) << left << "service"
         << setw(30) << left << "url"
         << setw(30) << left << "user"
         << setw(30) << left << "pwd"
         << endl;
}

void listService()
{
    displayHeader();

    ifstream ifs(PASSWORD_WALLET_PATH);
    std::string line;
    int lineIndex = 1;
    while (getline(ifs, line))
    {
        displayLine(line, lineIndex, false, false);
        lineIndex++;
    }
}

string getLineByIndex(int index)
{
    ifstream ifs(PASSWORD_WALLET_PATH);
    std::string line;
    int lineIndex = 1;
    while (getline(ifs, line))
    {
        if (lineIndex == index)
        {
            break;
        }
        lineIndex++;
    }
    return line;
}

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful

    string arg = argv[1];
    string globalPassword = argv[2];

    // Compute the key with MD5 hash algorithm
    computeKey(globalPassword, KEY);

    // Add new service
    if (arg == "-a")
    {
        string service = "?";
        string url, username, pwd;
        for (int i = 3; i < argc; i = i + 2)
        {
            string arg = argv[i];
            if (arg == "-srv")
            {
                service = argv[i + 1];
            }
            else if (arg == "-url")
            {
                url = argv[i + 1];
            }
            else if (arg == "-user")
            {
                username = argv[i + 1];
            }
            else if (arg == "-pwd")
            {
                pwd = argv[i + 1];
            }
        }
        addService(service, url, username, pwd);
    }
    // List all services
    else if (arg == "-l")
    {
        listService();
    }
    // Display specific service
    else if (arg == "-d")
    {
        int index;
        bool displayUser = false;
        bool displayPwd = false;
        for(int i = 3; i < argc; i++)
        {
            string arg = argv[i];            
            if (arg == "-i")
            {
                index = atoi(argv[i + 1]);
                i++;
            }
            else if (arg == "-pwd")
            {
                displayUser = true;
            }
            else if (arg == "-user")
            {
                displayPwd = true;
            }
        }
        displayHeader();
        displayLine(getLineByIndex(index), index, displayUser, displayPwd);
    }
    return 0;
}
