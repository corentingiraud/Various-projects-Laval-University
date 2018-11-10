// To compile: `g++ ex2.cpp -o ex2.out -lcryptopp`

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

/*
 * Compute MD5 Hash using CryptoPP library.
 *
 * Arguments
 * 	globalPassword: main secret
 *  digest: pointer to the digest
 */
void computeKey(string globalPassword, byte *digest)
{
    Weak::MD5 hash;
    hash.CalculateDigest(digest, (const byte *)globalPassword.c_str(), globalPassword.length());
}

/*
 * Encode string using HEXencoder from CryptoPP lib
 *
 * Arguments
 * 	text: text to encode
 * 
 * Returns
 *  encoded: a string representing hexEncode(text)
 */
string hexEncode(string text)
{
    string encoded;
    StringSource ss2(text, true,
                     new HexEncoder(
                         new StringSink(encoded)));
    return encoded;
}

/*
 * Decode string using HEXdecoder from CryptoPP lib
 *
 * Arguments
 * 	text: text to decode
 * 
 * Returns
 *  decode: a string representing hexDecode(text)
 */
string hexDecode(string text)
{
    string decoded;
    StringSource ss2(text, true,
                     new HexDecoder(
                         new StringSink(decoded)));
    return decoded;
}

/*
 * Crypt and encode a string using AES 128 CTR mode and HEXencoder
 *
 * Arguments
 * 	plainText: text to crypt and encode
 * 
 * Returns
 *  A string representing <hexEncode(IV_CTR)>$<hexEncode(Cipher)>.
 *  "$" character is used as a delimiter
 */
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

/*
 * Decrypt and decode a string using AES 128 CTR mode and HEXdecoder.
 * First, the function will parse the text and isolate IV_CTR & cipher.
 * Then, it will initialize the decoder and decrytor.
 * Finally, it will decode then decrypt the cipher text. 
 *
 * Arguments
 * 	text: text to decrypt and decode
 * 
 * Returns
 *  A string representing the decoded and decrypted value.
 */
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

/*
 * Add service to the wallet file.
 * It will use the following format:
 *  `<hexEncode(CTR_IV)>$<hexEncode(AES_CTR(service))>:
 *  <hexEncode(CTR_IV)>$<hexEncode(AES_CTR(url))>:
 *  <hexEncode(CTR_IV)>$<hexEncode(AES_CTR(username))>:
 *  <hexEncode(CTR_IV)>$<hexEncode(AES_CTR(password))>`
 * Each line represents a service.
 * ":" character is used as a delimiter
 *
 * Arguments
 * 	text: text to decrypt and decode
 * 
 * Returns
 *  A string representing the decoded and decrypted value.
 */
void addService(string service, string url, string name, string pwd)
{
    fstream file;
    file.open(PASSWORD_WALLET_PATH, ios_base::app);
    file << cryptAndEncode(service) << ":" << cryptAndEncode(url)
         << ":" << cryptAndEncode(name) << ":" << cryptAndEncode(pwd) << endl;
    file.close();
}

/*
 * Display a service in column.
 *
 * Arguments
 * 	line: the line representing a service
 *  lineIndex: a number representing the service index in the wallet file
 *  displayUser: a bool to indicate if the function will display the username
 *  displayPwd: a bool to indicate if the function will display the password
 */
void displayService(string line, int lineIndex, bool displayUser, bool displayPwd)
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

/*
 * Display header in column.
 */
void displayHeader()
{
    cout << setw(10) << left << "ligne"
         << setw(30) << left << "service"
         << setw(30) << left << "url"
         << setw(30) << left << "user"
         << setw(30) << left << "pwd"
         << endl;
}
/*
 * Display every service in wallet file
 */
void listService()
{
    displayHeader();

    ifstream ifs(PASSWORD_WALLET_PATH);
    std::string line;
    int lineIndex = 1;
    while (getline(ifs, line))
    {
        displayService(line, lineIndex, false, false);
        lineIndex++;
    }
}

/*
 * Get a specific line in the wallet file
 *  
 * Arguments:
 *  index: a number representing the line index in the wallet file
 * 
 * Returns:
 *  A string of the asked line
 */
string getServiceByIndex(int index)
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
        for (int i = 3; i < argc; i++)
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
        displayService(getServiceByIndex(index), index, displayUser, displayPwd);
    }
    return 0;
}
