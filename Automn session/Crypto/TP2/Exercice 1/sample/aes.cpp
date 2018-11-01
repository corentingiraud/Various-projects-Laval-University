#include <iostream>
#include <fstream>
#include <iomanip>
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

using namespace std;
using namespace CryptoPP;

/*Fonction de chiffrement : elle prend le message à chiffrer, la clé et iv et elle retourne le message chiffré*/
//-----------------------------------------------------------------------------
string EncryptionAES(string message, byte key[16], byte iv[16])
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

//-----------------------------------------------------------------------------
/*Fonction de déchiffrement : elle prend le message à déchiffrer, la clé et iv et elle retourne le message claire*/
string DecryptionAES(string message, byte key[16], byte iv[16])
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

//-----------------------------------------------------------------------------

//Une fonction pour encoder un message en hexadécimal
string encoderHex(string in)
{

    string out;

    StringSource(in, true, new HexEncoder(new StringSink(out)));

    return out;
}

//-----------------------------------------------------------------------------
//Une fonction pour encoder un message en base64
string encoderBase64(string in)
{

    string out;

    StringSource(in, true, new Base64Encoder(new StringSink(out)));

    return out;
}

//---------------------------------------------------------------------------

int main(int argc, char *argv[])
{

    byte iv[16];
    byte key[AES::DEFAULT_KEYLENGTH];

    // créer un générateur aléatoire
    AutoSeededRandomPool rng;
    // générer aléatoirement iv
    rng.GenerateBlock(iv, 16);
    // générer aléatoirement une clé AES avec une taille de 128 bits
    rng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);

    //initialiser le message à chiffrer
    string originalString = "Hello world";
    std::cout << "Message original : " << originalString << std::endl;

    //chiffrer le message
    string encryptedString = EncryptionAES(originalString, key, iv);
    std::cout << "Message chiffré en binaire : " << encryptedString << std::endl;

    std::cout << "Message chiffré en base64 : " << encoderBase64(encryptedString) << std::endl;

    std::cout << "Message chiffré en hexadécimal : " << encoderHex(encryptedString) << std::endl;

    //déchiffrer le message
    string decryptedString = DecryptionAES(encryptedString, key, iv);
    std::cout << "decrypted String : " << decryptedString << std::endl;

    return 0;
}
