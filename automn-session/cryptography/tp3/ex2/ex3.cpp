// To compile: `g++ ex2.cpp -o ex2.out -lcryptopp`

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

using namespace std;
using namespace CryptoPP;

string PROTOCOLS[3] = {
    "Mot de passe",
    "HTTP-Digest",
    "UAF",
};

string SERVER1_PATH = "password2.1.txt";

Weak::MD5 HASH1;

// ------------ FUNCTION DECLARATIONS

// QUESTION 2.1: MOT DE PASSE

void registerPassword();
void authenticatePassword();

// QUESTION 2.2: HTTP-Digest
// QUESTION 2.3: UAF

// ------------ FUNCTION IMPLEMENTATIONS

// GENERAL FUNCTION

string hackerMenu(string message)
{
    string newMessage = "";
    cout << "--- MITM ---> /!\\ HACKER /!\\, inscrire un message modifié, si vous le souhaitez: ";
    getline(cin, newMessage);
    if (newMessage.empty())
    {
        return message;
    }
    return newMessage;
}

string display(string step, bool clientToServer, string message)
{
    string way = "S -> C";
    if (clientToServer)
    {
        way = "C -> S";
    }
    cout << step << ". " << way << " : " << message << endl;
    string newMessage = hackerMenu(message);
    if (strcmp(newMessage.c_str(), message.c_str()))
    {
        cout << step << "'. " << way << " : " << newMessage << endl;
        return newMessage;
    }
    return message;
}

int subMenu(int protocol)
{
    int menu;
    string protocolName = PROTOCOLS[protocol];
    do
    {
        cout << endl
             << " --------- Sous menu: " << protocolName << endl
             << endl;
        cout << "1. Enregistrer un nouveau compte" << endl;
        cout << "2. Authentification" << endl;
        cout << "3. Menu précédent" << endl;
        cout << "4. Quitter" << endl;
        cout << "Choix : ";
        while (!(cin >> menu))
        {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Mauvais choix. Choix : ";
        }
        cout << endl;

        switch (menu)
        {
        case 1:
            switch (protocol)
            {
            case 0:
                registerPassword();
                break;
            }
            break;

        case 2:
            switch (protocol)
            {
            case 0:
                authenticatePassword();
                break;
            }
            break;

        case 3:
            return 0; // No effect to main menu
            break;

        case 4:
            return 4; // Option 4 main menu is exit
            break;
        }

    } while (menu != 0);
}

void mainMenu()
{
    int menu;
    do
    {
        cout << endl
             << " ----------------------- MENU -----------------------" << endl
             << endl;
        cout << "1. Mot de passe" << endl;
        cout << "2. HTTP-Digest" << endl;
        cout << "3. UAF" << endl;
        cout << "4. Quitter" << endl;
        cout << "Choix : ";
        while (!(cin >> menu))
        {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Mauvais choix. Choix : ";
        }
        cout << endl;
        cout << endl;

        switch (menu)
        {
        case 1:
            menu = subMenu(0);
            break;

        case 2:
            cout << "Not implemented" << endl;
            break;

        case 3:
            cout << "Not implemented" << endl;
            break;
        }
    } while (menu != 4);
}

void credit()
{
    cout << R"(   
__________                __          __         .__   
\______   \_______  _____/  |_  ____ |  | ______ |  |  
 |     ___/\_  __ \/  _ \   __\/  _ \|  |/ /  _ \|  |  
 |    |     |  | \(  <_> )  | (  <_> )    <  <_> )  |__
 |____|     |__|   \____/|__|  \____/|__|_ \____/|____/
                                          \/
                                Coded by Corentin Giraud
    )" << endl;
}

/*
 * Encode string using Base64Encoder from CryptoPP lib
 *
 * Arguments
 * 	text: text to encode
 * 
 * Returns
 *  encoded: a string representing hexEncode(text)
 */
string base64Encode(string text)
{
    string encoded;
    StringSource ss(text, true,
                    new Base64Encoder(
                        new StringSink(encoded)));
    return encoded;
}

/*
 * Decode string using Base64Decoder from CryptoPP lib
 *
 * Arguments
 * 	encoded: text to decode
 * 
 * Returns
 *  decoded: a string representing base64Decode(encoded)
 */
string base64Decode(string encoded)
{
    string decoded;
    StringSource ss(encoded, true,
                    new Base64Encoder(
                        new StringSink(decoded)));
    return decoded;
}

/*
 * Compute MD5 Hash using CryptoPP library and.
 *
 * Arguments
 * 	text: main secret
 *  digest: pointer to the digest
 */
string md5AndEncode(string text)
{
    byte digest[ Weak::MD5::DIGESTSIZE ];

    Weak::MD5 hash;
    hash.CalculateDigest( digest, (const byte*)text.c_str(), text.length() );

    Base64Encoder encoder(NULL, false);
    string output;
    encoder.Attach( new StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    return output;
}

// QUESTION 2.1: MOT DE PASSE

void registerPassword()
{
    string message = "";
    cout << "Veuillez entrez l'enregistrement au format <username password>: ";
    while (getline(cin, message))
    {
        if (!message.empty())
        {
            break;
        }
    }
    message = display("E1", true, message);
    string username = message.substr(0, message.find(" "));
    string password = message.substr(message.find(" ") + 1, message.length());
    if (username.empty() || password.empty() || message.find(" ") == string::npos)
    {
        message = "400: Bad Request";
        message = display("E2", false, message);
        return;
    }
    fstream file;
    file.open(SERVER1_PATH, ios_base::app);
    file << username << ":" << md5AndEncode(password) << endl;
    file.close();
    message = "200";
    display("E2", false, message);
}

void authenticatePassword()
{
    string message = "";
    cout << "Veuillez entrez vos identifiants au format <username password>: ";
    while (getline(cin, message))
    {
        if (!message.empty())
        {
            break;
        }
    }
    message = display("A1", true, generateSessionID() + message);
    string username = message.substr(0, message.find(" "));
    string password = message.substr(message.find(" ") + 1, message.length());
    if (username.empty() || password.empty() || message.find(" ") == string::npos)
    {
        message = "400: Bad Request";
        message = display("A2", false, message);
        return;
    }
    ifstream ifs(SERVER1_PATH);
    string line;
    map<string, string> users;

    while (getline(ifs, line))
    {
        users[line.substr(0, line.find(":"))] = line.substr(line.find(":") + 1, line.length());
    }

    if (users.find(username) != users.end())
    {
        cout << users[username] << endl;
        cout << md5AndEncode(password) << endl;
        if (users[username] == md5AndEncode(password))
        {
            display("A2", false, "SessionID 200 SetCookie:Session=Ns");
            return;
        }
    }
    display("A2", false, "SessionID 401");
}

// QUESTION 2.2: HTTP-Digest
// QUESTION 2.3: UAF

int main(int argc, char *argv[])
{
    credit();

    mainMenu();

    return 0;
}
