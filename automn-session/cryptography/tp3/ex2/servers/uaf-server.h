#ifndef DEF_UAF_SERVER
#define DEF_UAF_SERVER
 
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include "../communication/communication.h"

class UAFServer: public Communication
{
    public:
        UAFServer();
        std::string registration(std::string payload);
        std::string preAuthenticate(std::string payload);
        std::string authenticate(std::string payload);
        std::string preTransaction(std::string payload);
        std::string transaction(std::string payload);

    private:
        std::map<std::string, CryptoPP::RSA::PublicKey> users;
        std::string ns;
        std::string nsTransaction;
        std::string currentUsername;
        std::string currentCommand;
        const std::string PERSISTENCE_PATH = "persistence/uaf.db";

        void importDB();
};
 
#endif
