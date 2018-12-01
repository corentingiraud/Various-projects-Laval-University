#ifndef DEF_PASSWORD_SERVER
#define DEF_PASSWORD_SERVER
 
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <algorithm>
#include "../communication/communication.h"

class PasswordServer: public Communication
{
    public:
        PasswordServer();
        std::string registration(std::string payload);
        std::string authenticate(std::string payload);
        std::string transaction(std::string payload);

    private:
        std::map<std::string, std::string> users;
        std::vector<std::string> cookies;
        const std::string PERSISTENCE_PATH = "persistence/password.db";

        void importDB();
};
 
#endif
