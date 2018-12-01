#ifndef DEF_HTTP_DISGEST_SERVER
#define DEF_HTTP_DISGEST_SERVER
 
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <algorithm>
#include "../communication/communication.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include "cryptopp/base64.h"

class HTTPDigestServer: public Communication
{
    public:
        HTTPDigestServer();
        std::string registration(std::string payload);
        std::string preAuthenticate(std::string payload);
        std::string authenticate(std::string payload);

    private:
        std::map<std::string, std::string> users;
        std::string httpVerb;
        std::string URI;
        const std::string PERSISTENCE_PATH = "persistence/http-digest.db";

        void importDB();
};
 
#endif
