#ifndef DEF_UAF_CLIENT
#define DEF_UAF_CLIENT
 
#include <iostream>
#include <limits>
#include <string>
#include <map>
#include "../servers/uaf-server.h"
#include "../communication/communication.h"
 
class UAFClient: public Communication
{
    public:
        UAFClient(UAFServer &server);
        int menu();

    private:
        UAFServer *uafServer;
        std::string masterPassword;
        const std::string PERSISTENCE_PATH = "persistence/uaf.client.wallet";
        std::map<std::string, std::map<std::string, std::string>> wallet;

        void registerToServer();
        void authenticate();
        void transaction();
        void updateWallet();
};
 
#endif
