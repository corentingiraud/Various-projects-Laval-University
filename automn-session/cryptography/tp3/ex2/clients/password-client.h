#ifndef DEF_PASSWORD_CLIENT
#define DEF_PASSWORD_CLIENT
 
#include <iostream>
#include <limits>
#include <string>
#include <map>
#include "../servers/password-server.h"
#include "../communication/communication.h"
 
class PasswordClient: public Communication
{
    public:
        PasswordClient(PasswordServer &server);
        int menu();

    private:
        PasswordServer *passwordServer;
        std::string cookie;

        void registerToServer();
        void authenticate();
        void transaction();
        void removeCookie();
};
 
#endif
