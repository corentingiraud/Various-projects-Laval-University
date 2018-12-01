#ifndef DEF_HTTP_DISGEST_CLIENT
#define DEF_HTTP_DISGEST_CLIENT
 
#include <iostream>
#include <limits>
#include <string>
#include <map>
#include "../servers/http-digest-server.h"
#include "../communication/communication.h"
 
class HTTPDigestClient: public Communication
{
    public:
        HTTPDigestClient(HTTPDigestServer &server);
        int menu();

    private:
        HTTPDigestServer *httpDigestServer;

        void registerToServer();
        void authenticate();
};
 
#endif
