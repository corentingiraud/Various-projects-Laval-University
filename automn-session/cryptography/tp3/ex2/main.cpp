#include <string>
#include <iostream>
#include <limits>
#include "servers/password-server.h"
#include "clients/password-client.h"
#include "servers/http-digest-server.h"
#include "clients/http-digest-client.h"

using namespace std;

PasswordServer passwordServer;
PasswordClient passwordClient(passwordServer);
HTTPDigestServer httpDigestServer;
HTTPDigestClient httpDigestClient(httpDigestServer);

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
        std::string line;
        getline(std::cin, line);
        std::istringstream ss(line);
        ss >> menu;
        cout << endl;
        cout << endl;

        switch (menu)
        {
        case 1:
            menu = passwordClient.menu();
            break;

        case 2:
            menu = httpDigestClient.menu();
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

int main(int argc, char *argv[])
{
    credit();

    mainMenu();

    return 0;
}
