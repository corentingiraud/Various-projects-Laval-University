#include "password-client.h"

PasswordClient::PasswordClient(PasswordServer &server)
{
  passwordServer = &server;
}

int PasswordClient::menu()
{
  int menu;
  do
  {
    std::cout << std::endl
              << " --------- Protocole 'Mot de passe': Menu Client" << std::endl
              << std::endl;
    std::cout << "1. Enregistrer un nouveau compte" << std::endl;
    std::cout << "2. Authentification" << std::endl;
    std::cout << "3. Transaction (authentification nécéssaire)" << std::endl;
    std::cout << "4. Supprimer le cookie (authentification nécéssaire)" << std::endl;
    std::cout << "5. Menu précédent" << std::endl;
    std::cout << "6. Quitter" << std::endl;
    std::cout << "Choix : ";
    std::string line;
    getline(std::cin, line);
    std::istringstream ss(line);
    ss >> menu;
    std::cout << std::endl;

    switch (menu)
    {
    case 1:
      registerToServer();
      break;

    case 2:
      authenticate();
      break;

    case 3:
      transaction();
      break;

    case 4:
      removeCookie();
      break;
    
    case 5:
      return 0; // No effect to main menu
      break;

    case 6:
      return 4; // Option 4 in main menu is exit
      break;
    }
  } while (true);
}

void PasswordClient::registerToServer()
{
  std::string payload = askUser("Veuillez entrez l'enregistrement au format <username password>: ");
  payload = display("E1", true, payload);
  passwordServer->registration(payload);
}

void PasswordClient::authenticate()
{
  std::string payload = askUser("Veuillez entrez vos identifiants au format <username password>: ");
  std::string sessionID = generateRandom();
  payload = display("A1", true, sessionID + " " + payload);
  std::string res = passwordServer->authenticate(payload);
  res = res.substr(res.find(" ") + 1, res.length()); // Remove sessionID
  std::string code = res.substr(0, res.find(" ")); // Extract code
  if (code == "200")
  {
    cookie = res.substr(res.find("=") + 1, res.length()); // Extract code
    std::cout << cookie << std::endl;
  }
}

void PasswordClient::transaction()
{
  if (cookie.empty())
  {
    std::cout << "Aucun cookie défini. Authentifiez-vous au préalable." << std::endl;
    return;
  }
  std::string payload = askUser("Veuillez entrez la commande: ");
  std::string sessionID = generateRandom();
  payload = display("T1", true, sessionID + " " + payload + " Cookie:session=" + cookie);
  std::string res = passwordServer->transaction(payload);
}

void PasswordClient::removeCookie()
{
  if (cookie.empty())
  {
    std::cout << "Aucun cookie défini." << std::endl;
    return;
  }
  std::string res = askUser("Voules-vous vraiment supprimer le cookie (" + cookie + ") ? <y/n>: ");
  if (res == "y")
  {
    cookie = "";
  }
}
