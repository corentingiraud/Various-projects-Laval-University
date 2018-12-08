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
              << " --------- Protocole 'Mot de passe': Menu Client" << std::endl;

    if (cookie.empty())
    {
      std::cout << " --------- Non authentifié" << std::endl;
    }
    else
    {
      std::cout << " --------- Authentifié. Cookie: " << cookie << "." << std::endl;
    }
    std::cout << "1. Enregistrer un nouveau compte" << std::endl;
    std::cout << "2. Authentification" << std::endl;
    std::cout << "3. Transaction (authentification nécéssaire)" << std::endl;
    std::cout << "4. Supprimer le cookie (authentification nécéssaire)" << std::endl;
    std::cout << "5. Menu précédent" << std::endl;
    std::cout << "6. Quitter" << std::endl;
    std::string choice = askUser("Choix: ");
    std::istringstream ss(choice);
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
  // Get credentials from user
  std::string payload = askUser("Veuillez entrez vos identifiants au format <username password>: ");

  // Generate sessionID and send payload
  std::string sessionID = generateRandom();
  payload = display("A1", true, sessionID + " " + payload);
  std::string res = passwordServer->authenticate(payload);

  // Remove sessionID and extract response code
  res = res.substr(res.find(" ") + 1, res.length()); 
  std::string code = res.substr(0, res.find(" "));

  if (code == "200")
  {
    // Extract code and save it
    cookie = res.substr(res.find("=") + 1, res.length());
  }
}

void PasswordClient::transaction()
{
  if (cookie.empty())
  {
    std::cout << "Aucun cookie défini. Authentifiez-vous au préalable." << std::endl;
    return;
  }

  // Ask client for a command, generate sessionID and send payload
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
  std::string res = askUser("Voulez-vous vraiment supprimer le cookie (" + cookie + ") ? <y/n>: ");
  if (res == "y")
  {
    cookie = "";
  }
}
