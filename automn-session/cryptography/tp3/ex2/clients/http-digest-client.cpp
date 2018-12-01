#include "http-digest-client.h"

HTTPDigestClient::HTTPDigestClient(HTTPDigestServer &server)
{
  httpDigestServer = &server;
}

int HTTPDigestClient::menu()
{
  int menu;
  do
  {
    std::cout << std::endl
              << " --------- Protocole 'HTTP Digest': Menu Client" << std::endl
              << std::endl;
    std::cout << "1. Enregistrer un nouveau compte" << std::endl;
    std::cout << "2. Authentification" << std::endl;
    std::cout << "3. Menu précédent" << std::endl;
    std::cout << "4. Quitter" << std::endl;
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
      return 0; // No effect to main menu
      break;

    case 4:
      return 4; // Option 4 in main menu is exit
      break;
    }
  } while (true);
}

void HTTPDigestClient::registerToServer()
{
  std::string payload = askUser("Veuillez entrez l'enregistrement au format <username password>: ");
  payload = display("E1", true, payload);
  httpDigestServer->registration(payload);
}

void HTTPDigestClient::authenticate()
{
  std::string httpVerb = "GET";
  std::string URI = "/dir/index.html";
  std::string req = httpVerb + " " + URI;
  std::string payload = display("A1", true, req);
  std::string res = httpDigestServer->preAuthenticate(payload);
  
  // Get credentials from user
  std::cout << "Le serveur requiert une authentification pour accèder à la ressource demandée." << std::endl;
  std::string credentials = askUser("Veuillez entrez vos identifiants au format <username password>: ");
  std::string username = credentials.substr(0, credentials.find(" "));
  std::string password = credentials.substr(credentials.find(" ") + 1, credentials.length());

  // Parse res
  res = res.substr(res.find("401 Unauthorized ") + std::string("401 Unauthorized ").length(), res.length());
  std::string ns = res.substr(0, res.find(" "));
  std::string sessionID = res.substr(res.find(" ") + 1, res.length());

  // Compute payload
  CryptoPP::Weak::MD5 hash;
  std::string nc = generateRandom();

  // - Compute md5(username:password)
  byte hashUsernamePassword[ CryptoPP::Weak::MD5::DIGESTSIZE ];
  std::string usernamePassword = username + ":" + password;
  hash.CalculateDigest(hashUsernamePassword, (const byte*)usernamePassword.c_str(), usernamePassword.length());
  std::string hashUsernamePasswordStr((char*)hashUsernamePassword, CryptoPP::Weak::MD5::DIGESTSIZE);

  // - Compute md5(httpVerb + URI)
  byte hashHttpVerbURI[ CryptoPP::Weak::MD5::DIGESTSIZE ];
  std::string httpVerbURI = httpVerb + ":" + URI;
  hash.CalculateDigest(hashHttpVerbURI, (const byte*)httpVerbURI.c_str(), httpVerbURI.length());
  std::string hashHttpVerbURIStr((char*)hashHttpVerbURI, CryptoPP::Weak::MD5::DIGESTSIZE);

  // - Compute final hash and encode it using base64
  std::string finalEncodedhash = md5AndEncode(hashUsernamePasswordStr + ":" + ns + ":" + nc + ":" + hashHttpVerbURIStr);

  payload = username + " " + ns + " " + nc + " " + finalEncodedhash + " " + sessionID;
  payload = display("A3", true, payload);
  
  // Send payload
  httpDigestServer->authenticate(payload);
}
