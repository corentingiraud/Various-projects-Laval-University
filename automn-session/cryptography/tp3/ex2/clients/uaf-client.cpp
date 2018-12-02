#include "uaf-client.h"

UAFClient::UAFClient(UAFServer &server)
{
  uafServer = &server;

  updateWallet();
}

int UAFClient::menu()
{
  if (masterPassword.empty())
  {
    std::cout << "Avant d'utiliser ce protocole, veuillez saisir le mot de passe maître du portefeuille de clés: ";
    getline(std::cin, masterPassword);
    std::cout << std::endl;
    computeKey();
    updateWallet();
  }

  int menu;
  do
  {
    std::cout << std::endl
              << " --------- Protocole 'UAF': Menu Client" << std::endl
              << std::endl;
    std::cout << "1. Enregistrer un nouveau compte" << std::endl;
    std::cout << "2. Authentification" << std::endl;
    std::cout << "3. Transaction (authentification nécéssaire)" << std::endl;
    std::cout << "4. Afficher le portefeuille de clé" << std::endl;
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
      displayWallet();
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

void UAFClient::registerToServer()
{
  std::string payload = askUser("Veuillez entrez le username: ");
  
  // Key generation
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::InvertibleRSAFunction params;
  params.GenerateRandomWithKeySize(rng, 1024);
  CryptoPP::RSA::PrivateKey privateKey(params);
  CryptoPP::RSA::PublicKey publicKey(params);

  // Encode keys with base64
  std::string encodedPrivateKey, encodedPublicKey;

  CryptoPP::Base64Encoder privKeySink(new CryptoPP::StringSink(encodedPrivateKey), false);
  privateKey.DEREncode(privKeySink);
  privKeySink.MessageEnd();

  CryptoPP::Base64Encoder pubKeySink(new CryptoPP::StringSink(encodedPublicKey), false);
  privateKey.DEREncode(pubKeySink);
  pubKeySink.MessageEnd();

  std::cout << "Private Key: " << encodedPrivateKey << std::endl;
  std::cout << "Public Key: " << encodedPublicKey << std::endl;
  // payload = display("E1", true, payload);
  // passwordServer->registration(payload);
}

void UAFClient::authenticate()
{
  // std::string payload = askUser("Veuillez entrez vos identifiants au format <username password>: ");
  // std::string sessionID = generateRandom();
  // payload = display("A1", true, sessionID + " " + payload);
  // std::string res = passwordServer->authenticate(payload);
  // res = res.substr(res.find(" ") + 1, res.length()); // Remove sessionID
  // std::string code = res.substr(0, res.find(" ")); // Extract code
  // std::cout << code << std::endl;
  // if (code == "200")
  // {
  //   cookie = res.substr(res.find("=") + 1, res.length()); // Extract code
  //   std::cout << cookie << std::endl;
  // }
}

void UAFClient::transaction()
{
  // if (cookie.empty())
  // {
  //   std::cout << "Aucun cookie défini. Authentifiez-vous au préalable." << std::endl;
  //   return;
  // }
  // std::string payload = askUser("Veuillez entrez la commande: ");
  // std::string sessionID = generateRandom();
  // payload = display("T1", true, sessionID + " " + payload + " Cookie:session=" + cookie);
  // std::string res = passwordServer->transaction(payload);
}

void UAFClient::displayWallet()
{
  for (auto server : wallet)
  {
    std::cout << "Nom du serveur: " << server.first << std::endl
              << std::endl;
    for (auto user : server.second)
    {
      std::cout << "   - Username: " << user.first << std::endl;

      // Encode privateKey using base64
      std::string encoded;
      CryptoPP::StringSource ss(
          user.second, true,
          new CryptoPP::Base64Encoder(
              new CryptoPP::StringSink(encoded), false));
      std::cout << "   - PrivateKey (base64): " << encoded << std::endl;
      std::cout << std::endl;
    }
  }
}

void UAFClient::updateWallet()
{
  std::ifstream ifs(PERSISTENCE_PATH);
  std::string line, serverName, delimiter, username, encodedCTR, privateKeyEncoded;

  while (getline(ifs, line))
  {
    // Parse line
    delimiter = ":";
    size_t pos = line.find(delimiter);
    serverName = line.substr(0, pos);
    line.erase(0, pos + delimiter.length());
    pos = line.find(delimiter);
    username = line.substr(0, pos);
    line.erase(0, pos + delimiter.length());
    delimiter = "$";
    pos = line.find(delimiter);
    encodedCTR = line.substr(0, pos);
    line.erase(0, pos + delimiter.length());
    privateKeyEncoded = line;

    // Decode private key
    std::string cipherText;
    CryptoPP::StringSource s1(privateKeyEncoded, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(cipherText)));

    // Decode and create CTR
    std::string ctrString;
    CryptoPP::StringSource s2(encodedCTR, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(ctrString)));
    byte ctr[CryptoPP::AES::BLOCKSIZE];
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
    {
      ctr[i] = ctrString[i];
    }

    // Decrypt privateKey
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(masterPasswordHash, sizeof(masterPasswordHash), ctr);
    std::string decryptedPrivateKey;
    CryptoPP::StringSource s3(cipherText, true,
                              new CryptoPP::StreamTransformationFilter(d,
                                                                       new CryptoPP::StringSink(decryptedPrivateKey)));

    // Define wallet attribute
    std::map<std::string, std::string> *serverWallet = &(wallet[serverName]);
    (*serverWallet)[username] = decryptedPrivateKey;
  }
}

void UAFClient::computeKey()
{
  hash1.CalculateDigest(masterPasswordHash, (const byte *)masterPassword.c_str(), masterPassword.length());
}
