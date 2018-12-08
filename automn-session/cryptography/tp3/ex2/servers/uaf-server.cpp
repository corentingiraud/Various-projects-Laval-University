#include "uaf-server.h"

UAFServer::UAFServer()
{
  importDB();
}

std::string UAFServer::registration(std::string payload)
{
  // Parse payload
  std::string payloadResponse;
  std::string username = payload.substr(0, payload.find(" "));
  std::string publicKey = payload.substr(payload.find(" ") + 1, payload.length());
  if (username.empty() || publicKey.empty() || payload.find(" ") == std::string::npos)
  {
    payloadResponse = "400 Bad Request";
    payloadResponse = display("E2", false, payloadResponse);
    return payloadResponse;
  }

  // Save credentials to persitence file
  std::fstream file;
  file.open(PERSISTENCE_PATH, std::ios_base::app);
  file << username << ":" << publicKey << std::endl;
  file.close();

  // Update inMemory db
  importDB();

  // Send response payload
  payloadResponse = "200";
  payloadResponse = display("E2", false, payloadResponse);
  return payloadResponse;
}
std::string UAFServer::preAuthenticate(std::string payload)
{
  // Compute payload
  std::string sessionID = payload.substr(0, payload.find(" "));
  currentUsername = payload.substr(payload.find(" ") + 1, payload.length());

  // Generate random NS
  ns = generateRandom();
  std::string payloadResponse = display("A2", false, sessionID + " " + ns);
  return payloadResponse;
}

std::string UAFServer::authenticate(std::string payload)
{
  std::string sessionID = payload.substr(0, payload.find(" "));

  // Test if currentUser is known
  if (users.find(currentUsername) == users.end())
  {
    std::string payloadRes = display("A4", false, sessionID + " 401 Unauthorized");
    return payloadRes;
  }

  std::string signatureEncoded = payload.substr(payload.find(" ") + 1, payload.length());

  // Decode signature
  std::string signatureDecoded;
  CryptoPP::StringSource ss(
      signatureEncoded, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signatureDecoded)));

  // Verify signature
  bool result = false;
  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA1>::Verifier verifier(users[currentUsername]);
  CryptoPP::StringSource ss2(
      ns + signatureDecoded, true,
      new CryptoPP::SignatureVerificationFilter(
          verifier, new CryptoPP::ArraySink((byte *)&result, sizeof(result)),
          CryptoPP::SignatureVerificationFilter::PUT_RESULT |
              CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END));

  // Send payload according to result
  if (result == true)
  {
    std::string payloadRes = display("A4", false, sessionID + " 200");
    return payloadRes;
  }
  std::string payloadRes = display("A4", false, sessionID + " 401 Unauthorized");
  return payloadRes;
}

std::string UAFServer::preTransaction(std::string payload)
{
  // Compute payload
  std::string sessionID = payload.substr(0, payload.find(" "));
  currentCommand = payload.substr(payload.find(" ") + 1, payload.length());
  
  // Generate random NS
  nsTransaction = generateRandom();
  std::string payloadResponse = display("T2", false, sessionID + " " + currentCommand + " " + nsTransaction);
  return payloadResponse;
}

std::string UAFServer::transaction(std::string payload)
{
  std::string sessionID = payload.substr(0, payload.find(" "));
  std::string signatureEncoded = payload.substr(payload.find(" ") + 1, payload.length());

  // Decode signature
  std::string signatureDecoded;
  CryptoPP::StringSource ss(
      signatureEncoded, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signatureDecoded)));

  // Verify signature
  bool result = false;
  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA1>::Verifier verifier(users[currentUsername]);
  CryptoPP::StringSource ss2(
      (currentCommand + nsTransaction) + signatureDecoded, true,
      new CryptoPP::SignatureVerificationFilter(
          verifier, new CryptoPP::ArraySink((byte *)&result, sizeof(result)),
          CryptoPP::SignatureVerificationFilter::PUT_RESULT |
              CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END));

  // Send payload according to result
  if (result == true)
  {
    std::string payloadRes = display("T4", false, sessionID + " 200");
    return payloadRes;
  }
  std::string payloadRes = display("T4", false, sessionID + " 401 Unauthorized");
  return payloadRes;
}

void UAFServer::importDB()
{
  std::ifstream ifs(PERSISTENCE_PATH);
  std::string line;

  while (getline(ifs, line))
  {
    std::string encodedPublicKey = line.substr(line.find(":") + 1, line.length());

    // Decode private key
    std::string decodedPublicKey;
    CryptoPP::StringSource s1(encodedPublicKey, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPublicKey)));

    // Create public key
    CryptoPP::StringSource ss(decodedPublicKey, true);
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(ss);

    // Save user and public key
    users[line.substr(0, line.find(":"))] = publicKey;
  }
}
