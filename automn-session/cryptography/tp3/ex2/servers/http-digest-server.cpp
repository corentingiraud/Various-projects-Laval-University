#include "http-digest-server.h"

HTTPDigestServer::HTTPDigestServer()
{
  importDB();
}

std::string HTTPDigestServer::registration(std::string payload)
{
  std::string payloadResponse;
  std::string username = payload.substr(0, payload.find(" "));
  std::string password = payload.substr(payload.find(" ") + 1, payload.length());
  if (username.empty() || password.empty() || payload.find(" ") == std::string::npos)
  {
    payloadResponse = "400 Bad Request";
    payloadResponse = display("E2", false, payloadResponse);
    return payloadResponse;
  }
  std::fstream file;
  file.open(PERSISTENCE_PATH, std::ios_base::app);
  file << username << ":" << md5AndEncode(username + ":" + password) << std::endl;
  file.close();
  payloadResponse = "200";
  payloadResponse = display("E2", false, payloadResponse);
  importDB();
  return payloadResponse;
}

std::string HTTPDigestServer::preAuthenticate(std::string payload)
{
  httpVerb = payload.substr(0, payload.find(" "));
  URI = payload.substr(payload.find(" ") + 1, payload.length());

  // Compute payload
  std::string ns = generateRandom();
  std::string sessionID = generateRandom();
  std::string payloadResponse = display("A2", false, "401 Unauthorized " + ns + " " + sessionID);
  return payloadResponse;
}

std::string HTTPDigestServer::authenticate(std::string payload)
{
  // Parse request
  std::string delimiter = " ";
  size_t pos = payload.find(delimiter);
  std::string username = payload.substr(0, pos);
  payload.erase(0, pos + delimiter.length());
  pos = payload.find(delimiter);
  std::string ns = payload.substr(0, pos);
  payload.erase(0, pos + delimiter.length());
  pos = payload.find(delimiter);
  std::string nc = payload.substr(0, pos);
  payload.erase(0, pos + delimiter.length());
  pos = payload.find(delimiter);
  std::string payloadHashEncoded = payload.substr(0, pos);
  // SessionID is useless according to the topic, so don't need to parse it

  // Find user in users map
  if (users.find(username) != users.end())
  {
    CryptoPP::Weak::MD5 hash;

    // Decode md5(username:password) using base64 decoder
    std::string hashUsernamePasswordStr;
    CryptoPP::StringSource s1(users[username], true,
      new CryptoPP::Base64Decoder(new CryptoPP::StringSink(hashUsernamePasswordStr)));

    // Compute md5(httpVerb:URI)
    byte hashHttpVerbURI[ CryptoPP::Weak::MD5::DIGESTSIZE ];
    std::string httpVerbURI = httpVerb + ":" + URI;
    hash.CalculateDigest(hashHttpVerbURI, (const byte*)httpVerbURI.c_str(), httpVerbURI.length());
    std::string hashHttpVerbURIStr((char*)hashHttpVerbURI, CryptoPP::Weak::MD5::DIGESTSIZE);

    // Compute final hash and encode it using base64
    std::string finalHash = md5AndEncode(hashUsernamePasswordStr + ":" + ns + ":" + nc + ":" + hashHttpVerbURIStr);

    // Compare hashes
    if (payloadHashEncoded == finalHash)
    {
      std::string payloadResponse = display("A4", false, "200");
      return payloadResponse;
    }
  }
  std::string payloadResponse = display("A4", false, "401 Unauthorized");
  return payloadResponse;
}

void HTTPDigestServer::importDB()
{
  std::ifstream ifs(PERSISTENCE_PATH);
  std::string line;

  while (getline(ifs, line))
  {
    users[line.substr(0, line.find(":"))] = line.substr(line.find(":") + 1, line.length());
  }  
}
