#include "password-server.h"

PasswordServer::PasswordServer()
{
  importDB();
}

std::string PasswordServer::registration(std::string payload)
{
  // Parse payload
  std::string payloadResponse;
  std::string username = payload.substr(0, payload.find(" "));
  std::string password = payload.substr(payload.find(" ") + 1, payload.length());
  if (username.empty() || password.empty() || payload.find(" ") == std::string::npos)
  {
    payloadResponse = "400 Bad Request";
    payloadResponse = display("E2", false, payloadResponse);
    return payloadResponse;
  }

  // Save username and base64(md5(password)) into persitence file
  std::fstream file;
  file.open(PERSISTENCE_PATH, std::ios_base::app);
  file << username << ":" << md5AndEncode(password) << std::endl;
  file.close();

  // Update users catalog
  importDB();

  // Send payload response
  payloadResponse = "200";
  payloadResponse = display("E2", false, payloadResponse);
  return payloadResponse;
}

std::string PasswordServer::authenticate(std::string payload)
{
  // Parse payload
  std::string sessionID = payload.substr(0, payload.find(" "));
  payload = payload.substr(payload.find(" ") + 1, payload.length()); // Remove sessionID
  std::string username = payload.substr(0, payload.find(" "));
  std::string password = payload.substr(payload.find(" ") + 1, payload.length());
  if (username.empty() || password.empty() || payload.find(" ") == std::string::npos)
  {
    std::string payloadRes = display("A2", false, "400 " + sessionID);
    return payloadRes;
  }

  // Find username in users catalogue
  if (users.find(username) != users.end())
  {
    // Compare hashes
    if (users[username] == md5AndEncode(password))
    {
      // Generate cookie
      std::string cookie = generateRandom();
      cookies.push_back(cookie);

      // Send payload
      std::string payloadRes = display("A2", false, sessionID + " 200 SetCookie:Session=" + cookie);
      return payloadRes;
    }
  }

  // Send error payload
  std::string payloadRes = display("A2", false, sessionID + " 401");
  return payloadRes;
}

std::string PasswordServer::transaction(std::string payload)
{
  // Parse payload
  std::string sessionID = payload.substr(0, payload.find(" "));

  // Extract cookie
  std::string cookie = payload.substr(payload.find("=") + 1, payload.length());

  // Find cookie
  if (std::find(cookies.begin(), cookies.end(), cookie) != cookies.end())
  {
    // Send success payload
    std::string payloadRes = display("T2", false, sessionID + " 200");
    return payloadRes;
  }
  
  // Send error payload
  std::string payloadRes = display("T2", false, sessionID + " 401");
  return payloadRes;
}

void PasswordServer::importDB()
{
  std::ifstream ifs(PERSISTENCE_PATH);
  std::string line;

  while (getline(ifs, line))
  {
    users[line.substr(0, line.find(":"))] = line.substr(line.find(":") + 1, line.length());
  }
}
