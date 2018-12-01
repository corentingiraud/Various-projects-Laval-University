#include "password-server.h"

PasswordServer::PasswordServer()
{
  importDB();
}

std::string PasswordServer::registration(std::string payload)
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
  file << username << ":" << md5AndEncode(password) << std::endl;
  file.close();
  payloadResponse = "200";
  payloadResponse = display("E2", false, payloadResponse);
  importDB();
  return payloadResponse;
}

std::string PasswordServer::authenticate(std::string payload)
{
  std::string sessionID = payload.substr(0, payload.find(" "));
  payload = payload.substr(payload.find(" ") + 1, payload.length()); // Remove sessionID
  std::string username = payload.substr(0, payload.find(" "));
  std::string password = payload.substr(payload.find(" ") + 1, payload.length());
  if (username.empty() || password.empty() || payload.find(" ") == std::string::npos)
  {
    std::string payloadRes = display("A2", false, "400 " + sessionID);
    return payloadRes;
  }
  if (users.find(username) != users.end())
  {
    if (users[username] == md5AndEncode(password))
    {
      std::string cookie = generateRandom();
      cookies.push_back(cookie);
      std::string payloadRes = display("A2", false, sessionID + " 200 SetCookie:Session=" + cookie);
      return payloadRes;
    }
  }
  std::string payloadRes = display("A2", false, sessionID + " 401");
  return payloadRes;
}

std::string PasswordServer::transaction(std::string payload)
{
  std::string sessionID = payload.substr(0, payload.find(" "));
  std::string cookie = payload.substr(payload.find("=") + 1, payload.length()); // Extract cookie
  if (std::find(cookies.begin(), cookies.end(), cookie) != cookies.end())
  {
    std::string payloadRes = display("T2", false, sessionID + " 200");
    return payloadRes;
  }
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
