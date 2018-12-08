#include "communication.h"

// This method is called on EVERY communication between clients and servers
// It allow user to play hacker role (MITM attack)
std::string Communication::hackerMenu(std::string message)
{
  std::string newMessage;
  std::cout << "--- HACKER ---> Vous avez intercepté le payload '" + message + "'." << std::endl;
  std::cout << "--- HACKER ---> Tapez un payload de remplacement si vous le souhaitez: ";
  getline(std::cin, newMessage);
  if (newMessage.empty())
  {
    return message;
  }
  return newMessage;
}

// This method is called on EVERY communication between clients and servers
std::string Communication::display(std::string step, bool clientToServer, std::string message)
{
  std::string way = "S -> C";
  if (clientToServer)
  {
    way = "C -> S";
  }
  std::cout << step << ". " << way << " : " << message << std::endl;
  std::string newMessage = hackerMenu(message);
  if (newMessage != message)
  {
    std::cout << step << "'. " << way << " : " << newMessage << std::endl;
    return newMessage;
  }
  return message;
}

// Global method to ask something to the program user
std::string Communication::askUser(std::string question)
{
  std::cout << question;
  std::string input;
  getline(std::cin, input);
  while (input.empty())
  {
    std::cout << "Chaine vide, ré-essayez: ";
    getline(std::cin, input);
  }
  return input;
}

// Global method to generate a random number using CryptoPP lib
std::string Communication::generateRandom()
{
  CryptoPP::AutoSeededRandomPool rng;
  // 16 bits => 5 digits number maximum
  CryptoPP::Integer rnd(rng, 16);
  std::stringstream ss;
  ss << rnd;
  return ss.str().substr(0, ss.str().length() - 1);
}

// Global method to hash (md5) and encode (base64) a string using CryptoPP lib
std::string Communication::md5AndEncode(std::string text)
{
  byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];

  hash1.CalculateDigest(digest, (const byte *)text.c_str(), text.length());

  CryptoPP::Base64Encoder encoder(NULL, false);
  std::string output;
  encoder.Attach(new CryptoPP::StringSink(output));
  encoder.Put(digest, sizeof(digest));
  encoder.MessageEnd();

  return output;
}
