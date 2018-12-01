#ifndef DEF_COMMUNICATION
#define DEF_COMMUNICATION

#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <cryptopp/osrng.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include "cryptopp/base64.h"

class Communication
{
  protected:
    virtual std::string display(std::string step, bool clientToServer, std::string message);
    virtual std::string askUser(std::string question);
    virtual std::string generateRandom();
    virtual std::string md5AndEncode(std::string text);

  private:
    std::string hackerMenu(std::string);
};

#endif
