#include <iostream>
#include <string>
#include <vector>
#include <time.h>
using namespace std;

// Global variables
string MSG;
string KEY;
string OP;
string MODE;
string IV;
int R;

// This method returns Ek(bloc) and uses KEY global variable
string cryptBloc(string bloc)
{
  string cryptResult = "";
  for (char &k : KEY)
  {
    int i = (int)k - 48;
    cryptResult = cryptResult + bloc[i - 1];
  }
  return cryptResult;
}

// This method returns Dk(cryptedBloc) and uses KEY global variable
string decryptBloc(string cryptedBloc)
{
  string decryptResult = "";
  for (char &k : KEY)
  {
    int j = (int)k - 48;
    decryptResult = decryptResult + cryptedBloc[j - 1];
  }
  return decryptResult;
}

// This method returns vector of string which have size characters (6 by default)
vector<string> splitMessageIntoBlocs(int size = 6)
{
  vector<string> result;
  int numSubBlocs = MSG.length() / size;
  for (int i = 0; i < numSubBlocs; i++)
  {
    result.push_back(MSG.substr(i * size, size));
  }
  if (R && numSubBlocs * size != MSG.length())
  {
    result.push_back(MSG.substr(numSubBlocs * size, MSG.length()));
  }
  return result;
}

// This method returns a XOR b. a and b must have the same size.
string XOR(string a, string b)
{
  if (a.length() == b.length())
  {
    string result = "";
    for (int i = 0; i < a.length(); i++)
    {
      result = result + to_string((a[i] - '0') ^ (b[i] - '0'));
    }
    return result;
  }
  cerr << "ERROR during XOR operation, string lengths must be equal" << endl;
  return "";
}

// This method returns 6 random bits
string randomBloc()
{
  string result = "";
  for (int i = 0; i < 6; i++)
  {
    result = result + to_string(rand() % 2);
  }
  return result;
}

string splitBlocLeft(string bloc, int size = R)
{
  return bloc.substr(0, size);
}

string splitBlocRight(string bloc, int size = 6)
{
  return bloc.substr(bloc.length() - size, bloc.length() - 1);
}

// This method add 1 to the bloc parameters.
string addOne(string bloc)
{
  int bit = bloc.at(bloc.length() - 1) - '0';
  int sum = bit ^ 1;
  string result = to_string(sum);
  int i = bloc.length() - 2;
  int carry = (bit & 1);

  while (carry && i >= 0)
  {
    bit = bloc.at(i) - '0';
    sum = bit ^ carry;
    result = to_string(sum) + result;
    carry = (bit & carry);
    i--;
  }

  return splitBlocLeft(bloc, i + 1) + result;
}

// ECB mode implementation
string ECB(vector<string> messageBlocs)
{
  vector<string>::iterator it;
  string result = "";

  if (OP == "enc")
  {
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute c_i = Ek(m_i) and add it to the result
      result = result + cryptBloc(*it);
    }
  }
  else if (OP == "dec")
  {
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute m_i = Dk(c_i) and add it to the result
      result = result + decryptBloc(*it);
    }
  }
  cerr << "OP option is invalid or is required" << endl;
  return result;
}

// CBC mode implementation
string CBC(vector<string> messageBlocs)
{
  string result = "";
  string tmpBloc;

  if (OP == "enc")
  {
    tmpBloc = IV.empty() ? randomBloc() : IV;
    result = tmpBloc;
    string blocToCrypt;
    vector<string>::iterator it;

    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute c_i = Ek(c_i-1 XOR m_i) and add it to result
      // NB: we must keep in memory c_i-1 to compute c_i. This value is stored in tmpBloc
      blocToCrypt = XOR(tmpBloc, *it);
      tmpBloc = cryptBloc(blocToCrypt);
      result = result + tmpBloc;
    }
  }
  else if (OP == "dec")
  {
    string decryptedBloc;
    vector<string>::reverse_iterator rIt;
    if (IV.size() != 0)
    {
      // If IV option was given, we insert it as the first position
      messageBlocs.insert(messageBlocs.begin(), IV);
    }
    // We iterate through the message from the end to the begining + 1 (because begining is IV vector)
    for (rIt = messageBlocs.rbegin(); rIt + 1 != messageBlocs.rend(); ++rIt)
    {
      // Compute m_i = c_i-1 XOR Dk(c_i) and add it to result
      tmpBloc = decryptBloc(*rIt);
      decryptedBloc = XOR(tmpBloc, *(rIt + 1));
      result = decryptedBloc + result;
    }
  }
  cerr << "OP option is invalid or is required" << endl;
  return result;
}

// CFB mode implementation
string CFB(vector<string> messageBlocs)
{
  string result = "";
  if (OP == "enc")
  {
    string i = IV.empty() ? randomBloc() : IV;
    result = i;
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute c_i = L(o_i, m_i.size()) XOR m_i and add it to result
      // Where l(o_i, r) represents a function which split o_i from 0 to r bit(s)
      string cryptedBloc = XOR(splitBlocLeft(cryptBloc(i), (*it).length()), *it);
      result = result + cryptedBloc;
      // Compute i_j+1 = (2^r * i_j + c_j) mod 2^n
      // Where:
      //   - 2^r * i_j + c_j can be simplify by i_j + c_j because i_j and c_j are strings
      //   - MOD 2^n can be simplify by keeping the 6 last characters (=> splitBlocRight() with default size (6))
      i = splitBlocRight(i + cryptedBloc); 
    }
    return result;
  }
  else if (OP == "dec")
  {
    result = "";
    string i = IV;
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute c_i = L(o_i, m_i.size()) XOR m_i and add it to result
      // Where l(o_i, r) representss a function which split o_i from 0 to r bit(s)
      string decryptedBloc = XOR(splitBlocLeft(cryptBloc(i), (*it).length()), *it);
      result = result + decryptedBloc;
      i = splitBlocRight(i + *it);
    }
    return result;
  }
  cerr << "OP option is invalid or is required" << endl;
  return result;
}

// OFB mode implementation
string OFB(vector<string> messageBlocs)
{
  string result = "";
  if (OP == "enc")
  {
    string o = IV.empty() ? randomBloc() : cryptBloc(IV);
    result = IV;
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute c_i = L(o_i, m_i.size()) XOR m_i and add it to result
      // Where l(o_i, r) represents a function which split o_i from 0 to r bit(s)
      string cryptedBloc = XOR(splitBlocLeft(o, (*it).length()), *it);
      result = result + cryptedBloc;
      o = cryptBloc(o); // Compute o_i+1 = Ek(o)
    }
    return result;
  }
  else if (OP == "dec")
  {
    result = "";
    string o = cryptBloc(IV);
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      // Compute m_i = L(o_i, c_i.size()) XOR c_i and add it to result
      // Where l(o_i, r) represents a function which split o_i from 0 to r bit(s)
      string decryptedBloc = XOR(splitBlocLeft(o, (*it).length()), *it);
      result = result + decryptedBloc;
      o = cryptBloc(o); // Compute o_i+1 = Ek(o)
    }
    return result;
  }
  cerr << "OP option is invalid or is required" << endl;
  return result;
}

// CTR mode implementation
string CTR(vector<string> messageBlocs)
{
  string result = "";
  if (OP == "enc")
  {
    string ctr = IV.empty() ? randomBloc() : IV;
    result = IV;
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      result = result + XOR(cryptBloc(ctr), *it); // Add 'Ek(counter_i-1) XOR m_i' to the result string
      ctr = addOne(ctr); // Add 1 to the counter vector: counter_i+1 = counter_i + 1
    }
    return result;
  }
  else if (OP == "dec")
  {
    string ctr = IV;
    vector<string>::iterator it;
    for (it = messageBlocs.begin(); it != messageBlocs.end(); it++)
    {
      result = result + XOR(cryptBloc(ctr), *it); // Add 'Ek(counter_i-1) XOR c_i' to the result string
      ctr = addOne(ctr); // Add 1 to the counter vector: counter_i+1 = counter_i + 1
    }
    return result;
  }
  cerr << "OP option is invalid or is required" << endl;
  return result;
}

int main(int argc, char *argv[])
{
  // ------------  Parse arguments
  // NB: no arg checks because user is trustful
  for (int i = 1; i < argc; ++i)
  {
    string arg = argv[i];
    if (arg == "-msg")
    {
      MSG = argv[i + 1];
      i++;
    }
    else if (arg == "-key")
    {
      KEY = argv[i + 1];
      i++;
    }
    else if (arg == "-op")
    {
      OP = argv[i + 1];
      i++;
    }
    else if (arg == "-mode")
    {
      MODE = argv[i + 1];
      i++;
    }
    else if (arg == "-iv")
    {
      IV = argv[i + 1];
      i++;
    }
    else if (arg == "-r")
    {
      R = atoi(argv[i + 1]);
      i++;
    }
  }

  srand(time(NULL)); // rand() function initialization with time

  // ------------  Options recap
  // It could be usefull for debug to decomment these lines
  // cout << "---- Ex2 program execution with the following options: " << endl;
  // cout << "Message: " << MSG << endl;
  // cout << "Key: " << KEY << endl;
  // cout << "Op: " << OP << endl;
  // cout << "Mode: " << MODE << endl;
  // cout << "Iv: " << IV << endl;
  // cout << "R: " << R << endl
  //      << endl
  //      << endl;

  // ------------ Execution
  string result = "";

  if (MODE == "ECB")
  {
    vector<string> messageBlocs = splitMessageIntoBlocs();
    result = ECB(messageBlocs);
  }
  else if (MODE == "CBC")
  {
    vector<string> messageBlocs = splitMessageIntoBlocs();
    result = CBC(messageBlocs);
  }
  else if (MODE == "CFB")
  {
    // Extract IV from message if no IV was given and MODE = "dec"
    if (OP == "dec" && IV.empty())
    {
      IV = splitBlocLeft(MSG, 6);
      MSG = splitBlocRight(MSG, MSG.length() - 6); // slice the IV from message and save new value into MSG
    }
    vector<string> messageBlocs = splitMessageIntoBlocs(R);
    result = CFB(messageBlocs);
  }
  else if (MODE == "OFB")
  {
    // Extract IV from message if no IV was given and MODE = "dec"
    if (OP == "dec" && IV.empty())
    {
      IV = splitBlocLeft(MSG, 6);
      MSG = splitBlocRight(MSG, MSG.length() - 6); // slice the IV from message and save new value into MSG
    }
    vector<string> messageBlocs = splitMessageIntoBlocs(R);
    result = OFB(messageBlocs);
  }
  else if (MODE == "CTR")
  {
    // Extract IV from message if no IV was given and MODE = "dec"
    if (OP == "dec" && IV.empty())
    {
      IV = splitBlocLeft(MSG, 6);
      MSG = splitBlocRight(MSG, MSG.length() - 6); // slice the IV from message and save new value into MSG
    }
    vector<string> messageBlocs = splitMessageIntoBlocs();
    result = CTR(messageBlocs);
  }
  else
  {
    cerr << "Invalid mode" << endl;
    return 1;
  }

  // Display result
  cout << result << endl;
  return 0;
}
