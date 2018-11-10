// To compile:
// To execute: Be carefull with () characters. You have to scape them (bash, zsh ...)

#include <string>
#include <vector>
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful

    int k, n, secret, q;

    if (string(argv[1]) == "-e")
    {
        for (int i = 2; i < argc; i++)
        {
            string arg = argv[i];
            if (arg == "-kn")
            {
                string threshold = argv[i + 1];
                threshold = threshold.substr(1, threshold.length() - 2); // Remove parenthesis
                string delimiter = ",";
                size_t pos = threshold.find(delimiter);
                k = stoi(threshold.substr(0, pos));
                n = stoi(threshold.substr(pos + 1, threshold.length() - 1));
            }
            else if (arg == "-s")
            {
                secret = atoi(argv[i + 1]);
            }
            else if (arg == "-q")
            {
                q = atoi(argv[i + 1]);
            }
            i++;
        }
        // vector<int> a = generateRandomPoly(k, q, s);
    }
    else if (string(argv[1]) == "-d")
    {
        vector<int *> points;
        for (int i = 2; i < argc; i++)
        {
            string arg = argv[i];
            if (arg == "-p")
            {
                string pointStr = argv[i + 1];
                pointStr = pointStr.substr(1, pointStr.length() - 2); // Remove parenthesis
                string delimiter = ",";
                size_t pos = pointStr.find(delimiter);
                int x = stoi(pointStr.substr(0, pos));
                int y = stoi(pointStr.substr(pos + 1, pointStr.length() - 1));
                int point[2] = {x, y}; 
                points.push_back(point);
            }
            else if (arg == "-q")
            {
                q = atoi(argv[i + 1]);
            }
            i++;
        }
    }
}
