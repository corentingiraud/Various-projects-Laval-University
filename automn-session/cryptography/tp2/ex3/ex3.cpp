// To compile: g++ ex3.cpp -o ex3.out -lcryptopp
// To execute: Be carefull with parenthesis characters. You have to escape them using " or \.

#include <string>
#include <vector>
#include <iostream>
#include <math.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>

using namespace std;
using namespace CryptoPP;

/*
 * Generate (k - 1) random polynomial coefficients from 0 to q.
 * The first coefficient is s (shamir secret).
 * This function use Integer class from cryptopp lib.
 * More information: https://www.cryptopp.com/docs/ref/class_integer.html
 *
 * Arguments
 * 	k: number of coefficient to generate
 *  s: shamir secret, it will be the first coefficient
 *  q: modulo value
 *
 * Returns:
 * 	vector containing coefficients
 */
vector<long> generateRandomCoefPoly(long k, long s, long q)
{
    vector<long> a;
    a.push_back(s);
    AutoSeededRandomPool rng;
    Integer::RandomNumberType r;
    for (int i = 1; i < k; i++)
    {
        Integer randomCoef = Integer(rng, 0, q);
        a.push_back(randomCoef.ConvertToLong());
    }
    return a;
}

/*
 * Generate n points (x,f(x)) where f is a polynom.
 * f coefficient is aCoefs.
 * 
 * Arguments
 * 	aCoefs: coefficients vector
 *  n: number of point to generate
 *  q: modulo value
 *
 * Returns:
 * 	vector containing vectors of coordinates x, y representing a generated point
 */
vector<vector<long>> generatePoints(vector<long> aCoefs, long n, long q)
{
    vector<vector<long>> points;
    for (long i = 1; i <= n; i++)
    {
        long x = i;
        long y = 0;
        for (long j = 0; j < aCoefs.size(); j++)
        {
            y = y + aCoefs[j] * pow(x, j);
        }
        vector<long> currentPoint;
        currentPoint.push_back(x);
        currentPoint.push_back(y % q);
        points.push_back(currentPoint);
    }
    return points;
}

/*
 * Compute (brute force) a modular inverse
 * 
 * Arguments
 * 	a: the number to inverse
 *  q: modulo value
 *
 * Returns:
 * 	a-1 (in Zq)
 */
long modInverse(long a, long q)
{
    a = a % q;
    for (long x = 1; x < q; x++)
        if ((a * x) % q == 1)
            return x;
    return 0;
}

/*
 * Find shamir secret using points and modulo value
 * 
 * Arguments
 *  points: Every point
 *  q: modulo value
 *
 * Returns:
 * 	the shamir secret
 */
long findSecret(vector<vector<long>> points, long q)
{
    long s = 0; // Shamir secret
    int i = 0;  // First index
    for (const auto &point : points)
    {
        // Compute Ii(0) of current point
        long num = 1;   // Numerator
        long denom = 1; // Denominator
        int j = 0;      // Second index
        for (const auto &pointI : points)
        {
            if (i != j)
            {
                num = (num * pointI[0]) % q;
                denom = (denom * (pointI[0] - point[0])) % q;
            }
            j++;
        }
        if (denom < 0)
            denom += q;

        // Find denom-1 (Modular inverse)
        long denomInverse = modInverse(denom, q);

        // Add to secret
        s += (point[1] * num * denomInverse) % q;
        i++;
    }
    return s % q;
}

int main(int argc, char *argv[])
{
    // ------------  Parse arguments
    // NB: no arg checks because user is trustful

    long k, n, s, q;

    // ------------ Shamir generation
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
                k = stol(threshold.substr(0, pos));
                n = stol(threshold.substr(pos + 1, threshold.length() - 1));
            }
            else if (arg == "-s")
            {
                s = atol(argv[i + 1]);
            }
            else if (arg == "-q")
            {
                q = atol(argv[i + 1]);
            }
            i++;
        }
        // Generate random coefficients
        vector<long> aCoefs = generateRandomCoefPoly(k, s, q);

        // Display polynom
        cout << "Generated polynom: ";
        int index = 0;
        for (const auto &a : aCoefs)
        {
            cout << a << " * x^" << index;
            if (index < k - 1) // Pretty print
                cout << " + ";
            index++;
        }
        cout << endl;

        // Generate n points
        vector<vector<long>> points = generatePoints(aCoefs, n, q);
        index = 1;

        // Display generated points
        cout << "Generated points: " << endl;
        for (const auto &i : points)
        {
            cout << "s" << index << ": (" << i[0] << "," << i[1] << ")" << endl;
            index++;
        }
    }

    // ------------ Shamir secret finding
    else if (string(argv[1]) == "-d")
    {
        vector<vector<long>> points;
        for (int i = 2; i < argc; i++)
        {
            string arg = argv[i];
            if (arg == "-p")
            {
                string pointStr = argv[i + 1];
                pointStr = pointStr.substr(1, pointStr.length() - 2); // Remove parenthesis
                string delimiter = ",";
                size_t pos = pointStr.find(delimiter);
                long x = stol(pointStr.substr(0, pos));
                long y = stol(pointStr.substr(pos + 1, pointStr.length() - 1));
                vector<long> currentPoint;
                currentPoint.push_back(x);
                currentPoint.push_back(y);
                points.push_back(currentPoint);
            }
            else if (arg == "-q")
            {
                q = atoi(argv[i + 1]);
            }
            i++;
        }
        // Find the secret a display it
        long s = findSecret(points, q);
        cout << "Secret: " << s << endl;
    }
}
