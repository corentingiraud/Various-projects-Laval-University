# Shamir's Secret Sharing - C++ | CryptoPP simple implementation

This c++ program is a simple implementation of the Shamir's Secret Sharing. More information about Shamir algorithm could be found on [wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

**This program uses CryptoPP library.**

For example, in ubuntu you have to install the following packages to install CryptoPP lib:
`sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils --fix-missing`

To compile:
`g++ ex3.cpp -o ex3.out -lcryptopp`

## Examples

### Example 1

Generate 5 points for sharing the secret 7. 3 points are necessary to find the secret. All operations will be computed modulus 31.

**Input:**
```
./ex3.out -e -kn \(3,5\) -s 7 -q 31
```

**Output (for example because every generation is unique):**
```
Generated polynom: 7 * x^0 + 13 * x^1 + 31 * x^2
Generated points: 
s1: (1,20)
s2: (2,2)
s3: (3,15)
s4: (4,28)
s5: (5,10)
```

### Example 2

Generate 4 points for sharing the secret 91. 3 points are necessary to find the secret. All operations will be computed modulus 127.

**Input:**
```
./ex3.out -e -kn \(3,4\) -s 91 -q 127
```

**Output (for example because every generation is unique):**
```
Generated polynom: 91 * x^0 + 68 * x^1 + 55 * x^2
Generated points: 
s1: (1,87)
s2: (2,66)
s3: (3,28)
s4: (4,100)
```

### Example 3

Find the secret using 3 points (option -p). All operations will be computed modulus 31.

**Input:**
```
./ex3.out -d -p \(1,20\) -p \(2,2\) -p \(3,15\) -q 31
```

**Output:**
```
Secret: 7
```

### Example 4

Find the secret using 3 points (option -p). All operations will be computed modulus 127.

**Input:**
```
./ex3.out -d -p \(1,64\) -p \(2,10\) -p \(7,97\) -q 127
```

**Output:**
```
Secret: 91
```
