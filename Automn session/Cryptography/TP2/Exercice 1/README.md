# Ransomware C++ Crypto++

**For educational purpose only**

A very simple c++ program to crypt an entire directory using [Crypto++](https://www.cryptopp.com/).
After encryption, a file called `pirate.txt` is created in the directory you want to crypt. It contains the Key and IV used to crypt every file using AES 128 with CBC mode. Of course these information need to be send to the pirate in a real ransomware.

**This program uses CryptoPP library.**

For example, in ubuntu you have to install the following packages to install CryptoPP lib:
`sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils --fix-missing`

To compile the project:
`g++ ex1.cpp -o ex1.out -lcryptopp -lstdc++fs`

To run the programme:
`./ex1.out <OPTIONS>`

OPTIONS:

- `-f`: file type (could be "jpg", "png", "doc", "pdf", "txt"). NB: only one extension! So if you want to crypt both .txt and .jpg, you have to use `-f txt -f jpg`
- `-d`: directory path (relative from execution path)
- `-1`: to decrypt
