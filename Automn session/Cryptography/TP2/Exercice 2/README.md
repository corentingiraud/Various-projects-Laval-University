# Passwords global wallet C++ Crypto

A very simple c++ program to save passwords in a file in a secure way using AES 128 CTR mode.

**This program uses CryptoPP library.**

For example, in ubuntu you have to install the following packages to install CryptoPP lib:
`sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils --fix-missing`

To compile:
`g++ ex2.cpp -o ex2.out -lcryptopp`

## Wallet file

The wallet file name is : `password-wallet.enc`.

The wallet format is:
`<hexEncode(CTR_IV)>$<hexEncode(AES_CTR(service))>:<hexEncode(CTR_IV)>$<hexEncode(AES_CTR(url))>:<hexEncode(CTR_IV)>$<hexEncode(AES_CTR(username))>:<hexEncode(CTR_IV)>$<hexEncode(AES_CTR(password))>`

## Examples

- `./ex2 -a 123pwd -srv facebook -url www.facebook.com -user alice@gmail.com -pwd 12t3r`: secure the wallet with 123pwd secret. Add facebook service (url: www.facebook.com) with username: alice@gmail.com and pwd: 12t3r
- `./ex2.out -l 123pwd`: list all services in the secure wallet
- `./ex2.out -d 123pwd -i 1 -user`: display a specific service indentified by its line index (-i option) and display only username
- `./ex2.out -d 123pwd -i 1 -user -pwd`: display a specific service indentified by its line index (-i option) and display username and password
