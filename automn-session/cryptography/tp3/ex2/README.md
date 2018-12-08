# Protokol

A c++ program to illustrate several protocol using cryptographic function.

## Requirement

**This program uses CryptoPP library.**

For example, in ubuntu you have to install the following packages to install CryptoPP lib:
```
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils --fix-missing
```

## Compilation

To compile:

```
g++ main.cpp communication/*.cpp servers/*.cpp clients/*.cpp -o main.out -lcryptopp
```

## Execution

To execute: 
```
./main.out
```

## Structure

This project uses four folders:

- `clients`:
    - `http-digest-client.h|.cpp`: class code source for http-digest protocol client
    - `password-client.h|.cpp`: class code source for password protocol client
    - `uaf-client.h|.cpp`: class code source for uaf protocol client
- `communication`:
    - `communication.h|.cpp`: code source for communication class. **Every client & server classes have been inherited from this class.**
- `persistence`:
    - Empty folder at the begining. The program stores data into it.
- `servers`:
    - `http-digest-server.h|.cpp`: class code source for http-digest protocol server
    - `password-server.h|.cpp`: class code source for password protocol server
    - `uaf-server.h|.cpp`: class code source for uaf protocol server

## Persistence file

The program will create several files in order to persist data. It will store them in persistence folder.

- `password.db`: Server database for password protocol. It uses the following format:
```
username + ":" + base64(md5(password))
```

- `http-digest.db`: Server database for http digest protocol. It uses the following format:
```
username + ":" + base64(md5(username:password))
```

- `uaf.client.wallet`: Store client wallet for UAF protocol. It uses the following format:
```
serverName + ":" + username + ":" + counterEncoded + "$" + privateKeyEncryptedEncodedWithAES
```

- `uaf.db`: Server database for UAF protocol. It uses the following format:
```
serverName + ":" + username + ":" + counterEncoded + "$" + privateKeyEncryptedEncodedWithAES
```
