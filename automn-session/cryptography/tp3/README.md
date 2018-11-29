# OpenSSL practice

## Key generation

Generate 2048bits private key encrypted with DES3 (ie: a pass phrase will be necessary to use the private key)

`openssl genrsa -des3 -out alice-privatekey.pem 2048`

## Hash signature

### Alice side

Store `sign(sha1(message.txt))` in `message.sha1-signed` with alice private key:

`openssl dgst -sha1 -sign alice-privatekey.pem -out message.sha1-signed message.txt`

### Bob side

Verify `sha1(message.txt) = unsigned(message.sha1-signed)` with alice public key:

`openssl dgst -sha1 -verify alice-publickey.pem -signature message.sha1-signed message.txt`

## Encrypt | Decrypt file (encrypted symetric key sharing)

### Alice side

Generate the random key and store it as binary file in `key.bin`:

`openssl rand -out key.bin 16`

Encrypt `message.txt` using AES 128 CBC using the key, encodes it using base64 and store it to `protected-message.txt`:

`openssl enc -aes-128-cbc -kfile key.bin -in message.txt -base64 -out protected-message.txt`

Encrypt the random key with the bob public key:

`openssl rsautl -encrypt -inkey bob-publickey.pem -pubin -in key.bin -out protected-key.bin`

Alice send to bob `protected-message.txt` and `protected-key.bin`.

### Bob side

Decrypt the random key with bob's private key file:

`openssl rsautl -decrypt -inkey bob-privatekey.pem -in protected-key.bin -out key.bin`

Decrypt `protected-message.txt` with the decrypted random key:

`openssl enc -d -aes-128-cbc -in protected-message.txt -out message.txt -base64 -kfile key.bin`
