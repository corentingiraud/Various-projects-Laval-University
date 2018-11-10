# Various block cipher mode of operation

This programme implements various [block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
including (ECB, CBC, CFB, OFB and CTR).

It uses a simple cryptographic system (a permutation).

To compile: `g++ ex2.cpp -o ex2.out`

## Available options

- `-msg`: binary message. Its size must be a multiple of 6.
- `-key`: key representing the permutation.
- `-op`: means operation. It could be `enc` for encryption or `dec` for decryption.
- `-mode`: indicates the block cipher mode of operation. It could be ` ECB`, `CBC`, `CFB`, `OFB` or `CTR`.
- `-iv` (optional): binary string of size 6. If no IV is provided by the user, the program will use a random one.
- `-r` (only for CFB and OFB mode): a number r where 1 <= r <= 6.

## Examples of usage

- `COMMAND` => `RESULT`

### ECB

- `./ex2 -msg 111000 -key 653421 -op enc -mode ECB` => `001011`
- `./ex2 -msg 111000000111 -key 653421 -op enc -mode ECB ` => `001011110100`
- `./ex2 -msg 111000000111101010 -key 653421 -op enc -mode ECB` => `001011110100011001`

### CBC
NB: the six first characters is the IV used for encryption

- `./ex2 -msg 110011001100101010 -key 564321 -op enc -mode CBC -iv 101010` => `101010010110100110001100`
- `./ex2 -msg 110011001100101010 -key 564321 -op dec -mode CBC -iv 101010` => `101010011001111111011010`

### CFB
NB: the six first characters is the IV used for encryption

- `./ex2 -msg 101010010101100011 -key 214365 -op enc -mode CFB -iv 110011 -r 5` => `110011011000101101111000`

### OFB
NB: the six first characters is the IV used for encryption

- `./ex2 -msg 010101101010001110 -key 654321 -op enc -mode OFB -iv 100100 -r 4` => `100100011111111000101010`

### CTR
NB: the six first characters is the IV used for encryption

- `ex2 -msg 111011011111101010 -key 321645 -op enc -mode CTR -iv 101111` => `101111010100000111110110`
