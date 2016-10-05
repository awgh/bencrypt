
# What is Bencrypt?

Bencrypt is an abstraction layer for cryptosystems in Go, that lets applications use hybrid cryptosystems without being coupled to their internal workings. It lets applications easily switch between using ECC or RSA, for example.

Implementations of both ECC-based and RSA-based systems are included, as are a collection of generally-useful crypto utilities, such as:

    - PKCS7 Padding/Unpadding
    - AES-CBC symmetric encrypt/decrypt
    - SSL Certificate Generation in both RSA and ECC modes

Bencrypt was developed to provide a layer of abstraction for cryptosystems below the [ratnet project](https://github.com/awgh/ratnet).
	
# Documentation

API Docs are availble here: https://godoc.org/github.com/awgh/bencrypt

# Usage

In normal usage, you will want to include at least two packages:
"bencrypt/bc" - This contains the API and interfaces, you'll need this every time

Then, include each cryptosystem definition that you want to use.  Two of them are included with bencrypt at the moment:
"bencrypt/ecc" - A hybrid cryptosystem using Curve25519, AES-CBC-256, and HMAC-SHA-256.
"bencrypt/rsa" - A hybrid cryptosystem using RSA-4096, AES-CBC-256, and HMAC-SHA-256.

# Add Your Own CryptoSystem

To add your own cryptosystem to bencrypt:
    1) Make a new package and include "bencrypt/bc".
    2) Create an implementation of [bc.PubKey](https://godoc.org/github.com/awgh/bencrypt/bc#PubKey) for your system.
    3) Create an implementation of [bc.KeyPair](https://godoc.org/github.com/awgh/bencrypt/bc#KeyPair) for your system.
	
Then, to use it, just include your system instead of "bencrypt/ecc" or "bencrypt/rsa" in your app.


# Authors and Contributors
awgh@awgh.org (@awgh)
