
What is Bencrypt?

Bencrypt is an abstraction layer for cryptosystems in Go, that lets applications use hybrid cryptosystems without being coupled to their internal workings. It lets applications easily switch between using ECC or RSA, for example.

Implementations of both ECC-based and RSA-based systems are included, as are a collection of generally-useful crypto utilities, such as:

    - PKCS7 Padding/Unpadding
    - AES symmetric encrypt/decrypt
    - SSL Certificate Generation in both RSA and ECC modes
    - Bencrypt was developed to provide a layer of abstraction for cryptosystems below the ratnet project.

	
Documentation

API Docs are availble here: https://godoc.org/github.com/awgh/bencrypt


Authors and Contributors
awgh@awgh.org (@awgh)