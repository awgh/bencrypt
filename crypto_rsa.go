package bencrypt

/*
-= Notes on the crypto =-

"The message must be no longer than the length of the public
modulus less twice the hash length plus 2."

The modulus for a 4096 bit key is 512 bytes.
The hash length for SHA256 is 32 bytes.
(32*2)+2 = 68.  512 - 68 = 444.  So we can have 444 bytes of data.

AES256 keys are 32 bytes long.  AES256 IVs are 16 bytes long.

Message Format:
--rsa begin---
(32) AES256 key
(32) SHA256 enc(msg) hash
(32) SHA256 header excluding this field hash  TOTAL=96 bytes
--rsa end---
--aes begin---
message
--aes end---
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
)

type RSA struct {
	privkey *rsa.PrivateKey
	pubkey  *rsa.PublicKey
	keyHash []byte
}

func (r *RSA) GetName() string {
	return "RSA-4096,AES-CBC-256,HMAC-SHA-256"
}

func (r *RSA) GetPubKey() interface{} {
	return r.pubkey
}

func (r *RSA) precompute() {
	keybytes, _ := x509.MarshalPKIXPublicKey(r.privkey)
	sha := sha256.New()
	sha.Write(keybytes)
	r.keyHash = sha.Sum(nil)

	r.privkey.Precompute()
	err := r.privkey.Validate()
	if err != nil {
		log.Fatal(err.Error())
	}

	r.pubkey = &r.privkey.PublicKey
}

func (r *RSA) GenerateKey() {
	p, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err.Error())
	}
	r.privkey = p

	r.precompute()
}

func (r *RSA) B64fromPrivateKey() string {
	var b pem.Block
	b.Type = "RSA PRIVATE KEY"
	b.Bytes = x509.MarshalPKCS1PrivateKey(r.privkey)
	data := pem.EncodeToMemory(&b)
	s := base64.StdEncoding.EncodeToString(data)
	return s
}

// Expecting base64-encoded single PEM block containing private key
func (r *RSA) B64toPrivateKey(s string) error {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(dec)
	if p != nil && p.Type == "RSA PRIVATE KEY" {
		priv, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return err
		}
		r.privkey = priv
		r.precompute()
		return nil
	}
	return errors.New("No Private Key Found.")
}

func (r *RSA) B64fromPublicKey(pubkey interface{}) string {
	public, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("*rsa.PublicKey type assertion failed - your code is broken.")
	}

	var b pem.Block
	b.Type = "PUBLIC KEY"
	b.Bytes, _ = x509.MarshalPKIXPublicKey(public)
	data := pem.EncodeToMemory(&b)
	s := base64.StdEncoding.EncodeToString(data)
	return s
}

// Expecting base64-encoded single PEM block containing public key
func (r *RSA) B64toPublicKey(s string) (interface{}, error) {
	pubkey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(pubkey)

	if p != nil && p.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		return pub.(*rsa.PublicKey), nil
	}
	return nil, errors.New("No Public Key Found.")
}

/*
	1) generate aes key (32 random bytes)
   	2) encrypt the message with aes key
   	3) sha256 the encrypted message
   	4) sha256 the key and msg hash
   	5) encrypt the header with rsa
   	6) PEM encode encrypted header and encrypted message -> return
*/
func (r *RSA) EncryptMessage(clear []byte, pubkey interface{}) ([]byte, error) {
	public, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("*rsa.PublicKey type assertion failed - your code is broken.")
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	ciphertext, err := aesEncrypt(clear, key)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(ciphertext)
	msgsum := sha.Sum(nil)

	sha.Reset()
	sha.Write(key)
	sha.Write(msgsum)
	hdrsum := sha.Sum(nil)

	header := make([]byte, 32+32+32)
	copy(header, key)
	copy(header[32:], msgsum)
	copy(header[32+32:], hdrsum)

	label := []byte("")
	enchdr, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, header, label)
	if err != nil {
		return nil, err
	}

	//6) PEM encode encrypted header and encrypted message -> return
	var h, t pem.Block
	h.Type = "HEADS"
	h.Bytes = enchdr

	t.Type = "TAILS"
	t.Bytes = ciphertext
	outval := pem.EncodeToMemory(&h)
	return append(outval, pem.EncodeToMemory(&t)...), nil
}

/*
1) PEM decode header and body
2) decrypt header
3) verify the header signature
4) verify the msg signature
5) decrypt the msg
*/
func (r *RSA) DecryptMessage(data []byte) ([]byte, error) {

	h, rest := pem.Decode(data)
	t, _ := pem.Decode(rest)
	if h == nil || t == nil {
		return nil, errors.New("Invalid message - header or body missing")
	}

	label := []byte("")
	header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privkey, h.Bytes, label)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(header[:32+32])
	hdrsum := sha.Sum(nil)

	x := subtle.ConstantTimeCompare(hdrsum, header[32+32:])
	if x != 1 {
		return nil, errors.New("Invalid message - header checksum failed")
	}

	sha.Reset()
	sha.Write(t.Bytes)
	msgsum := sha.Sum(nil)

	x = subtle.ConstantTimeCompare(msgsum, header[32:32+32])
	if x != 1 {
		return nil, errors.New("Invalid message - message checksum failed")
	}

	clear, err := aesDecrypt(t.Bytes, header[:32])
	if err != nil {
		return nil, err
	}
	return clear, nil
}
