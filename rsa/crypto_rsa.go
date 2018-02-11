package rsa

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

	"github.com/awgh/bencrypt"
	"github.com/awgh/bencrypt/bc"
)

var (
	// NAME - human-readable name of this Crypto implementation
	NAME = "RSA-4096,AES-CBC-256,HMAC-SHA-256"
)

func init() {
	bencrypt.KeypairTypes[NAME] = func() bc.KeyPair { return new(KeyPair) }
}

// PubKey : Implements bc.PubKey interface
type PubKey struct {
	Pubkey *rsa.PublicKey
}

// ToB64 : Returns Public Key as a Base64 encoded string
func (e *PubKey) ToB64() string {
	return base64.StdEncoding.EncodeToString(e.ToBytes())
}

// FromB64 : Sets Public Key from a Base64 encoded string
func (e *PubKey) FromB64(s string) error {
	pubkeypem, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return e.FromBytes(pubkeypem)
}

// ToBytes : Returns Public Key as bytes (PEM text)
func (e *PubKey) ToBytes() []byte {
	var b pem.Block
	b.Type = "PUBLIC KEY"
	b.Bytes, _ = x509.MarshalPKIXPublicKey(e.Pubkey)
	data := pem.EncodeToMemory(&b)
	return data
}

// FromBytes : Sets Public Key from bytes (PEM text)
func (e *PubKey) FromBytes(b []byte) error {
	p, _ := pem.Decode(b)
	if p != nil && p.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return err
		}
		e.Pubkey = pub.(*rsa.PublicKey)
		if e.Pubkey == nil {
			return errors.New("Nil Public Key in PubKey.FromBytes")
		}
		return nil
	}
	return errors.New("No Public Key Found in PubKey.FromBytes")
}

// Clone : Returns a new PubKey of the same type as this one
func (e *PubKey) Clone() bc.PubKey {
	return new(PubKey)
}

// KeyPair for RSA : Bencrypt Implementation of a RSA-4096,AES-CBC-256,HMAC-SHA-256 system
type KeyPair struct {
	privkey *rsa.PrivateKey
	pubkey  *PubKey
	keyHash []byte
}

// GetName : Returns the common language name for this cryptosystem
func (r *KeyPair) GetName() string {
	return NAME
}

// GetPubKey : Returns the Public portion of this KeyPair
func (r *KeyPair) GetPubKey() bc.PubKey {
	return r.pubkey
}

// Precompute : Precomputes key
func (r *KeyPair) Precompute() {
	keybytes, _ := x509.MarshalPKIXPublicKey(r.privkey)
	sha := sha256.New()
	if _, err := sha.Write(keybytes); err != nil {
		log.Fatal(err.Error())
	}
	r.keyHash = sha.Sum(nil)

	r.privkey.Precompute()
	if err := r.privkey.Validate(); err != nil {
		log.Fatal(err.Error())
	}

	if r.pubkey == nil {
		r.pubkey = new(PubKey)
	}
	r.pubkey.Pubkey = &r.privkey.PublicKey
}

// GenerateKey : Generates a new keypair inside this KeyPair object
func (r *KeyPair) GenerateKey() {
	p, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err.Error())
	}
	r.privkey = p

	r.Precompute()
}

// ToB64 : Returns the private portion of this keypair as a Base64-encoded string
func (r *KeyPair) ToB64() string {
	var b pem.Block
	b.Type = "RSA PRIVATE KEY"
	b.Bytes = x509.MarshalPKCS1PrivateKey(r.privkey)
	data := pem.EncodeToMemory(&b)
	s := base64.StdEncoding.EncodeToString(data)
	return s
}

// FromB64 : Sets the private portion of this keypair from a Base64-encoded string
func (r *KeyPair) FromB64(s string) error {
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
		r.Precompute()
		return nil
	}
	return errors.New("No Private Key Found")
}

/*
EncryptMessage : Encrypts a message
	1) generate aes key (32 random bytes)
   	2) encrypt the message with aes key
   	3) sha256 the encrypted message
   	4) sha256 the key and msg hash
   	5) encrypt the header with rsa
   	6) PEM encode encrypted header and encrypted message -> return
*/
func (r *KeyPair) EncryptMessage(clear []byte, pubkey bc.PubKey) ([]byte, error) {
	public, ok := pubkey.(*PubKey)
	if !ok {
		log.Fatal("KeyPair.EncryptMessage requires an PubKey, not some different kind of key")
	}
	// 1) generate aes key (32 random bytes)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	// 2) encrypt the message with aes key
	ciphertext, err := bc.AesEncrypt(clear, key)
	if err != nil {
		return nil, err
	}
	// 3) sha256 the encrypted message
	sha := sha256.New()
	_, err = sha.Write(ciphertext)
	if err != nil {
		return nil, err
	}
	msgsum := sha.Sum(nil)
	// 4) sha256 the key and msg hash
	sha.Reset()
	_, err = sha.Write(key)
	if err != nil {
		return nil, err
	}
	_, err = sha.Write(msgsum)
	if err != nil {
		return nil, err
	}
	hdrsum := sha.Sum(nil)
	// 5) encrypt the header with rsa
	header := make([]byte, 32+32+32)
	copy(header, key)
	copy(header[32:], msgsum)
	copy(header[32+32:], hdrsum)

	label := []byte("")
	enchdr, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public.Pubkey, header, label)
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
DecryptMessage : Decrypts a message
1) PEM decode header and body
2) decrypt header
3) verify the header signature
4) verify the msg signature
5) decrypt the msg
*/
func (r *KeyPair) DecryptMessage(data []byte) (bool, []byte, error) {

	h, rest := pem.Decode(data)
	t, _ := pem.Decode(rest)
	if h == nil || t == nil {
		return false, nil, errors.New("Invalid message - header or body missing")
	}

	label := []byte("")
	header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privkey, h.Bytes, label)
	if err != nil {
		return false, nil, err
	}

	sha := sha256.New()
	_, err = sha.Write(header[:32+32])
	if err != nil {
		return false, nil, err
	}
	hdrsum := sha.Sum(nil)

	x := subtle.ConstantTimeCompare(hdrsum, header[32+32:])
	if x != 1 {
		return false, nil, errors.New("Invalid message - header checksum failed")
	}

	sha.Reset()
	_, err = sha.Write(t.Bytes)
	if err != nil {
		return false, nil, err
	}
	msgsum := sha.Sum(nil)

	x = subtle.ConstantTimeCompare(msgsum, header[32:32+32])
	if x != 1 {
		return false, nil, errors.New("Invalid message - message checksum failed")
	}

	clear, err := bc.AesDecrypt(t.Bytes, header[:32])
	if err != nil {
		return false, nil, err
	}
	return true, clear, nil
}

// ValidatePubKey : Returns true if and only if the argument is a valid PubKey to this KeyPair
func (r *KeyPair) ValidatePubKey(s string) bool {
	pk := new(PubKey)
	if err := pk.FromB64(s); err != nil || pk.Pubkey == nil {
		return false
	}
	return true
}

// Clone : Returns a new node of the same type as this one
func (r *KeyPair) Clone() bc.KeyPair {
	return new(KeyPair)
}
