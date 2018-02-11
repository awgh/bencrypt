package ecc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"

	"github.com/awgh/bencrypt"
	"github.com/awgh/bencrypt/bc"

	"golang.org/x/crypto/curve25519"
)

var (
	// NAME - human-readable name of this Crypto implementation
	NAME = "Curve25519,AES-CBC-256,HMAC-SHA-256"

	//1ef17714-dbbf-4d1c-8869-e8273e2c327a
	aesKeyLabel = []byte{
		0x1e, 0xf1, 0x77, 0x14, 0xdb, 0xbf, 0x4d, 0x1c,
		0x88, 0x69, 0xe8, 0x27, 0x3e, 0x2c, 0x32, 0x7a}

	//1f8fac50-357a-4cfd-b67b-085311534df8
	macKeyLabel = []byte{
		0x1f, 0x8f, 0xac, 0x50, 0x35, 0x7a, 0x4c, 0xfd,
		0xb6, 0x7b, 0x08, 0x53, 0x11, 0x53, 0x4d, 0xf8}

	//c0533b6e-1a94-44b7-b3be-24f98430fd69
	luggageKeyLabel = []byte{
		0xc0, 0x53, 0x3b, 0x6e, 0x1a, 0x94, 0x44, 0xb7,
		0xb3, 0xbe, 0x24, 0xf9, 0x84, 0x30, 0xfd, 0x69}
)

// PubKey : Implements bc.PubKey interface
type PubKey struct {
	Pubkey []byte //len=32
}

func init() {
	bencrypt.KeypairTypes[NAME] = func() bc.KeyPair { return new(KeyPair) }
}

// ToB64 : Returns Public Key as a Base64 encoded string
func (e *PubKey) ToB64() string {
	return base64.StdEncoding.EncodeToString(e.Pubkey)
}

// FromB64 : Sets Public Key from a Base64 encoded string
func (e *PubKey) FromB64(s string) error {
	pk, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(pk) != 32 {
		return errors.New("Key array wrong size in PubKey.FromB64")
	}
	e.Pubkey = pk
	return nil
}

// ToBytes : Returns Public Key as bytes
func (e *PubKey) ToBytes() []byte {
	return e.Pubkey
}

// FromBytes : Sets Public Key from bytes
func (e *PubKey) FromBytes(b []byte) error {
	if len(b) != 32 {
		return errors.New("Key array wrong size in PubKey.FromBytes")
	}
	e.Pubkey = b
	return nil
}

// Clone : Returns a new PubKey of the same type as this one
func (e *PubKey) Clone() bc.PubKey {
	return new(PubKey)
}

// KeyPair for ECC : Bencrypt Implementation of a Curve25519,AES-CBC-256,HMAC-SHA-256 system
type KeyPair struct {
	privkey [32]byte //len=32
	pubkey  *PubKey
	//keyHash []byte
}

// GetName : Returns the common language name for this cryptosystem
func (e *KeyPair) GetName() string {
	return NAME
}

// GetPubKey : Returns the Public portion of this KeyPair
func (e *KeyPair) GetPubKey() bc.PubKey {
	return e.pubkey
}

// Precompute : This does nothing in ECC
func (e *KeyPair) Precompute() {
}

// GenerateKey : Generates a new keypair inside this KeyPair object
func (e *KeyPair) GenerateKey() {
	var private [32]byte
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		log.Fatal(err.Error())
	}

	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &private)
	pko := new(PubKey)
	if err := pko.FromBytes(pk[:]); err != nil {
		log.Fatal(err.Error())
	}
	e.pubkey = pko

	copy(e.privkey[:], private[:])
	e.Precompute()
}

// ToB64 : Returns the private portion of this keypair as a Base64-encoded string
func (e *KeyPair) ToB64() string {
	data := append(e.pubkey.ToBytes(), e.privkey[:]...)
	s := base64.StdEncoding.EncodeToString(data)
	return s
}

// FromB64 : Sets the private portion of this keypair from a Base64-encoded string
func (e *KeyPair) FromB64(s string) error {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(dec) != 64 {
		return errors.New("Key array wrong size in B64toPrivateKey")
	}
	pk := new(PubKey)
	err = pk.FromBytes(dec[0:32])
	if err != nil {
		return err
	}
	e.pubkey = pk
	copy(e.privkey[:], dec[32:64])
	e.Precompute()
	return nil
}

/*
EncryptMessage : Encrypts a message
1) generates a random number r in [1, n-1] and calculates R = r G;
2) derives a shared secret: S = P_x, where P = (P_x, P_y) = r K_B (and P ne O);
3) uses KDF to derive a symmetric encryption and a MAC key: k_E | k_M = textrm{KDF}(S|S_1);
4) encrypts the message: c = E(k_E; m);
5) computes luggage tag so recipient can quickly see if this is for them
6) computes the tag of encrypted message and S_2: d = textrm{MAC}(k_M; c | S_2);
7) outputs R | luggageTag | c | d.
*/
func (e *KeyPair) EncryptMessage(clear []byte, pubkey bc.PubKey) ([]byte, error) {
	if pubkey == nil {
		return nil, errors.New("Nil PubKey in EncryptMessage")
	}

	pk := pubkey.ToBytes()

	if len(pk) != 32 {
		return nil, errors.New("Key array wrong size in EncryptMessage")
	}

	//1) generates a random number r \in [1, n-1] and calculates R = r G;
	var private, R, public, sharedKey [32]byte
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		log.Fatal(err.Error())
	}
	curve25519.ScalarBaseMult(&R, &private)

	//2) derives a shared secret: S = P_x, where P = (P_x, P_y) = r K_B (and P \ne O);
	copy(public[:], pk[:])
	curve25519.ScalarMult(&sharedKey, &private, &public)

	//3) uses KDF to derive a symmetric encryption and a MAC keys: k_E \| k_M = \textrm{KDF}(S\|S_1);
	aesKey, err := bc.Kdf(sharedKey[:], aesKeyLabel, nil)
	if err != nil {
		return nil, err
	}
	macKey, err := bc.Kdf(sharedKey[:], macKeyLabel, nil)
	if err != nil {
		return nil, err
	}

	//4) encrypts the message: c = E(k_E; m);
	ciphertext, err := bc.AesEncrypt(clear, aesKey)
	if err != nil {
		return nil, err
	}

	//5) computes luggage tag so recipient can quickly see if this is for them
	luggageTag, err := bc.Kdf(sharedKey[:], luggageKeyLabel, nil)
	if err != nil {
		return nil, err
	}

	//6) computes the tag of encrypted message and S_2: d = \textrm{MAC}(k_M; c \| S_2);
	mac := hmac.New(sha256.New, macKey)
	_, err = mac.Write(R[:])
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(luggageTag[:])
	if err != nil {
		return nil, err
	}
	_, err = mac.Write(ciphertext)
	if err != nil {
		return nil, err
	}
	msgmac := mac.Sum(nil)

	//7) outputs R | luggageTag | c | d.
	out := make([]byte, 32+len(luggageTag)+len(ciphertext)+32)
	copy(out[:], R[:])
	copy(out[32:], luggageTag[:])
	copy(out[32+len(luggageTag):], ciphertext[:])
	copy(out[32+len(luggageTag)+len(ciphertext):], msgmac[:])
	return out, nil
}

/*
DecryptMessage : Decrypts a message
1) derives the shared secret: S = P_x, where P = (P_x, P_y) = k_B R (it is the same as the one Alice derived because P = k_B R = k_B r G = r k_B G = r K_B), or outputs failed if P=O;
2) checks the luggage tag
3) derives keys the same way as Alice did: k_E \| k_M = \textrm{KDF}(S\|S_1);
4) uses MAC to check the tag and outputs failed if d \ne \textrm{MAC}(k_M; c \| S_2);
5) uses symmetric encryption scheme to decrypt the message m = E^{-1}(k_E; c).

Returns:
bool - Luggage Tag check passed
[]byte - decrypted data, if tag check passed
error - what you would expect
*/
func (e *KeyPair) DecryptMessage(data []byte) (bool, []byte, error) {
	//1) derives the shared secret: S = P_x, where P = (P_x, P_y) = k_B R (it is the same as the one Alice derived because P = k_B R = k_B r G = r k_B G = r K_B), or outputs failed if P=O;
	var sharedKey, r [32]byte
	copy(r[:], data[:32])
	curve25519.ScalarMult(&sharedKey, &e.privkey, &r)

	//2) checks the luggage tag
	luggageTag, err := bc.Kdf(sharedKey[:], luggageKeyLabel, nil)
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(luggageTag, data[32:64]) {
		return false, nil, nil
	}

	//3) derives keys the same way as Alice did: k_E \| k_M = \textrm{KDF}(S\|S_1);
	aesKey, err := bc.Kdf(sharedKey[:], aesKeyLabel, nil)
	if err != nil {
		return true, nil, err
	}
	macKey, err := bc.Kdf(sharedKey[:], macKeyLabel, nil)
	if err != nil {
		return true, nil, err
	}

	//4) uses MAC to check the tag and outputs failed if d \ne \textrm{MAC}(k_M; c \| S_2);
	expectedMac := data[len(data)-32:]
	mac := hmac.New(sha256.New, macKey)
	_, err = mac.Write(data[:len(data)-32])
	if err != nil {
		return true, nil, err
	}
	realMac := mac.Sum(nil)
	if !hmac.Equal(realMac, expectedMac) {
		return true, nil, errors.New("HMAC check failed")
	}

	//5) uses symmetric encryption scheme to decrypt the message m = E^{-1}(k_E; c).
	clear, err := bc.AesDecrypt(data[64:len(data)-32], aesKey)
	if err != nil {
		return true, nil, err
	}
	return true, clear, nil
}

// ValidatePubKey : Returns true if and only if the argument is a valid PubKey to this KeyPair
func (e *KeyPair) ValidatePubKey(s string) bool {
	pk := new(PubKey)
	if err := pk.FromB64(s); err != nil || pk.Pubkey == nil || len(pk.Pubkey) != 32 {
		return false
	}
	return true
}

// Clone : Returns a new node of the same type as this one
func (e *KeyPair) Clone() bc.KeyPair {
	return new(KeyPair)
}
