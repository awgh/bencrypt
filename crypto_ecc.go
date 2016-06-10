package bencrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"

	"golang.org/x/crypto/curve25519"
)

type ECC struct {
	privkey [32]byte //len=32
	pubkey  [32]byte //len=32
	keyHash []byte
}

func (e *ECC) GetName() string {
	return "Curve25519,AES-CBC-256,HMAC-SHA-256"
}

func (e *ECC) GetPubKey() interface{} {
	return e.pubkey[:]
}

func (e *ECC) precompute() {
}

func (e *ECC) GenerateKey() {
	var private [32]byte
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		log.Fatal(err.Error())
	}
	curve25519.ScalarBaseMult(&e.pubkey, &private)
	copy(e.privkey[:], private[:])
	e.precompute()
}

func (e *ECC) B64fromPrivateKey() string {
	data := append(e.pubkey[:], e.privkey[:]...)
	s := base64.StdEncoding.EncodeToString(data)
	return s
}

// Expecting base64-encoded single string containing public+private key
func (e *ECC) B64toPrivateKey(s string) error {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(dec) != 64 {
		return errors.New("Key array wrong size in B64toPrivateKey.")
	}
	copy(e.pubkey[:], dec[0:32])
	copy(e.privkey[:], dec[32:64])

	e.precompute()
	return nil
}

func (e *ECC) B64fromPublicKey(pubkey interface{}) string {
	//	log.Println("B64FromPublicKey")
	pk, ok := pubkey.([]byte)
	if ok {
		if len(pk) != 32 {
			log.Fatal("Key array wrong size in B64fromPublicKey. ", len(pk))
		}
		return base64.StdEncoding.EncodeToString(pk)
	}
	log.Fatal("pubkey was not a []byte, your code is broken.")
	return ""
}

// Expecting base64-encoded single string containing public key
func (e *ECC) B64toPublicKey(s string) (interface{}, error) {
	pubkey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(pubkey) != 32 {
		return nil, errors.New("Key array wrong size in B64toPublicKey. ")
	}
	return pubkey[:], nil
}

/*
1) generates a random number r \in [1, n-1] and calculates R = r G;
2) derives a shared secret: S = P_x, where P = (P_x, P_y) = r K_B (and P \ne O);
3) uses KDF to derive a symmetric encryption and a MAC keys: k_E \| k_M = \textrm{KDF}(S\|S_1);
4) encrypts the message: c = E(k_E; m);
5) computes the tag of encrypted message and S_2: d = \textrm{MAC}(k_M; c \| S_2);
6) outputs R \| c \| d.
*/
func (e *ECC) EncryptMessage(clear []byte, pubkey interface{}) ([]byte, error) {
	pk, ok := pubkey.([]byte)
	if ok {
		if len(pk) != 32 {
			return nil, errors.New("Key array wrong size in EncryptMessage.")
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
		aesKey, err := kdf(sharedKey, aesKeyLabel, nil)
		if err != nil {
			return nil, err
		}
		macKey, err := kdf(sharedKey, macKeyLabel, nil)
		if err != nil {
			return nil, err
		}

		//4) encrypts the message: c = E(k_E; m);
		ciphertext, err := aesEncrypt(clear, aesKey)
		if err != nil {
			return nil, err
		}
		//5) computes the tag of encrypted message and S_2: d = \textrm{MAC}(k_M; c \| S_2);
		mac := hmac.New(sha256.New, macKey)
		mac.Write(ciphertext)
		msgmac := mac.Sum(nil)

		//6) outputs R \| c \| d.
		out := make([]byte, 32+len(ciphertext)+32)
		copy(out[:], R[:])
		copy(out[32:], ciphertext[:])
		copy(out[32+len(ciphertext):], msgmac[:])
		return out, nil
	}
	return nil, errors.New("pubkey was not a []byte, your code is broken.")
}

/*
1) derives the shared secret: S = P_x, where P = (P_x, P_y) = k_B R (it is the same as the one Alice derived because P = k_B R = k_B r G = r k_B G = r K_B), or outputs failed if P=O;
2) derives keys the same way as Alice did: k_E \| k_M = \textrm{KDF}(S\|S_1);
3) uses MAC to check the tag and outputs failed if d \ne \textrm{MAC}(k_M; c \| S_2);
4) uses symmetric encryption scheme to decrypt the message m = E^{-1}(k_E; c).
*/
func (e *ECC) DecryptMessage(data []byte) ([]byte, error) {
	//1) derives the shared secret: S = P_x, where P = (P_x, P_y) = k_B R (it is the same as the one Alice derived because P = k_B R = k_B r G = r k_B G = r K_B), or outputs failed if P=O;
	var sharedKey, r [32]byte
	copy(r[:], data[:32])
	curve25519.ScalarMult(&sharedKey, &e.privkey, &r)

	//2) derives keys the same way as Alice did: k_E \| k_M = \textrm{KDF}(S\|S_1);
	aesKey, err := kdf(sharedKey, aesKeyLabel, nil)
	if err != nil {
		return nil, err
	}
	macKey, err := kdf(sharedKey, macKeyLabel, nil)
	if err != nil {
		return nil, err
	}

	//3) uses MAC to check the tag and outputs failed if d \ne \textrm{MAC}(k_M; c \| S_2);
	expectedMac := data[len(data)-32:]
	mac := hmac.New(sha256.New, macKey)
	mac.Write(data[32 : len(data)-32])
	realMac := mac.Sum(nil)
	if !hmac.Equal(realMac, expectedMac) {
		return nil, errors.New("HMAC check failed.")
	}

	//4) uses symmetric encryption scheme to decrypt the message m = E^{-1}(k_E; c).
	clear, err := aesDecrypt(data[32:len(data)-32], aesKey)
	if err != nil {
		return nil, err
	}
	return clear, nil
}
