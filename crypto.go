package bencrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ECC_MODE = true // ECC or RSA mode

	//1ef17714-dbbf-4d1c-8869-e8273e2c327a
	aesKeyLabel = []byte{
		0x1e, 0xf1, 0x77, 0x14, 0xdb, 0xbf, 0x4d, 0x1c,
		0x88, 0x69, 0xe8, 0x27, 0x3e, 0x2c, 0x32, 0x7a}

	//1f8fac50-357a-4cfd-b67b-085311534df8
	macKeyLabel = []byte{
		0x1f, 0x8f, 0xac, 0x50, 0x35, 0x7a, 0x4c, 0xfd,
		0xb6, 0x7b, 0x08, 0x53, 0x11, 0x53, 0x4d, 0xf8}
)

func GenerateRandomBytes(count int) ([]byte, error) {
	b := make([]byte, count)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func kdf(key [32]byte, label, salt []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, key[:], salt[:], label)
	derivedKey := make([]byte, 32)
	if n, err := io.ReadFull(hkdf, derivedKey); err != nil || n != len(derivedKey) {
		return nil, errors.New("Failure in Key Derivation")
	}
	return derivedKey, nil
}

func DestHash(pubkey interface{}, salt []byte) ([]byte, error) {
	//	log.Println("DestHash")
	pk, ok := pubkey.([]byte)
	if ok {
		if len(pk) != 32 {
			return nil, errors.New("Key array wrong size.")
		}
		var p [32]byte
		copy(p[:], pk)
		h, err := kdf(p, pk, salt)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	//else {
	//	//*rsa.PublicKey
	//	keybytes, _ := x509.MarshalPKIXPublicKey(destkey)

	//}
	return nil, errors.New("pubkey was not a []byte or *rsa.PublicKey, your code is broken.")
}

func aesEncrypt(clear, aesKey []byte) ([]byte, error) {
	clear, _ = pkcs7Pad(clear, aes.BlockSize)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(clear))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], []byte(clear))
	return ciphertext, nil
}

func aesDecrypt(ciphertext, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	text := ciphertext[aes.BlockSize:]
	cbc := cipher.NewCBCDecrypter(block, iv)
	clear := make([]byte, len(text))
	cbc.CryptBlocks(clear, text)
	clear, _ = pkcs7Unpad(clear, aes.BlockSize)

	return clear, nil
}

type CryptoAPI interface {
	GenerateKey()
	precompute()
	B64fromPrivateKey() string
	B64fromPublicKey(pubkey interface{}) string
	B64toPublicKey(s string) (interface{}, error)
	B64toPrivateKey(s string) error
	EncryptMessage(clear []byte, pubkey interface{}) ([]byte, error)
	DecryptMessage(data []byte) ([]byte, error)

	GetName() string
	GetPubKey() interface{}
}
