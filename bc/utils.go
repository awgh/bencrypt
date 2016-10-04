package bc

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

// GenerateRandomBytes : Generates as many random bytes as you ask for, returns them as []byte
func GenerateRandomBytes(count int) ([]byte, error) {
	b := make([]byte, count)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Pkcs7Pad : Appends padding, PKCS-7 style
func Pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
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

// Pkcs7Unpad : Returns slice of the original data without padding.
func Pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
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

// Kdf : Key derivation function
func Kdf(key []byte, label, salt []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, key[:], salt[:], label)
	derivedKey := make([]byte, 32)
	if n, err := io.ReadFull(hkdf, derivedKey); err != nil || n != len(derivedKey) {
		return nil, errors.New("Failure in Key Derivation")
	}
	return derivedKey, nil
}

// DestHash : Makes a hash out of a destination PubKey and a salt
func DestHash(pubkey PubKey, salt []byte) ([]byte, error) {
	pk := pubkey.ToBytes()

	h, err := Kdf(pk, pk, salt)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// AesEncrypt : Encrypt some bytes with a given key using AES-CBC-aes.BlockSize
func AesEncrypt(clear, aesKey []byte) ([]byte, error) {
	clear, _ = Pkcs7Pad(clear, aes.BlockSize)
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

// AesDecrypt : Decrypt some bytes with a given key using AES-CBC-aes.BlockSize
func AesDecrypt(ciphertext, aesKey []byte) ([]byte, error) {
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
	clear, _ = Pkcs7Unpad(clear, aes.BlockSize)

	return clear, nil
}
