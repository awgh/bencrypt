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
	"io/ioutil"
	"os"

	"golang.org/x/crypto/hkdf"

	"github.com/rainycape/vfs"
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

// OpenAndDecrypt returns an in-memory VFS initialized with the contents
// of the given filename, which will be decrypted with the given AES key,
//  and which must have one of the following fileTypes:
//
//  - .zip
//  - .tar
//  - .tar.gz
//  - .tar.bz2
func OpenAndDecrypt(filename string, fileType string, aesKey []byte) (vfs.VFS, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	clear, err := AesDecrypt(b, aesKey)
	if err != nil {
		return nil, err
	}
	bb := bytes.NewBuffer(clear)
	switch fileType {
	case ".zip":
		return vfs.Zip(bb, int64(bb.Len()))
	case ".tar":
		return vfs.Tar(bb)
	case ".tar.gz":
		return vfs.TarGzip(bb)
	case ".tar.bz2":
		return vfs.TarBzip2(bb)
	}
	return nil, fmt.Errorf("can't open a VFS from a %s file", fileType)
}

// SaveAndEncrypt converts the given VFS to the given archive type,
// and then encrypts the archive with the given AES key.
// Supported fileTypes:
//
//  - .zip
//  - .tar
//  - .tar.gz
//  TODO: NOT SUPPORTED - .tar.bz2
func SaveAndEncrypt(fs vfs.VFS, outfile string, fileType string, aesKey []byte) error {
	bb := bytes.NewBuffer(nil)
	switch fileType {
	case ".zip":
		if err := vfs.WriteZip(bb, fs); err != nil {
			return err
		}
	case ".tar":
		if err := vfs.WriteTar(bb, fs); err != nil {
			return err
		}
	case ".tar.gz":
		if err := vfs.WriteTarGzip(bb, fs); err != nil {
			return err
		}
	default:
		return fmt.Errorf("can't write a VFS to a %s file", fileType)
	}
	cipher, err := AesEncrypt(bb.Bytes(), aesKey)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(outfile, cipher, 0600); err != nil {
		return err
	}
	return nil
}

// EncryptFile will encrypt clearfile with aesKey and save it to outfile
func EncryptFile(clearfile string, outfile string, aesKey []byte) error {
	f, err := os.Open(clearfile)
	if err != nil {
		return err
	}
	defer f.Close()
	clear, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	cipher, err := AesEncrypt(clear, aesKey)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(outfile, cipher, 0600); err != nil {
		return err
	}
	return nil
}
