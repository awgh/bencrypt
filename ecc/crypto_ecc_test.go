package ecc

import (
	"bytes"
	"testing"

	"github.com/awgh/bencrypt/bc"
)

var (
	eccCrypt bc.KeyPair = new(KeyPair)
)

func Test_B64PublicKey_ECC(t *testing.T) {
	pubkey := new(PubKey)
	if err := pubkey.FromB64(pubkeyb64Ecc); err != nil {
		t.Error(err.Error())
	}
	b64 := pubkey.ToB64()
	if pubkeyb64Ecc != b64 {
		t.Error("base64 public key conversion test failed")
	} else {
		t.Log("base64 public key conversion test passed")
	}
}

func Test_B64PrivateKey_ECC(t *testing.T) {
	err := eccCrypt.FromB64(pubprivkeyb64Ecc)
	if err != nil {
		t.Error(err.Error())
	}
	b64 := eccCrypt.ToB64()
	if pubprivkeyb64Ecc != b64 {
		t.Error("base64 private key conversion test failed")
	} else {
		t.Log("base64 private key conversion test passed")
	}
}

func Test_GenerateKeys_ECC(t *testing.T) {
	// save old key so other tests don't break
	oldkey := eccCrypt.ToB64()

	eccCrypt.GenerateKey()
	t.Log("b64 pubpriv: " + eccCrypt.ToB64())
	pubkey := eccCrypt.GetPubKey()
	b64 := pubkey.ToB64()
	t.Log(b64)

	// restore old key
	eccCrypt.FromB64(oldkey)
}

func Test_EncryptDecrypt_ECC(t *testing.T) {
	cleartext, err := bc.GenerateRandomBytes(151)
	if err != nil {
		t.Error(err.Error())
	}
	pubkey := new(PubKey)
	if err := pubkey.FromB64(pubkeyb64Ecc); err != nil {
		t.Error(err.Error())
	}
	ciphertext, err := eccCrypt.EncryptMessage(cleartext, pubkey)
	if err != nil {
		t.Error(err.Error())
	}
	recovered, err := eccCrypt.DecryptMessage(ciphertext)
	if err != nil {
		t.Error(err.Error())
	}

	//if len(cleartext) != len(recovered) {
	//	t.Error("encrypt decrypt lost the length")
	//}

	if bytes.Equal(cleartext, recovered[:len(cleartext)]) {
		t.Log("encrypt decrypt test passed")
	} else {
		t.Error("encrypt decrypt test failed")
	}
}

// ECC TEST KEYS
var pubprivkeyb64Ecc = "Tcksa18txiwMEocq7NXdeMwz6PPBD+nxCjb/WCtxq1+dln3M3IaOmg+YfTIbBpk+jIbZZZiT+4CoeFzaJGEWmg=="
var pubkeyb64Ecc = "Tcksa18txiwMEocq7NXdeMwz6PPBD+nxCjb/WCtxq18="
var privkeyb64Ecc = "nZZ9zNyGjpoPmH0yGwaZPoyG2WWYk/uAqHhc2iRhFpo="
