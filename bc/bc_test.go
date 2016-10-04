package bc

import "testing"

func Test_Pkcs7Pad_1(t *testing.T) {
	a := make([]byte, 14)
	b := make([]byte, 16) // aes.BlockSize == 16
	c := make([]byte, 250)

	a, _ = Pkcs7Pad(a, 16)
	b, _ = Pkcs7Pad(a, 16)
	c, _ = Pkcs7Pad(a, 16)

	if len(a) != 16 {
		t.Error("Pkcs7Pad did not pad")
	}
	if len(b) != 32 {
		t.Error("Pkcs7Pad padded incorrectly")
	}
	if len(c)%16 != 0 {
		t.Error("Pkcs7Pad padded incorrectly on mult>1")
	}

	t.Log("Pkcs7Pad tests passed")
}
