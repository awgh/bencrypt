package bc

import (
	"os"
	"testing"

	"github.com/rainycape/vfs"
)

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

func testOpenedVFS(t *testing.T, fs vfs.VFS) {
	data1, err := vfs.ReadFile(fs, "a/b/c/d")
	if err != nil {
		t.Fatal(err)
	}
	if string(data1) != "go" {
		t.Errorf("expecting a/b/c/d to contain \"go\", it contains %q instead", string(data1))
	}
	data2, err := vfs.ReadFile(fs, "empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(data2) > 0 {
		t.Error("non-empty empty file")
	}
}

func Test_RoundTrip_1(t *testing.T) {

	aesKey, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile("fs.zip", "fs_test.aes", aesKey); err != nil {
		t.Fatal(err)
	}
	fs, err := OpenAndDecrypt("fs_test.aes", ".zip", aesKey)
	if err != nil {
		t.Fatal(err)
	}
	testOpenedVFS(t, fs)

	aesKey2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAndEncrypt(fs, "fs_test2.aes", ".tar.gz", aesKey2); err != nil {
		t.Fatal(err)
	}
	fs2, err := OpenAndDecrypt("fs_test2.aes", ".tar.gz", aesKey2)
	if err != nil {
		t.Fatal(err)
	}
	testOpenedVFS(t, fs2)

	os.Remove("fs_test.aes")
	os.Remove("fs_test2.aes")
}
