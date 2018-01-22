package bc

// KeyPair : Interface to implement to make a bencrypt-compatable cryptosystem
type KeyPair interface {
	GenerateKey()
	Precompute()

	ToB64() string
	FromB64(s string) error

	EncryptMessage(clear []byte, pubkey PubKey) ([]byte, error)
	DecryptMessage(data []byte) (bool, []byte, error)

	GetName() string
	GetPubKey() PubKey

	ValidatePubKey(s string) bool

	Clone() KeyPair
}

// PubKey : Interface to implement to make a bencrypt-compatable Public Key
type PubKey interface {
	ToB64() string
	FromB64(s string) error

	ToBytes() []byte
	FromBytes([]byte) error

	Clone() PubKey
}
