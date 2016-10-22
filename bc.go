package bencrypt

import "github.com/awgh/bencrypt/bc"

var (
	// KeypairTypes : Registry of available Keypair types by name
	KeypairTypes map[string]func() bc.KeyPair
)

func init() {
	KeypairTypes = make(map[string]func() bc.KeyPair)
}
