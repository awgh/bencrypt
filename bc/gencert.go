// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

// stolen from google sample code
// todo: parameterize pwd/filenames

package bc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	host      = "localhost"
	validFrom = "" //Creation date formatted as Jan 1 15:04:05 2011
	validFor  = 365 * 24 * time.Hour
	isCA      = false
	rsaBits   = 2048
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// InitSSL : Generate you some SSL cert/key, only if the named files don't exist
func InitSSL(certfile string, keyfile string, useECC bool) error {
	haveCert := true
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		haveCert = false
	}
	if _, err := os.Stat(certfile); os.IsNotExist(err) {
		haveCert = false
	}
	if !haveCert {
		err := GenerateSSLCert(certfile, keyfile, useECC)
		if err != nil {
			return err
		}
	}

	return nil
}

// GenerateSSLCert : Generate you some SSL cert/key
func GenerateSSLCert(certfile string, keyfile string, eccMode bool) error {
	certBytes, keyBytes, err := GenerateSSLCertBytes(eccMode)
	if err != nil {
		return fmt.Errorf("error generating cert: %v", err)
	}

	certOut, err := os.Create(certfile)
	defer certOut.Close()
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certfile, err)
	}
	if _, err = certOut.Write(certBytes); err != nil {
		return fmt.Errorf("error writing %s: %v", certfile, err)
	}

	keyOut, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyOut.Close()
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyfile, err)
	}
	if _, err = keyOut.Write(keyBytes); err != nil {
		return fmt.Errorf("error writing %s: %v", keyfile, err)
	}

	return nil
}

// GenerateSSLCertBytes : Generate you some SSL cert/key bytes
func GenerateSSLCertBytes(eccMode bool) ([]byte, []byte, error) {
	var priv interface{}
	var err error
	if eccMode {
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse creation date: %s", err)
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	var certBuf bytes.Buffer
	if err = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("error encoding cert: %v", err)
	}

	var keyBuf bytes.Buffer
	if err = pem.Encode(&keyBuf, pemBlockForKey(priv)); err != nil {
		return nil, nil, fmt.Errorf("error encoding key: %v", err)
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
