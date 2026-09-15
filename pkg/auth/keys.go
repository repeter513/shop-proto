package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func LoadPrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not ed25519 private key")
	}
	return pk, nil
}

func LoadPublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not ed25519 public key")
	}
	return pk, nil
}
