package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

type SignatureAlgorithm struct {
	Hash   func() hash.Hash
	Verify func(publicKey interface{}, hash []byte, signature []byte) error
}

var SupportedSignatureAlgorithms = map[string]SignatureAlgorithm{
	"SHA1withRSA": {
		Hash: sha1.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			rsaKey, ok := publicKey.(*rsa.PublicKey)
			if !ok {
				return errors.New("invalid public key type for RSA")
			}
			return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA1, hash, signature)
		},
	},
	"SHA256withRSA": {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			rsaKey, ok := publicKey.(*rsa.PublicKey)
			if !ok {
				return errors.New("invalid public key type for RSA")
			}
			return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash, signature)
		},
	},
	"SHA256withECDSA": {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("invalid public key type for ECDSA")
			}
			if !ecdsa.VerifyASN1(ecdsaKey, hash, signature) {
				return errors.New("ECDSA verification failed")
			}
			return nil
		},
	},
	"SHA384withECDSA": {
		Hash: sha512.New384,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("invalid public key type for ECDSA")
			}
			if !ecdsa.VerifyASN1(ecdsaKey, hash, signature) {
				return errors.New("ECDSA verification failed")
			}
			return nil
		},
	},
	"SHA256withRSA-PSS": {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			rsaKey, ok := publicKey.(*rsa.PublicKey)
			if !ok {
				return errors.New("invalid public key type for RSA")
			}
			return rsa.VerifyPSS(rsaKey, crypto.SHA256, hash, signature, nil)
		},
	},
}
