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

type UnsupportedAlgorithmPairError struct {
	HashAlgo      string
	SignatureAlgo string
}

func (e UnsupportedAlgorithmPairError) Error() string {
	return "unsupported algorithm pair: " + e.HashAlgo + "/" + e.SignatureAlgo
}

// CompositeKey defines a hash and signature algorithm combination.
type CompositeKey struct {
	HashAlgo      string
	SignatureAlgo string
}

// SignatureHashAlgorithm contains the hash function and the universal verify function.
type SignatureHashAlgorithm struct {
	Hash   func() hash.Hash
	Verify func(publicKey interface{}, hash []byte, signature []byte) error
}

// General verification function to reduce boilerplate.
func generalVerify(publicKey interface{}, hash []byte, signature []byte, algo CompositeKey) error {
	switch algo.SignatureAlgo {
	case "RSA":
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid public key type for RSA")
		}
		return rsa.VerifyPKCS1v15(rsaKey, getCryptoHash(algo.HashAlgo), hash, signature)
	case "RSA-PSS":
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid public key type for RSA")
		}
		return rsa.VerifyPSS(rsaKey, getCryptoHash(algo.HashAlgo), hash, signature, nil)
	case "ECDSA":
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid public key type for ECDSA")
		}
		if !ecdsa.VerifyASN1(ecdsaKey, hash, signature) {
			return errors.New("ECDSA verification failed")
		}
	default:
		return errors.New("unsupported signature algorithm")
	}
	return nil
}

// SupportedSignatureHashAlgorithms is a map with CompositeKey as the key.
var SupportedSignatureHashAlgorithms = map[CompositeKey]SignatureHashAlgorithm{
	{HashAlgo: "SHA1", SignatureAlgo: "RSA"}: {
		Hash: sha1.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			return generalVerify(publicKey, hash, signature, CompositeKey{HashAlgo: "SHA1", SignatureAlgo: "RSA"})
		},
	},
	{HashAlgo: "SHA256", SignatureAlgo: "RSA"}: {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			return generalVerify(publicKey, hash, signature, CompositeKey{HashAlgo: "SHA256", SignatureAlgo: "RSA"})
		},
	},
	{HashAlgo: "SHA256", SignatureAlgo: "ECDSA"}: {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			return generalVerify(publicKey, hash, signature, CompositeKey{HashAlgo: "SHA256", SignatureAlgo: "ECDSA"})
		},
	},
	{HashAlgo: "SHA384", SignatureAlgo: "ECDSA"}: {
		Hash: sha512.New384,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			return generalVerify(publicKey, hash, signature, CompositeKey{HashAlgo: "SHA384", SignatureAlgo: "ECDSA"})
		},
	},
	{HashAlgo: "SHA256", SignatureAlgo: "RSA-PSS"}: {
		Hash: sha256.New,
		Verify: func(publicKey interface{}, hash []byte, signature []byte) error {
			return generalVerify(publicKey, hash, signature, CompositeKey{HashAlgo: "SHA256", SignatureAlgo: "RSA-PSS"})
		},
	},
}

// getCryptoHash maps string-based hash names to crypto.Hash values.
func getCryptoHash(hashAlgo string) crypto.Hash {
	switch hashAlgo {
	case "SHA1":
		return crypto.SHA1
	case "SHA256":
		return crypto.SHA256
	case "SHA384":
		return crypto.SHA384
	default:
		return 0 // Unsupported hash algorithm
	}
}
