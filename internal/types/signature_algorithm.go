package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"hash"
)

type ErrInvalidPublicKey struct {
	Expected string
}

func (e ErrInvalidPublicKey) Error() string {
	return "invalid public key type for " + e.Expected
}

// CompositeAlgorithmKey defines a hash and signature algorithm combination.
type CompositeAlgorithmKey struct {
	HashAlgorithm      string
	SignatureAlgorithm string
}

func GeneralVerify(publicKey interface{}, hash []byte, signature []byte, algo CompositeAlgorithmKey) error {
	switch algo.SignatureAlgorithm {
	case RSA.String():
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPKCS1v15(rsaKey, getCryptoHash(algo.HashAlgorithm), hash, signature)
	case RSAPSS.String():
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPSS(rsaKey, getCryptoHash(algo.HashAlgorithm), hash, signature, nil)
	case ECDSA.String():
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		if !ecdsa.VerifyASN1(ecdsaKey, hash, signature) {
			return errors.New("ECDSA verification failed")
		}
	default:
		return errors.New("unsupported signature algorithm")
	}
	return nil
}

func GeneralHash(algorithm string) hash.Hash {
	switch algorithm {
	case SHA1.String():
		return crypto.SHA1.New()
	case SHA256.String():
		return crypto.SHA256.New()
	case SHA384.String():
		return crypto.SHA384.New()
	case SHA512.String():
		return crypto.SHA512.New()
	default:
		return nil
	}
}

// getCryptoHash maps string-based hash names to crypto.Hash values.
func getCryptoHash(hashAlgorithm string) crypto.Hash {
	switch hashAlgorithm {
	case SHA1.String():
		return crypto.SHA1
	case SHA256.String():
		return crypto.SHA256
	case SHA384.String():
		return crypto.SHA384
	case SHA512.String():
		return crypto.SHA512
	default:
		return 0
	}
}
