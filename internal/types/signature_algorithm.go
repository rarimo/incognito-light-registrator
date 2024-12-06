package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"hash"

	"github.com/rarimo/passport-identity-provider/internal/algorithms"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type ErrInvalidPublicKey struct {
	Expected SignatureAlgorithm
}

func (e ErrInvalidPublicKey) Error() string {
	return "invalid public key type for " + e.Expected.String()
}

// CompositeAlgorithmKey defines a hash and signature algorithm combination.
type CompositeAlgorithmKey struct {
	HashAlgorithm
	SignatureAlgorithm
}

func GeneralVerify(publicKey interface{}, hash []byte, signature []byte, algo CompositeAlgorithmKey) error {
	switch algo.SignatureAlgorithm {
	case RSA:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPKCS1v15(rsaKey, getCryptoHash(algo.HashAlgorithm), hash, signature)
	case RSAPSS:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPSS(rsaKey, getCryptoHash(algo.HashAlgorithm), hash, signature, nil)
	case ECDSA:
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		if !ecdsa.VerifyASN1(ecdsaKey, hash, signature) {
			return errors.New("ECDSA verification failed")
		}
	case Brainpool:
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}

		if err := algorithms.VerifyBrainpool(hash, signature, ecdsaKey); err != nil {
			return errors.Wrap(err, "failed to verify brainpool signature")
		}
	default:
		return errors.New("unsupported signature algorithm")
	}
	return nil
}

func GeneralHash(algorithm HashAlgorithm) hash.Hash {
	switch algorithm {
	case SHA1:
		return crypto.SHA1.New()
	case SHA256:
		return crypto.SHA256.New()
	case SHA384:
		return crypto.SHA384.New()
	case SHA512:
		return crypto.SHA512.New()
	default:
		return nil
	}
}

// getCryptoHash maps string-based hash names to crypto.Hash values.
func getCryptoHash(hashAlgorithm HashAlgorithm) crypto.Hash {
	switch hashAlgorithm {
	case SHA1:
		return crypto.SHA1
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512
	default:
		return 0
	}
}
