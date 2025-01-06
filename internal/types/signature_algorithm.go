package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"

	"gitlab.com/distributed_lab/logan/v3/errors"
)

type ErrInvalidPublicKey struct {
	Expected SignatureAlgorithm
}

func (e ErrInvalidPublicKey) Error() string {
	return "invalid public key type for " + e.Expected.String()
}

// AlgorithmPair defines a hash and signature algorithm combination.
type AlgorithmPair struct {
	DgHashAlgorithm        HashAlgorithm
	SignedAttrHashAlg      HashAlgorithm
	SignatureDigestHashAlg HashAlgorithm
	SignatureAlgorithm
}

func GeneralVerify(publicKey interface{}, hash []byte, signature []byte, algo AlgorithmPair) error {
	switch algo.SignatureAlgorithm {
	case RSA:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPKCS1v15(rsaKey, getCryptoHash(algo.SignedAttrHashAlg), hash, signature)
	case RSAPSS:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return rsa.VerifyPSS(rsaKey, getCryptoHash(algo.SignedAttrHashAlg), hash, signature, nil)
	case ECDSA:
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey{Expected: algo.SignatureAlgorithm}
		}
		return verifyECDSA(hash, signature, ecdsaKey)
	default:
		return errors.New("unsupported signature algorithm")
	}
}

func verifyECDSA(data, sig []byte, publicKey *ecdsa.PublicKey) error {
	lenToIndex := map[int]int{
		28:  14,
		32:  16,
		48:  24,
		56:  28,
		64:  32,
		96:  48,
		132: 66,
	}

	// Handle raw (r || s) signature format
	index, isLenSupported := lenToIndex[len(sig)]
	if isLenSupported {
		r := new(big.Int).SetBytes(sig[:index])
		s := new(big.Int).SetBytes(sig[index:])
		if ecdsa.Verify(publicKey, data, r, s) {
			return nil
		}
	}

	// Handle ASN.1 DER signature format
	if ecdsa.VerifyASN1(publicKey, data, sig) {
		return nil
	}

	if !isLenSupported {
		return fmt.Errorf(
			"unexpected ECDSA signature length, got %d bytes for %s curve",
			len(sig),
			publicKey.Curve.Params().Name,
		)
	}

	return errors.New("failed to verify ECDSA signature")
}

func GeneralHash(algorithm HashAlgorithm) hash.Hash {
	switch algorithm {
	case SHA1:
		return crypto.SHA1.New()
	case SHA224:
		return crypto.SHA224.New()
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
	case SHA224:
		return crypto.SHA224
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
