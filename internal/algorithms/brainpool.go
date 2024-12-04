package algorithms

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func VerifyBrainpool(data, sig []byte, publicKey *ecdsa.PublicKey) error {
	var esig ECDSASignature
	_, err := asn1.Unmarshal(sig, &esig)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if ok := ecdsa.Verify(publicKey, hash[:], esig.R, esig.S); !ok {
		return err
	}

	return nil
}
