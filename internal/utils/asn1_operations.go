package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func ExtractFirstNBits(data []byte, n uint) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}

	numBytes := (n + 7) / 8

	if uint(len(data))*8 < n {
		return nil, fmt.Errorf("not enough bits in data: required %d, available %d", n, len(data)*8)
	}

	result := make([]byte, numBytes)

	copy(result, data[:numBytes])

	remainingBits := n % 8
	if remainingBits != 0 {
		mask := byte(0xFF << (8 - remainingBits))
		result[numBytes-1] &= mask
	}

	return result, nil
}

func GetDataGroup(encapsulatedContent []byte, tag int) ([]byte, error) {
	var encapsulatedData types.EncapsulatedData
	if _, err := asn1.Unmarshal(encapsulatedContent, &encapsulatedData); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal encapsulated data")
	}

	// In some cases data groups sequence is not sorted, so we need to iterate over all elements to find the one with the correct tag
	for _, key := range encapsulatedData.PrivateKey {
		if key.Integer == tag {
			return key.OctetStr, nil
		}
	}

	return nil, nil
}

func TruncateHexPrefix(hexString *string) *string {
	if hexString == nil || *hexString == "0x" || *hexString == "" {
		return nil
	}

	if strings.HasPrefix(*hexString, "0x") && len(*hexString) > 2 {
		trimmed := (*hexString)[2:]
		return &trimmed
	}

	return hexString
}

func BuildSignedData(
		contract, verifier *common.Address,
		passportHash, dg1Commitment, publicKey [32]byte,
) ([]byte, error) {
	return abiEncodePacked(types.RegistrationSimplePrefix, contract, passportHash[:], dg1Commitment[:], publicKey[:], verifier)
}

func ExtractPublicKey(dg15 []byte) (interface{}, [32]byte, error) {
	var zeroHash [32]byte
	if len(dg15) == 0 {
		return nil, zeroHash, nil
	}

	pub, err := generalPublicKeyExtraction(dg15)
	if err != nil {
		return nil, zeroHash, err
	}

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		// ECDSA Key:
		// pubKey = Poseidon2(x mod 2^248, y mod 2^248)
		modulus := new(big.Int).Lsh(big.NewInt(1), 248) // 2^248

		xMod := new(big.Int).Mod(k.X, modulus)
		yMod := new(big.Int).Mod(k.Y, modulus)

		h, err := poseidon.Hash([]*big.Int{xMod, yMod})
		if err != nil {
			return k, zeroHash, err
		}
		return k, bigIntTo32Bytes(h), nil
	case *rsa.PublicKey:
		// RSA Key:
		// pubKey = Poseidon5(200bit, 200bit, 200bit, 200bit, 224bit) = 1024 bits total
		N := k.N
		bitLen := N.BitLen()
		requiredBits := 200*4 + 224 // = 1024 bits total

		if bitLen < requiredBits {
			return k, zeroHash, errors.New("RSA modulus too small to extract required bits")
		}

		// Extract the top 1024 bits
		shift := bitLen - requiredBits
		topBits := new(big.Int).Rsh(N, uint(shift))

		// Split into chunks: 4 chunks of 200 bits + 1 chunk of 224 bits
		chunkSizes := []int{200, 200, 200, 200, 224}
		chunks := make([]*big.Int, len(chunkSizes))

		current := new(big.Int).Set(topBits)
		for i, size := range chunkSizes {
			mask := new(big.Int).Lsh(big.NewInt(1), uint(size))
			mask.Sub(mask, big.NewInt(1)) // mask = 2^size - 1

			chunk := new(big.Int).And(current, mask)
			chunks[len(chunkSizes)-1-i] = chunk // Fill in reverse order
			current.Rsh(current, uint(size))
		}

		h, err := poseidon.Hash(chunks)
		if err != nil {
			return k, zeroHash, err
		}
		return k, bigIntTo32Bytes(h), nil
	default:
		return nil, zeroHash, nil
	}
}

func ToEthSignedMessageHash(data []byte) []byte {
	prefix := []byte(types.EthSignedMessagePrefix)
	return crypto.Keccak256(append(prefix, data...))
}

func TruncateDg1Hash(dg1Hash []byte) (dg1Truncated [32]byte) {
	truncateStart := 32 - len(dg1Hash)
	dg1HashStart := 0
	if len(dg1Hash) > types.DG1TruncateLength {
		dg1HashStart = len(dg1Hash) - types.DG1TruncateLength
		truncateStart = 1
	}

	copy(dg1Truncated[truncateStart:], dg1Hash[dg1HashStart:])
	return dg1Truncated
}

func ReverseBits(input []byte) []byte {
	n := len(input)
	output := make([]byte, n)

	for i := 0; i < n; i++ {
		output[i] = reverseByte(input[i])
	}

	for i := 0; i < n/2; i++ {
		output[i], output[n-1-i] = output[n-1-i], output[i]
	}

	return output
}

func reverseByte(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func generalPublicKeyExtraction(dg15 []byte) (any, error) {
	var rawDg15 asn1.RawValue
	if _, err := asn1.Unmarshal(dg15, &rawDg15); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal ASN.1")
	}

	fixedDg15, err := fixRSAPublicKeyEncoding(rawDg15.Bytes)
	if err != nil {
		// If RSA key encoding failed, try ECDSA
		return extractEcPublicKey(dg15)
	}

	return x509.ParsePKIXPublicKey(fixedDg15)
}

func extractEcPublicKey(dg15 []byte) (*ecdsa.PublicKey, error) {
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(dg15, &raw)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal ASN.1")
	}

	var publicKey types.ECPublicKey
	_, err = asn1.Unmarshal(raw.Bytes, &publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal public key structure")
	}

	pointBytes := publicKey.PublicKey.Bytes
	if len(pointBytes) == 0 {
		return nil, errors.New("no point data found in the public key")
	}

	if pointBytes[0] != 0x04 {
		return nil, errors.New("only uncompressed points are supported")
	}

	x := new(big.Int).SetBytes(pointBytes[1:33])
	y := new(big.Int).SetBytes(pointBytes[33:])

	pubKey := &ecdsa.PublicKey{
		X: x,
		Y: y,
	}

	return pubKey, nil
}

func bigIntTo32Bytes(num *big.Int) [32]byte {
	var out [32]byte
	if num == nil {
		return out
	}
	numBytes := num.Bytes()
	if len(numBytes) > 32 {
		// If somehow it's larger, truncate the leftmost numBytes
		numBytes = numBytes[len(numBytes)-32:]
	}
	// Left pad with zeros
	copy(out[32-len(numBytes):], numBytes)
	return out
}

// fixExponentEncoding attempts to fix the exponent encoding by parsing the public key structure and re-encoding it.
// It expects a structure like SubjectPublicKeyInfo -> AlgorithmIdentifier + BIT STRING (with the key).
// Inside the BIT STRING for RSA or ECDSA public keys, we expect a SEQUENCE { INTEGER n, INTEGER e } for RSA.
// We will try to decode and then re-encode the exponent with minimal encoding.
func fixExponentEncoding(derBytes []byte) ([]byte, error) {
	// SubjectPublicKeyInfo ::= SEQUENCE {
	//     algorithm AlgorithmIdentifier,
	//     subjectPublicKey BIT STRING
	// }
	var spki struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return nil, err
	}

	// Inside subjectPublicKey (bit string), we expect something like RSAPublicKey for RSA:
	// RSAPublicKey ::= SEQUENCE {
	//     modulus INTEGER,       -- n
	//     publicExponent INTEGER -- e
	// }
	var rsaPub struct {
		Modulus        asn1.RawValue
		PublicExponent asn1.RawValue
	}

	// The subjectPublicKey is a BIT STRING containing the key data. The key data itself is ASN.1 DER.
	rsaKeyData := spki.SubjectPublicKey.Bytes
	_, err = asn1.Unmarshal(rsaKeyData, &rsaPub)
	if err != nil {
		return nil, err
	}

	// Try to parse the publicExponent from rsaPub.PublicExponent
	var exponentBytes []byte
	if rsaPub.PublicExponent.Tag == asn1.TagInteger && rsaPub.PublicExponent.Class == asn1.ClassUniversal {
		exponentBytes = rsaPub.PublicExponent.Bytes
	} else {
		return nil, errors.New("public exponent not an integer")
	}

	// If the exponent is already minimal, no need to fix.
	// A minimal positive integer encoding in ASN.1:
	// - Must not have leading unnecessary zeros.
	// We'll remove leading zeros and ensure at least one byte remains.
	fixedExponent := stripLeadingZeros(exponentBytes)
	if len(fixedExponent) == 0 {
		// Should never happen unless exponent was all zeros, fallback to 0x01 or error
		fixedExponent = []byte{0x01}
	}

	// If no change is needed, just return.
	if len(fixedExponent) == len(exponentBytes) && bytes.Equal(fixedExponent, exponentBytes) {
		return derBytes, nil
	}

	// Re-encode with fixed exponent
	rsaPub.PublicExponent.FullBytes = nil // Clear so we rely on Bytes
	rsaPub.PublicExponent.Bytes = fixedExponent

	// Re-marshal the RSA key
	newRsaKeyData, err := asn1.Marshal(rsaPub)
	if err != nil {
		return nil, err
	}

	// Re-marshal the whole SPKI
	spki.SubjectPublicKey = asn1.BitString{Bytes: newRsaKeyData, BitLength: len(newRsaKeyData) * 8}
	newDer, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}

	return newDer, nil
}

// stripLeadingZeros removes leading 0x00 bytes from a positive integer representation.
// It leaves at least one byte remaining.
func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0x00 {
		i++
	}
	return b[i:]
}

// fixRSAPublicKeyEncoding tries to parse a public key DER. If it fails due to encoding issues,
// it attempts to fix and re-parse.
func fixRSAPublicKeyEncoding(der []byte) ([]byte, error) {
	_, err := x509.ParsePKIXPublicKey(der)
	if err == nil {
		// Already OK
		return der, nil
	}

	// Try fixing exponent encoding
	newDer, fixErr := fixExponentEncoding(der)
	if fixErr != nil {
		return nil, errors.Wrap(fixErr, "failed to fix exponent encoding")
	}

	// Validate that the new DER is parseable
	_, err = x509.ParsePKIXPublicKey(newDer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse after fix")
	}

	return newDer, nil
}

func abiEncodePacked(args ...interface{}) ([]byte, error) {
	encoded := make([]byte, 0)
	for _, arg := range args {
		switch val := arg.(type) {
		case string:
			encoded = append(encoded, common.LeftPadBytes([]byte(val), 32)...)
		case *big.Int:
			encoded = append(encoded, common.LeftPadBytes(val.Bytes(), 32)...)
		case bool:
			if val {
				encoded = append(encoded, []byte{0x0, 0x1}...)
			}
		case common.Hash:
			encoded = append(encoded, val[:]...)
		case []byte:
			encoded = append(encoded, val...)
		case *common.Address:
			encoded = append(encoded, val[:]...)
		default:
			return nil, fmt.Errorf("unsupported type %T", arg)
		}
	}
	return encoded, nil
}
