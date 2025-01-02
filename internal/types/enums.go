package types

import "strings"

type HashAlgorithm uint8

const (
	SHA1 HashAlgorithm = iota
	SHA224
	SHA256
	SHA384
	SHA512
)

var hashAlgorithmMap = map[string]HashAlgorithm{
	"SHA1":   SHA1,
	"SHA224": SHA224,
	"SHA256": SHA256,
	"SHA384": SHA384,
	"SHA512": SHA512,
}

var hashAlgorithmSizeMap = map[int]HashAlgorithm{
	20: SHA1,
	28: SHA224,
	32: SHA256,
	48: SHA384,
	64: SHA512,
}

func (h HashAlgorithm) String() string {
	switch h {
	case SHA1:
		return "SHA1"
	case SHA224:
		return "SHA224"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	default:
		return Unknown
	}
}

func HashAlgorithmFromString(alg string) HashAlgorithm {
	h, ok := hashAlgorithmMap[strings.ToUpper(alg)]
	if !ok {
		return HashAlgorithm(0)
	}
	return h
}

func HashAlgorithmFromSize(size int) HashAlgorithm {
	h, ok := hashAlgorithmSizeMap[size]
	if !ok {
		return HashAlgorithm(0)
	}
	return h
}

func IsValidHashAlgorithm(alg string) (HashAlgorithm, bool) {
	h, ok := hashAlgorithmMap[alg]
	return h, ok
}

type SignatureAlgorithm uint8

const (
	RSA SignatureAlgorithm = iota
	RSAPSS
	ECDSA
	Unknown = "Unknown"
)

var signatureAlgorithmMap = map[string]SignatureAlgorithm{
	"RSA":     RSA,
	"RSA-PSS": RSAPSS,
	"ECDSA":   ECDSA,
}

func (s SignatureAlgorithm) String() string {
	switch s {
	case RSA:
		return "RSA"
	case RSAPSS:
		return "RSA-PSS"
	case ECDSA:
		return "ECDSA"
	default:
		return Unknown
	}
}

func SignatureAlgorithmFromString(alg string) SignatureAlgorithm {
	s, ok := signatureAlgorithmMap[alg]
	if !ok {
		return SignatureAlgorithm(0)
	}
	return s
}

func IsValidSignatureAlgorithm(alg string) (SignatureAlgorithm, bool) {
	s, ok := signatureAlgorithmMap[alg]
	return s, ok
}
