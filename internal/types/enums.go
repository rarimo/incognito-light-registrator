package types

type HashAlgorithm uint8

const (
	SHA1 HashAlgorithm = iota
	SHA256
	SHA384
	SHA512
)

var hashAlgorithmMap = map[string]HashAlgorithm{
	"SHA1":   SHA1,
	"SHA256": SHA256,
	"SHA384": SHA384,
	"SHA512": SHA512,
}

func (h HashAlgorithm) String() string {
	switch h {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	default:
		return "Unknown"
	}
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
		return "Unknown"
	}
}

func IsValidSignatureAlgorithm(alg string) (SignatureAlgorithm, bool) {
	s, ok := signatureAlgorithmMap[alg]
	return s, ok
}
