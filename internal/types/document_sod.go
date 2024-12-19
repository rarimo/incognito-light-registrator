package types

import "encoding/asn1"

type DigestAttribute struct {
	ID     asn1.ObjectIdentifier
	Digest []asn1.RawValue `asn1:"set"`
}

type EncapsulatedData struct {
	Version             int
	PrivateKeyAlgorithm asn1.RawValue
	PrivateKey          []PrivateKeyElement
}

type PrivateKeyElement struct {
	Integer  int
	OctetStr asn1.RawContent
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type ECPublicKey struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}
