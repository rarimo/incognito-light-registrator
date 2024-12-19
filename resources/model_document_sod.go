/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type DocumentSod struct {
	// The active authentication signature
	AaSignature *string `json:"aa_signature,omitempty"`
	// The Data Group 15, hex string
	Dg15 *string `json:"dg15,omitempty"`
	// The encapsulated content, for e.g. 186 bytes-long hex string
	EncapsulatedContent string `json:"encapsulated_content"`
	// The hash algorithm used to hash the content
	HashAlgorithm string `json:"hash_algorithm"`
	// The PEM file containing the public key
	PemFile string `json:"pem_file"`
	// Signature corresponding to the algorithm
	Signature string `json:"signature"`
	// The signature algorithm used to sign the content
	SignatureAlgorithm string `json:"signature_algorithm"`
	// The signed attributes, for e.g. 104 bytes-long hex string
	SignedAttributes string `json:"signed_attributes"`
	// The document SOD, hex string
	Sod *string `json:"sod,omitempty"`
}
