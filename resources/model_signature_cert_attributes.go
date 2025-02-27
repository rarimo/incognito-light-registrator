/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type SignatureCertAttributes struct {
	// Public key of the ICAO root certificate that signed the provided certificate.
	MasterCertPublicKey string `json:"master_cert_public_key"`
	// PublicKey for signature validation.
	PublicKey string `json:"public_key"`
	// ECDSA signature of the abi encoded signed data
	Signature string `json:"signature"`
}
