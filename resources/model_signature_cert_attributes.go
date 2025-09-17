/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type SignatureCertAttributes struct {
	// Poseidon hash of public key parsed from PEM certificate.
	PublicKeyHash string `json:"public_key_hash"`
	// ECDSA signature of the abi encoded signed data
	Signature string `json:"signature"`
}
