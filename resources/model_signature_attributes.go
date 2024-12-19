/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

import "github.com/ethereum/go-ethereum/common"

type SignatureAttributes struct {
	// Poseidon hash of truncated signed attributes
	PassportHash string `json:"passport_hash"`
	// Public key parsed from dg15. Omitted (empty string) if passport has no dg15
	PublicKey string `json:"public_key"`
	// ECDSA signature of the abi encoded signed data
	Signature string `json:"signature"`
	// Verifier contract address
	Verifier common.Address `json:"verifier"`
}
