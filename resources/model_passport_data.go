/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

import "github.com/ethereum/go-ethereum/common"

type PassportData struct {
	// Hex of poseidon hash of truncated signed attributes
	Hash string `json:"hash"`
	// Public key (hex) parsed from dg15. Omitted (empty string) if passport has no dg15
	PublicKey string `json:"public_key"`
	// Verifier contract address (hex)
	Verifier common.Address `json:"verifier"`
}
