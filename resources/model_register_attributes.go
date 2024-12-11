/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

import "github.com/iden3/go-rapidsnark/types"

type RegisterAttributes struct {
	DocumentSod DocumentSod `json:"document_sod"`
	// Zero-knowledge proof with dg1 public input
	ZkProof types.ZKProof `json:"zk_proof"`
}
