package data

import (
	"time"

	"github.com/rarimo/passport-identity-provider/internal/types"
)

type DocumentSODQ interface {
	New() DocumentSODQ
	Get() (*DocumentSOD, error)
	Insert(data DocumentSOD) (*DocumentSOD, error)
	ResetFilters() DocumentSODQ
}

type DocumentSOD struct {
	ID                  int64                       `db:"id" structs:"-"`
	CreatedAt           time.Time                   `db:"created_at" structs:"-"`
	UpdatedAt           time.Time                   `db:"updated_at" structs:"-"`
	DG15                string                      `db:"dg15" structs:"dg15"`
	HashAlgorigthm      types.HashAlgorithm         `db:"hash_algorithm" structs:"hash_algorithm"`
	SignatureAlgorithm  types.SignatureAlgorithm    `db:"signature_algorithm" structs:"signature_algorithm"`
	SignedAttributes    string                      `db:"signed_attributes" structs:"signed_attributes"`
	EncapsulatedContent string                      `db:"encapsulated_content" structs:"encapsulated_content"`
	Signature           string                      `db:"signature" structs:"signature"`
	AaSignature         string                      `db:"aa_signature" structs:"aa_signature"`
	PemFile             string                      `db:"pem_file" structs:"pem_file"`
	Hash                string                      `db:"hash" structs:"hash"`
	ErrorKind           *types.DocumentSODErrorKind `db:"error_kind" structs:"error_kind"`
	Error               *string                     `db:"error" structs:"error"`
}
