package requests

import (
	"encoding/json"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func NewRegisterRequest(r *http.Request) (request resources.RegisterResponse, err error) {
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return request, validation.NewError("err_decode", "failed to unmarshal register request")
	}

	return request, validateRegister(request)
}

func validateRegister(r resources.RegisterResponse) error {
	return validation.Errors{
		"/data/attributes/document_sod/signature_algorithm": validation.Validate(
			r.Data.Attributes.DocumentSod.SignatureAlgorithm,
			validation.Required,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidSignatureAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported signature algorithm")
				}

				return nil
			}),
		),
		"/data/attributes/document_sod/hash_algorithm": validation.Validate(
			r.Data.Attributes.DocumentSod.HashAlgorithm,
			validation.Required,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidHashAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported hash algorithm")
				}

				return nil
			})),
		"/data/attributes/document_sod/dg15": validation.Validate(
			r.Data.Attributes.DocumentSod.Dg15,
			validation.Required,
			validation.Length(1, 512),
		),
		"/data/attributes/document_sod/signed_attributes": validation.Validate(
			r.Data.Attributes.DocumentSod.SignedAttributes,
			validation.Required,
			validation.Length(1, 512),
		),
		"/data/attributes/document_sod/encapsulated_content": validation.Validate(
			r.Data.Attributes.DocumentSod.EncapsulatedContent,
			validation.Required,
			validation.Length(1, 4096),
		),
		"/data/attributes/document_sod/signature": validation.Validate(
			r.Data.Attributes.DocumentSod.Signature,
			validation.Required,
			validation.Length(1, 4096),
		),
		"/data/attributes/document_sod/pem_file": validation.Validate(
			r.Data.Attributes.DocumentSod.PemFile,
			validation.Required,
			validation.Length(1, 4096),
		),
		"/data/attributes/zk_proof/proof": validation.Validate(
			r.Data.Attributes.ZkProof.Proof,
			validation.Required,
		),
	}.Filter()
}
