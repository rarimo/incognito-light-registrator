package requests

import (
	"encoding/json"
	"fmt"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/resources"
)

func NewRegisterIDRequest(r *http.Request) (request resources.RegisterIDResponse, err error) {
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return request, validation.NewError("err_decode", "failed to unmarshal register request")
	}

	return request, validateRegisterID(request)
}

func validateRegisterID(r resources.RegisterIDResponse) error {
	return validation.Errors{
		"/data/attributes/document_sod/signature_algorithm": validation.Validate(
			r.Data.Attributes.DocumentSod.SignatureAlgorithm,
			validation.Required,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidSignatureAlgorithm(value.(string))
				if !ok {
					return fmt.Errorf("unsupported signature algorithm: %s", value)
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
					return fmt.Errorf("unsupported hash algorithm: %s", value)
				}

				return nil
			})),
		"/data/attributes/document_sod/dg15": validation.Validate(
			r.Data.Attributes.DocumentSod.Dg15,
			validation.Length(0, 32760),
		),
		"/data/attributes/document_sod/signed_attributes": validation.Validate(
			r.Data.Attributes.DocumentSod.SignedAttributes,
			validation.Required,
			validation.Length(0, 65536),
		),
		"/data/attributes/document_sod/encapsulated_content": validation.Validate(
			r.Data.Attributes.DocumentSod.EncapsulatedContent,
			validation.Required,
			validation.Length(0, 65536),
		),
		"/data/attributes/document_sod/signature": validation.Validate(
			r.Data.Attributes.DocumentSod.Signature,
			validation.Required,
			validation.Length(0, 16384),
		),
		"/data/attributes/document_sod/aa_signature": validation.Validate(
			r.Data.Attributes.DocumentSod.AaSignature,
			validation.Length(0, 16384),
		),
		"/data/attributes/document_sod/pem_file": validation.Validate(
			r.Data.Attributes.DocumentSod.PemFile,
			validation.Required,
			validation.Length(0, 65536),
		),
		"/data/attributes/zk_proof/proof": validation.Validate(
			//proof is just array of bytes, we will write it in bin file later
			r.Data.Attributes.ZkProof,
			validation.Required,
			validation.Length(1, 262144),
		),
		"/data/attributes/document_sod/sod": validation.Validate(
			r.Data.Attributes.DocumentSod.Sod,
			validation.Length(0, 262144),
		),
	}.Filter()
}
