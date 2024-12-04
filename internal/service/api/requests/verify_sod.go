package requests

import (
	"encoding/json"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func NewVerifySodRequest(r *http.Request) (request resources.DocumentSodResponse, err error) {
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		return request, validation.NewError("err_decode", "failed to unmarshal verify sod request")
	}

	return request, validateVerifySod(request)
}

func validateVerifySod(r resources.DocumentSodResponse) error {
	return validation.Errors{
		"/data/attributes/signature_algorithm": validation.Validate(
			r.Data.Attributes.SignatureAlgorithm,
			validation.Required,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidSignatureAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported signature algorithm")
				}

				return nil
			}),
		),
		"/data/attributes/hash_algorithm": validation.Validate(
			r.Data.Attributes.HashAlgorithm,
			validation.Required,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidHashAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported hash algorithm")
				}

				return nil
			})),
		"/data/attributes/dg15": validation.Validate(
			r.Data.Attributes.Dg15,
			validation.Required,
			validation.Length(1, 512),
		),
		"/data/attributes/signed_attributes": validation.Validate(
			r.Data.Attributes.SignedAttributes,
			validation.Required,
			validation.Length(1, 256),
		),
		"/data/attributes/encapsulated_content": validation.Validate(
			r.Data.Attributes.SignedAttributes,
			validation.Required,
			validation.Length(1, 1024),
		),
		"/data/attributes/signature": validation.Validate(
			r.Data.Attributes.SignedAttributes,
			validation.Required,
			validation.Length(1, 1024),
		),
		"/data/attributes/pem_file": validation.Validate(
			r.Data.Attributes.SignedAttributes,
			validation.Required,
			validation.Length(1, 4096),
		),
	}.Filter()
}
