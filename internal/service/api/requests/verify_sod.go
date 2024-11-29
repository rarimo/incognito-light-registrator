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
		return request, validation.Errors{
			"/": errors.Wrap(err, "failed to decode request"),
		}.Filter()
	}

	return request, validateVerifySod(request)
}

func validateVerifySod(r resources.DocumentSodResponse) error {
	return validation.Errors{
		"/data/attributes/signature": validation.Validate(
			r.Data.Attributes.SignatureAlgorithm,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidSignatureAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported signature algorithm")
				}

				return nil
			}),
		),
		"/data/attributes/algorithm": validation.Validate(
			r.Data.Attributes.HashAlgorithm,
			validation.By(func(value interface{}) error {
				_, ok := types.IsValidHashAlgorithm(value.(string))
				if !ok {
					return errors.New("unsupported hash algorithm")
				}

				return nil
			})),
	}.Filter()
}
