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
	key := types.CompositeKey{
		HashAlgo:      r.Data.Attributes.HashAlgorithm,
		SignatureAlgo: r.Data.Attributes.SignatureAlgorithm,
	}

	if _, ok := types.SupportedSignatureHashAlgorithms[key]; ok {
		return nil
	}

	return validation.Errors{
		"/data/attributes": types.UnsupportedAlgorithmPairError{
			HashAlgo:      r.Data.Attributes.HashAlgorithm,
			SignatureAlgo: r.Data.Attributes.SignatureAlgorithm,
		},
	}.Filter()
}
