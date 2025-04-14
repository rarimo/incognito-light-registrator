package requests

import (
	"encoding/json"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/passport-identity-provider/resources"
)

func NewRegisterRequestCert(r *http.Request) (request resources.RegisterCertRequest, err error) {
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return request, validation.NewError("err_decode", "failed to unmarshal register certificate request")
	}

	return request, validateRegisterCert(request)
}

func validateRegisterCert(r resources.RegisterCertRequest) error {
	return validation.Errors{
		"/data/attributes/pem_file": validation.Validate(
			r.Data.Attributes.PemFile,
			validation.Required,
			validation.Length(0, 65536),
		),
	}.Filter()
}
