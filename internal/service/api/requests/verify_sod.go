package requests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func NewVerifySodRequest(r *http.Request) (request resources.DocumentSodResponse, err error) {
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		return request, validation.Errors{
			"/": errors.Wrap(err, "failed to decode request"),
		}.Filter()
	}

	encapsulatedContent := PrependPrefix(request.Data.Attributes.EncapsulatedContent)
	if strings.Compare(encapsulatedContent, request.Data.Attributes.EncapsulatedContent) != 0 {
		api.Log(r).WithFields(logan.F{
			"encapsulated_content_new": encapsulatedContent,
			"encapsulated_content_old": request.Data.Attributes.EncapsulatedContent,
		}).Info("encapsulated content update")
		request.Data.Attributes.EncapsulatedContent = encapsulatedContent
	}

	return request, validateVerifySod(request)
}

// PrependPrefix - сrunch before Android fix
func PrependPrefix(data string) string {
	// Parse by VERSION field
	subs := strings.Split(data, "0201")

	dataLength := subs[0]

	// recreate the rest of the string without length
	rest := "0201" + strings.Join(subs[1:], "0201")

	restByteLen := int64(len(rest) / 2)

	actualLength := toHex(restByteLen)

	if restByteLen > 128 && restByteLen < 256 {
		actualLength = "81" + actualLength
	}
	if restByteLen > 256 {
		actualLength = "82" + actualLength
	}

	data = "30" + dataLength + rest
	if strings.Compare(dataLength, actualLength) != 0 {
		data = "30" + actualLength + rest
	}

	return data
}

func toHex(number int64) string {
	hexStr := strconv.FormatInt(number, 16)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	return hexStr
}

func validateVerifySod(r resources.DocumentSodResponse) error {
	return validation.Errors{
		"/data/attributes/hash_algorithm": validation.Validate(
			r.Data.Attributes.HashAlgorithm,
			validation.In("SHA1", "SHA256", "SHA384"),
		),
		"/data/attributes/signature_algorithm": validation.Validate(
			r.Data.Attributes.SignatureAlgorithm,
			validation.In("RSA", "ECDSA", "RSA-PSS"),
		),
	}.Filter()
}
