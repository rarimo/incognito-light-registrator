package handlers

import (
	"net/http"

	"github.com/rarimo/certificate-transparency-go/x509"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/jsonapi"
	"github.com/rarimo/passport-identity-provider/internal/utils"

	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func RegisterCertificate(w http.ResponseWriter, r *http.Request) {
	log := api.Log(r)
	cfg := api.VerifierConfig(r)
	req, err := requests.NewRegisterRequestCert(r)
	if err != nil {
		log.WithError(err).Error("failed to create new register certificate request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	var jsonError []*jsonapi.ErrorObject
	PemFile := req.Data.Attributes.PemFile

	var response *resources.SignatureCertResponse
	cert, err := parseCertificate([]byte(PemFile))
	if err != nil {
		log.WithError(err).Error("failed to parse certificate")
		jsonError = problems.BadRequest(validation.Errors{
			"pem_file": err,
		})
		ape.RenderErr(w, jsonError...)
		return
	}
	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots:             cfg.MasterCerts,
		DisableTimeChecks: cfg.DisableTimeChecks,
		DisableNameChecks: cfg.DisableNameChecks,
	})
	if err != nil {
		log.WithError(err).Error("invalid certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if len(foundCerts) == 0 {
		log.Error("invalid certificate: no valid certificate found")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	masterCert := foundCerts[0][1]

	pubKeyMasterCertBytes, err := extractPublicKey(masterCert.PublicKey)
	if err != nil {
		log.WithError(err).Error("Failed to extract master public key")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	rawSignedData, err := utils.BuildSignedCertData(*pubKeyMasterCertBytes)
	if err != nil {
		log.WithError(err).Error("failed to build signed data")
		jsonError = append(jsonError, problems.InternalError())
		ape.RenderErr(w, jsonError...)
		return
	}

	signature, err := crypto.Sign(utils.ToEthSignedMessageHash(crypto.Keccak256(rawSignedData)), api.KeysConfig(r).SignatureKey)
	if err != nil {
		log.WithError(err).Error("failed to sign public key")
		jsonError = append(jsonError, problems.InternalError())
		ape.RenderErr(w, jsonError...)
		return
	}

	signature[64] += 27

	pubKeyBytes, err := extractPublicKey(&api.KeysConfig(r).SignatureKey.PublicKey)
	if err != nil {
		log.WithError(err).Error("Failed to extract public key")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	response = &resources.SignatureCertResponse{
		Data: resources.SignatureCert{
			Key: resources.NewKeyInt64(0, resources.SIGNATURE_CERT),
			Attributes: resources.SignatureCertAttributes{
				PublicKey:           hexutil.Encode((*pubKeyBytes)[:]),
				MasterCertPublicKey: hexutil.Encode((*pubKeyMasterCertBytes)[:]),
				Signature:           hexutil.Encode(signature),
			},
		},
	}
	ape.Render(w, response)
}

func extractPublicKey(publicKey interface{}) (*[]byte, error) {
	var pubKeyBytes []byte
	var err error
	pubKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &pubKeyBytes, nil
}
