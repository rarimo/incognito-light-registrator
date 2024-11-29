package handlers

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/jsonapi"
	errors2 "github.com/pkg/errors"

	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func VerifySod(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewVerifySodRequest(r)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to create new create identity request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	// algorithm pair already validated in NewVerifySodRequest
	algorithm, _ := types.SupportedSignatureHashAlgorithms[types.CompositeKey{
		HashAlgo:      req.Data.Attributes.HashAlgorithm,
		SignatureAlgo: req.Data.Attributes.SignatureAlgorithm,
	}]

	rawReqData, err := json.Marshal(req.Data)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to marshal create identity request")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	log := api.Log(r).WithFields(logan.F{
		"user-agent":   r.Header.Get("User-Agent"),
		"request_data": string(rawReqData),
	})

	signedAttributes, err := hex.DecodeString(req.Data.Attributes.SignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to decode hex string")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	encapsulatedContent, err := hex.DecodeString(req.Data.Attributes.EncapsulatedContent)
	if err != nil {
		log.WithError(err).Error("failed to decode hex string")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if err := validateSignedAttributes(signedAttributes, encapsulatedContent, algorithm); err != nil {
		log.WithError(err).Error("failed to validate signed attributes")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	cert, err := parseCertificate([]byte(req.Data.Attributes.PemFile))
	if err != nil {
		log.WithError(err).Error("failed to parse certificate")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := verifySignature(req, cert, signedAttributes, algorithm); err != nil {
		log.WithError(err).Error("failed to verify signature")

		response := make([]*jsonapi.ErrorObject, 1)
		response[0] = problems.InternalError()
		if errors2.Is(err, rsa.ErrVerification) {
			response = problems.BadRequest(validation.Errors{
				"/data/attributes/signature": errors2.New("signature verification failed"),
			})
		}

		ape.RenderErr(w, response...)
		return
	}

	cfg := api.VerifierConfig(r)

	encapsulatedData := types.EncapsulatedData{}
	if _, err = asn1.Unmarshal(encapsulatedContent, &encapsulatedData); err != nil {
		log.WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	privateKey := make([]asn1.RawValue, 0)
	if _, err = asn1.Unmarshal(encapsulatedData.PrivateKey.FullBytes, &privateKey); err != nil {
		log.WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	privKeyEl := types.PrivateKeyElement{}
	if _, err = asn1.Unmarshal(privateKey[0].FullBytes, &privKeyEl); err != nil {
		log.WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := validateCert(cert, cfg.MasterCerts); err != nil {
		log.WithError(err).Error("failed to validate certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	dg1Hex := hex.EncodeToString(privKeyEl.OctetStr.Bytes)
	ape.Render(w, resources.VerifySodResponse{
		Data: resources.VerifySod{
			Key: resources.NewKeyInt64(0, resources.VERIFY_SOD),
			Attributes: resources.VerifySodAttributes{
				Dg1: &dg1Hex,
			},
		},
	})
}

func parseCertificate(pemFile []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemFile)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return cert, nil
}

func validateSignedAttributes(
		signedAttributes,
		encapsulatedContent []byte,
		algorithm types.SignatureHashAlgorithm,
) error {
	signedAttributesASN1 := make([]asn1.RawValue, 0)

	if _, err := asn1.UnmarshalWithParams(signedAttributes, &signedAttributesASN1, "set"); err != nil {
		return errors.Wrap(err, "failed to unmarshal ASN1 with params")
	}

	if len(signedAttributesASN1) == 0 {
		return errors.New("signed attributes amount is 0")
	}

	digestAttr := types.DigestAttribute{}
	if _, err := asn1.Unmarshal(signedAttributesASN1[len(signedAttributesASN1)-1].FullBytes, &digestAttr); err != nil {
		return errors.Wrap(err, "failed to unmarshal ASN1")
	}

	h := algorithm.Hash()
	h.Write(encapsulatedContent)
	d := h.Sum(nil)

	if len(digestAttr.Digest) == 0 {
		return errors.New("signed attributes digest values amount is 0")
	}

	if !bytes.Equal(digestAttr.Digest[0].Bytes, d) {
		return errors.From(errors.New("digest signed attribute is not equal to encapsulated content hash"), logan.F{
			"signed_attributes":    hex.EncodeToString(digestAttr.Digest[0].Bytes),
			"content_hash":         hex.EncodeToString(d),
			"encapsulated_content": hex.EncodeToString(encapsulatedContent),
		})
	}
	return nil
}

func verifySignature(
		req resources.DocumentSodResponse,
		cert *x509.Certificate,
		signedAttributes []byte,
		algorithm types.SignatureHashAlgorithm,
) error {
	signature, err := hex.DecodeString(req.Data.Attributes.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

	h := algorithm.Hash()
	h.Write(signedAttributes)
	d := h.Sum(nil)

	if err := algorithm.Verify(cert.PublicKey, d, signature); err != nil {
		return err
	}

	return nil
}

func validateCert(cert *x509.Certificate, masterCertsPem []byte) error {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(masterCertsPem)

	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	if len(foundCerts) == 0 {
		return errors.New("invalid certificate: no valid certificate found")
	}

	return nil
}
