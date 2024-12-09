package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/iden3/go-iden3-crypto/poseidon"
	errors2 "github.com/pkg/errors"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/types"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func Register(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewRegisterRequest(r)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to create new register request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	algorithmPair := types.AlgorithmPair{
		HashAlgorithm:      types.HashAlgorithmFromString(req.Data.Attributes.HashAlgorithm),
		SignatureAlgorithm: types.SignatureAlgorithmFromString(req.Data.Attributes.SignatureAlgorithm),
	}

	documentSOD := data.DocumentSOD{
		DG15:                req.Data.Attributes.Dg15,
		HashAlgorigthm:      algorithmPair.HashAlgorithm,
		SignatureAlgorithm:  algorithmPair.SignatureAlgorithm,
		SignedAttributed:    req.Data.Attributes.SignedAttributes,
		EncapsulatedContent: req.Data.Attributes.EncapsulatedContent,
		Signature:           req.Data.Attributes.Signature,
		PemFile:             req.Data.Attributes.PemFile,
		ErrorKind:           nil,
		Error:               nil,
	}

	var response resources.RegisterResponse

	defer func(documentSOD *data.DocumentSOD, response *resources.RegisterResponse) {
		if _, err := api.DocumentSODQ(r).Insert(*documentSOD); err != nil {
			api.Log(r).WithError(err).Error("failed to insert document SOD")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		if response != nil {
			ape.Render(w, response)
		}
	}(&documentSOD, &response)

	rawReqData, err := json.Marshal(req.Data)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to marshal register request")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	log := api.Log(r).WithFields(logan.F{
		"user-agent":   r.Header.Get("User-Agent"),
		"request_data": string(rawReqData),
	})

	cfg := api.VerifierConfig(r)

	signedAttributes, err := hex.DecodeString(req.Data.Attributes.SignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to decode signed attributes")
		ape.RenderErr(w, problems.BadRequest(validation.Errors{
			"signed_attributes": err,
		})...)
		return
	}

	encapsulatedContent, err := hex.DecodeString(req.Data.Attributes.EncapsulatedContent)
	if err != nil {
		log.WithError(err).Error("failed to decode encapsulated content")
		ape.RenderErr(w, problems.BadRequest(validation.Errors{
			"encapsulated_content": err,
		})...)
		return
	}

	cert, err := parseCertificate([]byte(req.Data.Attributes.PemFile))
	if err != nil {
		log.WithError(err).Error("failed to parse certificate")
		ape.RenderErr(w, problems.BadRequest(validation.Errors{
			"pem_file": err,
		})...)
		return
	}

	slaveSignature, err := hex.DecodeString(req.Data.Attributes.Signature)
	if err != nil {
		log.WithError(err).Error("failed to decode slaveSignature")
		ape.RenderErr(w, problems.BadRequest(validation.Errors{
			"slaveSignature": err,
		})...)
		return
	}

	err = verifySod(signedAttributes, encapsulatedContent, slaveSignature, cert, algorithmPair, cfg.MasterCerts)
	if err != nil {
		var sodError *types.SodError
		errors2.As(err, &sodError)

		log.WithError(err).Error("failed to verify SOD")

		documentSOD.ErrorKind = sodError.GetOptionalKind()
		documentSOD.Error = sodError.GetOptionalMessage()

		if resp := mapResponse(sodError.Kind, sodError.Message); resp != nil {
			ape.RenderErr(w, problems.BadRequest(resp)...)
			return
		}
	}

	truncatedSignedAttributes, err := extractBits(signedAttributes, 252)
	if err != nil {
		log.WithError(err).Error("failed to extract bits from signed attributes")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	documentHash, err := poseidon.HashBytes(truncatedSignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to hash signed attributes")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	dg1, err := getDataGroup(encapsulatedContent, 0)
	if err != nil {
		log.WithError(err).Error("failed to get data group")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	message := append(dg1, documentHash.Bytes()...)

	signature, err := ecdsa.SignASN1(rand.Reader, api.KeysConfig(r).SignatureKey, message)
	if err != nil {
		log.WithError(err).Error("failed to sign message")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	response = resources.RegisterResponse{
		Data: resources.Register{
			Key: resources.NewKeyInt64(0, resources.REGISTER),
			Attributes: resources.RegisterAttributes{
				Signature:    hex.EncodeToString(signature),
				DocumentHash: hex.EncodeToString(documentHash.Bytes()),
			},
		},
	}
}

func verifySod(
		signedAttributes []byte,
		encapsulatedContent []byte,
		signature []byte,
		cert *x509.Certificate,
		algorithmPair types.AlgorithmPair,
		masterCertsPem []byte,
) error {
	if err := validateSignedAttributes(signedAttributes, encapsulatedContent, algorithmPair.HashAlgorithm); err != nil {
		return &types.SodError{
			Kind:    types.SAValidateErr.Ptr(),
			Message: err,
		}
	}

	if err := verifySignature(signature, cert, signedAttributes, algorithmPair); err != nil {
		unwrappedErr := errors2.Unwrap(err)
		if errors2.Is(unwrappedErr, types.ErrInvalidPublicKey{}) {
			return &types.SodError{
				Kind:    types.PEMFilePubKeyErr.Ptr(),
				Message: err,
			}
		}

		return &types.SodError{
			Kind:    types.SigVerifyErr.Ptr(),
			Message: err,
		}
	}

	if err := validateCert(cert, masterCertsPem); err != nil {
		return &types.SodError{
			Kind:    types.PEMFileValidateErr.Ptr(),
			Message: err,
		}
	}

	return nil
}

func parseCertificate(pemFile []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemFile)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func validateSignedAttributes(
		signedAttributes,
		encapsulatedContent []byte,
		hashAlgorithm types.HashAlgorithm,
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

	h := types.GeneralHash(hashAlgorithm)
	h.Write(encapsulatedContent)
	d := h.Sum(nil)

	if len(digestAttr.Digest) == 0 {
		return errors.New("signed attributes digest values amount is 0")
	}

	if !bytes.Equal(digestAttr.Digest[0].Bytes, d) {
		return errors.From(
			errors.New("digest values are not equal"), logan.F{
				"signed_attributes":    hex.EncodeToString(digestAttr.Digest[0].Bytes),
				"content_hash":         hex.EncodeToString(d),
				"encapsulated_content": hex.EncodeToString(encapsulatedContent),
			},
		)
	}
	return nil
}

func verifySignature(
		signature []byte,
		cert *x509.Certificate,
		signedAttributes []byte,
		algorithmPair types.AlgorithmPair,
) error {
	h := types.GeneralHash(algorithmPair.HashAlgorithm)
	h.Write(signedAttributes)
	d := h.Sum(nil)

	if err := types.GeneralVerify(cert.PublicKey, d, signature, algorithmPair); err != nil {
		return err
	}

	return nil
}

func validateCert(cert *x509.Certificate, masterCertsPem []byte) error {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(masterCertsPem)

	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots:             roots,
		DisableTimeChecks: true,
		DisableNameChecks: true,
	})
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	if len(foundCerts) == 0 {
		return errors.New("invalid certificate: no valid certificate found")
	}

	return nil
}

func extractBits(data []byte, numBits int) ([]byte, error) {
	numBytes := (numBits + 7) / 8
	if len(data) < numBytes {
		return nil, fmt.Errorf("data is too short, requires at least %d bytes", numBytes)
	}

	result := make([]byte, numBytes)
	copy(result, data[:numBytes])

	remainingBits := numBits % 8
	if remainingBits != 0 {
		mask := byte(0xFF << (8 - remainingBits))
		result[numBytes-1] &= mask
	}

	return result, nil
}

func mapResponse(errKind *types.DocumentSODErrorKind, err error) validation.Errors {
	if errKind == nil {
		return nil
	}

	switch *errKind {
	case types.SAValidateErr:
		return validation.Errors{
			"signed_attributes": err,
		}
	case types.PEMFileValidateErr, types.PEMFileParseErr, types.PEMFilePubKeyErr:
		return validation.Errors{
			"pem_file": err,
		}
	case types.SigVerifyErr:
		return validation.Errors{
			"signature": err,
		}
	default:
		return nil
	}
}

func getDataGroup(encapsulatedContent []byte, index int) ([]byte, error) {
	encapsulatedData := types.EncapsulatedData{}
	if _, err := asn1.Unmarshal(encapsulatedContent, &encapsulatedData); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal encapsulated data")
	}

	privateKey := make([]asn1.RawValue, 0)
	if _, err := asn1.Unmarshal(encapsulatedData.PrivateKey.FullBytes, &privateKey); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal private key")
	}

	privKeyEl := types.PrivateKeyElement{}
	if _, err := asn1.Unmarshal(privateKey[index].FullBytes, &privKeyEl); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal private key element")
	}

	return privKeyEl.OctetStr.Bytes, nil
}
