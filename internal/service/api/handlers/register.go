package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/google/jsonapi"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/verifier"
	errors2 "github.com/pkg/errors"
	"github.com/rarimo/passport-identity-provider/internal/config"
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
		HashAlgorithm:      types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm),
		SignatureAlgorithm: types.SignatureAlgorithmFromString(req.Data.Attributes.DocumentSod.SignatureAlgorithm),
	}

	documentSOD := data.DocumentSOD{
		DG15:                req.Data.Attributes.DocumentSod.Dg15,
		HashAlgorigthm:      algorithmPair.HashAlgorithm,
		SignatureAlgorithm:  algorithmPair.SignatureAlgorithm,
		SignedAttributes:    req.Data.Attributes.DocumentSod.SignedAttributes,
		EncapsulatedContent: req.Data.Attributes.DocumentSod.EncapsulatedContent,
		Signature:           req.Data.Attributes.DocumentSod.Signature,
		AaSignature:         req.Data.Attributes.DocumentSod.AaSignature,
		PemFile:             req.Data.Attributes.DocumentSod.PemFile,
		ErrorKind:           nil,
		Error:               nil,
	}

	var response *resources.SignatureResponse
	var jsonError []*jsonapi.ErrorObject

	defer func() {
		// SHA256 hash used for unique constraint reserved for expansion, since postgresql has index limit
		resultHash := sha256.New()

		message := fmt.Sprintf(
			"%s%s%s%s%s",
			documentSOD.HashAlgorigthm, documentSOD.SignatureAlgorithm, documentSOD.SignedAttributes,
			documentSOD.EncapsulatedContent, documentSOD.Signature,
		)

		if documentSOD.Error != nil {
			message += fmt.Sprintf("%s%s", documentSOD.ErrorKind, *documentSOD.Error)
		}

		resultHash.Write([]byte(message))
		documentSOD.Hash = hex.EncodeToString(resultHash.Sum(nil))

		if _, err := api.DocumentSODQ(r).Insert(documentSOD); err != nil {
			api.Log(r).WithError(err).Error("failed to insert document SOD")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		if jsonError != nil {
			ape.RenderErr(w, jsonError...)
			return
		}

		if response != nil {
			ape.Render(w, response)
		}
	}()

	rawReqData, err := json.Marshal(req.Data)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to marshal register request")
		jsonError = append(jsonError, problems.InternalError())
		return
	}
	log := api.Log(r).WithFields(logan.F{
		"user-agent":   r.Header.Get("User-Agent"),
		"request_data": string(rawReqData),
	})

	cfg := api.VerifierConfig(r)

	if err := verifier.VerifyGroth16(
		req.Data.Attributes.ZkProof,
		cfg.VerificationKeys[types.SHA256],
	); err != nil {
		log.WithError(err).Error("failed to verify zk proof")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return
	}

	signedAttributes, err := hex.DecodeString(req.Data.Attributes.DocumentSod.SignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to decode signed attributes")
		jsonError = problems.BadRequest(validation.Errors{
			"signed_attributes": err,
		})
		return
	}

	encapsulatedContent, err := hex.DecodeString(req.Data.Attributes.DocumentSod.EncapsulatedContent)
	if err != nil {
		log.WithError(err).Error("failed to decode encapsulated content")
		jsonError = problems.BadRequest(validation.Errors{
			"encapsulated_content": err,
		})
		return
	}

	cert, err := parseCertificate([]byte(req.Data.Attributes.DocumentSod.PemFile))
	if err != nil {
		log.WithError(err).Error("failed to parse certificate")
		jsonError = problems.BadRequest(validation.Errors{
			"pem_file": err,
		})
		return
	}

	slaveSignatureHex, err := hex.DecodeString(req.Data.Attributes.DocumentSod.Signature)
	if err != nil {
		log.WithError(err).Error("failed to decode slaveSignature")
		jsonError = problems.BadRequest(validation.Errors{
			"slaveSignature": err,
		})
		return
	}

	var slaveSignature asn1.RawValue
	if _, err := asn1.Unmarshal(slaveSignatureHex, &slaveSignature); err != nil {
		log.WithError(err).Error("failed to unmarshal slaveSignature")
		jsonError = problems.BadRequest(validation.Errors{
			"slaveSignature": err,
		})
		return
	}

	dg1, err := getDataGroup(encapsulatedContent, 0)
	if err != nil {
		log.WithError(err).Error("failed to get data group")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofDg1Decimal, ok := big.NewInt(0).SetString(req.Data.Attributes.ZkProof.PubSignals[0], 10)
	if !ok {
		log.Error("failed to convert proofDg1Decimal to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	dg1Truncated := dg1
	if len(dg1) > 31 {
		// Since circuit is using 31 bits of dg1, we need to truncate it to last 31 bytes
		dg1Truncated = dg1[len(dg1)-31:]
	}

	if !bytes.Equal(dg1Truncated, proofDg1Decimal.Bytes()) {
		log.Error("proof contains foreign data group 1")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("proof contains foreign data group 1"),
		})
		return
	}

	err = verifySod(signedAttributes, encapsulatedContent, slaveSignature.Bytes, cert, algorithmPair, cfg)
	if err != nil {
		var sodError *types.SodError
		errors2.As(err, &sodError)

		log.WithError(err).Error("failed to verify SOD")

		documentSOD.ErrorKind = sodError.GetOptionalKind()
		documentSOD.Error = sodError.GetOptionalMessage()

		if resp := mapResponse(sodError.Kind, sodError.Message); resp != nil {
			jsonError = problems.BadRequest(resp)
			return
		}
	}

	truncatedSignedAttributes, err := extractBits(signedAttributes, 252)
	if err != nil {
		log.WithError(err).Error("failed to extract bits from signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	documentHash, err := poseidon.HashBytes(truncatedSignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to hash signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	message := append(dg1, documentHash.Bytes()...)

	signature, err := ecdsa.SignASN1(rand.Reader, api.KeysConfig(r).SignatureKey, message)
	if err != nil {
		log.WithError(err).Error("failed to sign message")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	response = &resources.SignatureResponse{
		Data: resources.Signature{
			Key: resources.NewKeyInt64(0, resources.SIGNATURE),
			Attributes: resources.SignatureAttributes{
				DocumentHash: hex.EncodeToString(documentHash.Bytes()),
				Signature:    hex.EncodeToString(signature),
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
		cfg *config.VerifierConfig,
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

	if err := validateCert(cert, cfg.MasterCerts, cfg.DisableTimeChecks, cfg.DisableNameChecks); err != nil {
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

func validateCert(cert *x509.Certificate, masterCertsPem []byte, disableTimeChecks, disableNameChecks bool) error {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(masterCertsPem)

	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots:             roots,
		DisableTimeChecks: disableTimeChecks,
		DisableNameChecks: disableNameChecks,
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
