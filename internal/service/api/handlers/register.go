package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/jsonapi"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/verifier"
	errors2 "github.com/pkg/errors"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/internal/utils"
	"gitlab.com/distributed_lab/logan/v3"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func Register(w http.ResponseWriter, r *http.Request) {
	log := api.Log(r)

	req, err := requests.NewRegisterRequest(r)
	if err != nil {
		log.WithError(err).Error("failed to create new register request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	algorithmPair := types.AlgorithmPair{
		HashAlgorithm:      types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm),
		SignatureAlgorithm: types.SignatureAlgorithmFromString(req.Data.Attributes.DocumentSod.SignatureAlgorithm),
	}

	documentSOD := data.DocumentSOD{
		HashAlgorigthm:      algorithmPair.HashAlgorithm,
		SignatureAlgorithm:  algorithmPair.SignatureAlgorithm,
		SignedAttributes:    utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.SignedAttributes),
		EncapsulatedContent: utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.EncapsulatedContent),
		Signature:           utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.Signature),
		PemFile:             req.Data.Attributes.DocumentSod.PemFile,
		ErrorKind:           nil,
		Error:               nil,
	}

	if req.Data.Attributes.DocumentSod.AaSignature != nil && *req.Data.Attributes.DocumentSod.AaSignature != "" {
		truncatedAaSignature := utils.TruncateHexPrefix(*req.Data.Attributes.DocumentSod.AaSignature)
		documentSOD.AaSignature = &truncatedAaSignature
	}

	if req.Data.Attributes.DocumentSod.Dg15 != nil && *req.Data.Attributes.DocumentSod.Dg15 != "" {
		truncatedDg15 := utils.TruncateHexPrefix(*req.Data.Attributes.DocumentSod.Dg15)
		documentSOD.DG15 = &truncatedDg15
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

		if _, err := api.DocumentSODQ(r).Upsert(documentSOD); err != nil {
			log.WithError(err).Error("failed to insert document SOD")
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

	verifierCfg := api.VerifierConfig(r)

	if err := verifier.VerifyGroth16(
		req.Data.Attributes.ZkProof,
		verifierCfg.VerificationKeys[algorithmPair.HashAlgorithm],
	); err != nil {
		log.WithError(err).Error("failed to verify zk proof")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return
	}

	signedAttributes, err := hex.DecodeString(utils.TruncateHexPrefix(documentSOD.SignedAttributes))
	if err != nil {
		log.WithError(err).Error("failed to decode signed attributes")
		jsonError = problems.BadRequest(validation.Errors{
			"signed_attributes": err,
		})
		return
	}

	encapsulatedContent, err := hex.DecodeString(utils.TruncateHexPrefix(documentSOD.EncapsulatedContent))
	if err != nil {
		log.WithError(err).Error("failed to decode encapsulated content")
		jsonError = problems.BadRequest(validation.Errors{
			"encapsulated_content": err,
		})
		return
	}

	cert, err := parseCertificate([]byte(documentSOD.PemFile))
	if err != nil {
		log.WithError(err).Error("failed to parse certificate")
		jsonError = problems.BadRequest(validation.Errors{
			"pem_file": err,
		})
		return
	}

	slaveSignature, err := hex.DecodeString(utils.TruncateHexPrefix(documentSOD.Signature))
	if err != nil {
		log.WithError(err).Error("failed to decode slaveSignature")
		jsonError = problems.BadRequest(validation.Errors{
			"slaveSignature": err,
		})
		return
	}

	dg1Hash, err := utils.GetDataGroup(encapsulatedContent, 1)
	if err != nil {
		log.WithError(err).Error("failed to get data group")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	if dg1Hash == nil {
		log.Error("data group 1 is missing")
		jsonError = problems.BadRequest(validation.Errors{
			"encapsulated_content": errors.New("data group 1 is missing"),
		})
		return
	}

	proofDg1Decimal, ok := big.NewInt(0).SetString(req.Data.Attributes.ZkProof.PubSignals[0], 10)
	if !ok {
		log.Error("failed to convert proofDg1Decimal to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	dg1Truncated := dg1Hash
	if len(dg1Hash) > types.DG1TruncateLength {
		// Since circuit is using types.DG1TruncateLength bytes of dg1Hash, we need to truncate it to first types.DG1TruncateLength bytes
		dg1Truncated = dg1Hash[len(dg1Hash)-types.DG1TruncateLength:]
	}

	if !bytes.Equal(dg1Truncated, proofDg1Decimal.FillBytes(make([]byte, types.DG1TruncateLength))) {
		log.Error("proof contains foreign data group 1")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("proof contains foreign data group 1"),
		})
		return
	}

	err = verifySod(signedAttributes, encapsulatedContent, slaveSignature, cert, algorithmPair, verifierCfg)
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

	truncatedSignedAttributes, err := utils.ExtractBits(signedAttributes, 252)
	if err != nil {
		log.WithError(err).Error("failed to extract bits from signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	passportHash, err := poseidon.HashBytes(truncatedSignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to hash signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	dg15Hash, err := utils.GetDataGroup(encapsulatedContent, 15)
	if err != nil {
		log.WithError(err).Error("failed to get data group")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	var extractedDg15 []byte
	if documentSOD.DG15 != nil {
		extractedDg15, err = hex.DecodeString(utils.TruncateHexPrefix(*documentSOD.DG15))
		if err != nil {
			log.WithError(err).Error("failed to decode dg15Hash")
			jsonError = append(jsonError, problems.InternalError())
			return
		}

		extractedDg15Hash := types.GeneralHash(algorithmPair.HashAlgorithm)
		extractedDg15Hash.Write(extractedDg15)

		if !bytes.Equal(dg15Hash, extractedDg15Hash.Sum(nil)) {
			log.Error("dg15Hash does not match")
			jsonError = problems.BadRequest(validation.Errors{
				"DG15": errors.New("dg15Hash does not match"),
			})
			return
		}
	}

	_, passportPubkeyHash, err := utils.ExtractPublicKey(extractedDg15)
	if err != nil {
		log.WithError(err).Error("failed to extract public key")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	addressesCfg := api.AddressesConfig(r)
	verifierContract, ok := addressesCfg.Verifiers[algorithmPair.HashAlgorithm]
	if !ok {
		log.Errorf("No verifier contract found for hash algorithm %s", algorithmPair.HashAlgorithm)
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	dg1HashSlice := [32]byte{}
	copy(dg1HashSlice[:], dg1Truncated)

	signedData, err := utils.BuildSignedData(
		addressesCfg.RegistrationContract,
		verifierContract,
		[32]byte(passportHash.Bytes()),
		dg1HashSlice,
		passportPubkeyHash,
	)
	if err != nil {
		log.WithError(err).Error("failed to build signed data")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	signature, err := crypto.Sign(utils.ToEthSignedMessageHash(signedData), api.KeysConfig(r).SignatureKey)
	if err != nil {
		log.WithError(err).Error("failed to sign messageHash")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	signature[64] += 27

	response = &resources.SignatureResponse{
		Data: resources.Signature{
			Key: resources.NewKeyInt64(0, resources.SIGNATURE),
			Attributes: resources.SignatureAttributes{
				PassportHash: hexutil.Encode(passportHash.Bytes()),
				PublicKey:    hexutil.Encode(passportPubkeyHash[:]),
				Verifier:     *verifierContract,
				Signature:    hexutil.Encode(signature),
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

func validateCert(cert *x509.Certificate, masterCerts *x509.CertPool, disableTimeChecks, disableNameChecks bool) error {
	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots:             masterCerts,
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
