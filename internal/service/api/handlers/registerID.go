package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/jsonapi"
	"github.com/google/uuid"
	"github.com/iden3/go-iden3-crypto/poseidon"
	errors2 "github.com/pkg/errors"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/internal/utils"

	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func RegisterID(w http.ResponseWriter, r *http.Request) {
	log := api.Log(r)
	requestID := uuid.New().String()

	req, err := requests.NewRegisterIDRequest(r)
	if err != nil {
		log.WithError(err).Error("failed to create new register request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	algorithmPair := types.AlgorithmPair{
		DgHashAlgorithm:        types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm),
		SignedAttrHashAlg:      types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm),
		SignatureDigestHashAlg: types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm),
		SignatureAlgorithm:     types.SignatureAlgorithmFromString(req.Data.Attributes.DocumentSod.SignatureAlgorithm),
	}

	documentSOD := data.DocumentSOD{
		HashAlgorigthm:      algorithmPair.DgHashAlgorithm,
		SignatureAlgorithm:  algorithmPair.SignatureAlgorithm,
		SignedAttributes:    *utils.TruncateHexPrefix(&req.Data.Attributes.DocumentSod.SignedAttributes),
		EncapsulatedContent: *utils.TruncateHexPrefix(&req.Data.Attributes.DocumentSod.EncapsulatedContent),
		Signature:           *utils.TruncateHexPrefix(&req.Data.Attributes.DocumentSod.Signature),
		AaSignature:         utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.AaSignature),
		DG15:                utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.Dg15),
		RawSOD:              utils.TruncateHexPrefix(req.Data.Attributes.DocumentSod.Sod),
		PemFile:             req.Data.Attributes.DocumentSod.PemFile,
		ErrorKind:           nil,
		Error:               nil,
	}

	proofFile := fmt.Sprintf("proof%s", requestID)
	cmdFile := fmt.Sprintf("cmd%s.txt", requestID)

	var response *resources.SignatureResponse
	var jsonError []*jsonapi.ErrorObject

	defer func() {
		// SHA256 hash used for unique constraint reserved for expansion, since postgresql has index limit. We'll add
		// every field, that participates in proof verification, to the hash, so we can detect if changes of crucial
		// fields lead to different results.
		//
		// For now, if logic expands, we can add more fields to the hash without versioning it, since if there is new
		// field, that participates in proof verification, we want to store the whole document SOD again. Possibly,
		// storage management could be optimized by adding hash versioning and basic data checks through all versions.
		resultHash := sha256.New()

		message := fmt.Sprintf(
			"%s%s%s%s%s%s",
			documentSOD.HashAlgorigthm, documentSOD.SignatureAlgorithm, documentSOD.SignedAttributes,
			documentSOD.EncapsulatedContent, documentSOD.Signature, documentSOD.PemFile,
		)

		if documentSOD.Error != nil {
			message += fmt.Sprintf("%s%s", documentSOD.ErrorKind, *documentSOD.Error)
		}

		if documentSOD.DG15 != nil {
			message += *documentSOD.DG15
		}

		resultHash.Write([]byte(message))
		documentSOD.Hash = hex.EncodeToString(resultHash.Sum(nil))

		if _, err := api.DocumentSODQ(r).Upsert(documentSOD); err != nil {
			log.WithError(err).Error("failed to insert document SOD")
			jsonError = append(jsonError, problems.InternalError())
			return
		}

		if jsonError != nil {
			ape.RenderErr(w, jsonError...)
			return
		}

		if response != nil {
			ape.Render(w, response)
		}

		if err := os.Remove(proofFile); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Errorf("failed to remove file %s", proofFile)
		}
		if err := os.Remove(cmdFile); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Errorf("failed to remove file %s", cmdFile)
		}
	}()

	verifierCfg := api.VerifierConfig(r)

	hexProof, err := base64.StdEncoding.DecodeString(req.Data.Attributes.ZkProof)
    if err != nil {
        log.WithError(err).Error("failed to decode base64")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return
    }

    pubSignal1 := hexProof[0:32]
    pubSignal2 := hexProof[32:64]

    hex1 := hex.EncodeToString(pubSignal1)
    hex2 := hex.EncodeToString(pubSignal2)


	signedAttributes, err := hex.DecodeString(documentSOD.SignedAttributes)
	if err != nil {
		log.WithError(err).Error("failed to decode signed attributes")
		jsonError = problems.BadRequest(validation.Errors{
			"signed_attributes": err,
		})
		return
	}

	encapsulatedContent, err := hex.DecodeString(documentSOD.EncapsulatedContent)
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

	slaveSignature, err := hex.DecodeString(documentSOD.Signature)
	if err != nil {
		log.WithError(err).Error("failed to decode slaveSignature")
		jsonError = problems.BadRequest(validation.Errors{
			"slaveSignature": err,
		})
		return
	}

	dg1Hash, err := utils.GetDataGroup(encapsulatedContent, 1)
	if err != nil {
		log.WithError(err).Error("failed to get data group 1")
		jsonError = append(jsonError, problems.BadRequest(validation.Errors{
			"encapsulated_content": errors.New("failed to get data group 1"),
		})...)
		return
	}

	if dg1Hash == nil {
		log.Error("data group 1 is missing")
		jsonError = problems.BadRequest(validation.Errors{
			"encapsulated_content": errors.New("data group 1 is missing"),
		})
		return
	}	

	proofDg1Decimal, ok := big.NewInt(0).SetString(hex2, 16)
	if !ok {
		log.Error("failed to convert proofDg1Decimal hex string to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofDg1Commitment, ok := big.NewInt(0).SetString(hex1, 16)
	if !ok {
		log.Error("failed to convert proofDg1Commitment hex string to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofDg1CommitmentBytes := proofDg1Commitment.FillBytes(make([]byte, 32))

	dg1Truncated := utils.TruncateDg1Hash(dg1Hash)

	if !bytes.Equal(dg1Truncated[:], proofDg1Decimal.FillBytes(make([]byte, 32))) {
		log.Error("proof contains foreign data group 1")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("proof contains foreign data group 1"),
		})
		return
	}

	saHashBytes, err := verifySod(signedAttributes, encapsulatedContent, slaveSignature, cert, &algorithmPair, verifierCfg)
	if err != nil {
		sodError := new(types.SodError)
		if !errors2.As(err, &sodError) {
			log.WithError(err).Error("failed to verify SOD")
			jsonError = append(jsonError, problems.InternalError())
			return
		}

		log.WithError(sodError.VerboseError).Error("failed to verify SOD")

		documentSOD.ErrorKind = sodError.KindPtr()
		documentSOD.Error = sodError.VerboseErrorPtr()

		if sodError.Details == nil {
			jsonError = append(jsonError, problems.InternalError())
			return
		}

		jsonError = problems.BadRequest(validation.Errors{
			sodError.Details.Kind.Field(): sodError.Details.Description,
		})
		return
	}	
	
	

	truncatedSignedAttributes, err := utils.ExtractFirstNBits(saHashBytes, 252)
	if err != nil {
		log.WithError(err).Error("failed to extract bits from signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}


	toBeHashed := []*big.Int{big.NewInt(0).SetBytes(utils.ReverseBits(truncatedSignedAttributes))}
	passportHash, err := poseidon.Hash(toBeHashed)
	if err != nil {
		log.WithError(err).Error("failed to hash signed attributes")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	passportHashBytes := passportHash.FillBytes(make([]byte, 32))

	dg15Hash, err := utils.GetDataGroup(encapsulatedContent, 15)
	if err != nil {
		log.WithError(err).Error("failed to get data group 15")
		jsonError = append(jsonError, problems.BadRequest(validation.Errors{
			"encapsulated_content": errors.New("failed to get data group 15"),
		})...)
		return
	}

	var extractedDg15 []byte
	if documentSOD.DG15 != nil {
		extractedDg15, err = hex.DecodeString(*documentSOD.DG15)
		if err != nil {
			log.WithError(err).Error("failed to decode dg15Hash")
			jsonError = append(jsonError, problems.BadRequest(validation.Errors{
				"dg15": errors.New("failed to decode dg15Hash"),
			})...)
			return
		}

		extractedDg15Hash := types.GeneralHash(algorithmPair.DgHashAlgorithm)
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
	verifierContract, ok := addressesCfg.Verifiers[algorithmPair.DgHashAlgorithm]
	if !ok {
		log.Errorf("No verifier contract found for hash algorithm %s", algorithmPair.DgHashAlgorithm)
		jsonError = append(jsonError, problems.InternalError())
		return
	}



	rawSignedData, err := utils.BuildSignedData(
		addressesCfg.RegistrationContract,
		verifierContract,
		[32]byte(passportHashBytes),
		[32]byte(proofDg1CommitmentBytes),
		passportPubkeyHash,
	)
	if err != nil {
		log.WithError(err).Error("failed to build signed data")
		jsonError = append(jsonError, problems.InternalError())
		return
	}


	signedData := bytes.TrimLeft(rawSignedData, "\x00")

	signature, err := crypto.Sign(utils.ToEthSignedMessageHash(crypto.Keccak256(signedData)), api.KeysConfig(r).SignatureKey)
	if err != nil {
		log.WithError(err).Error("failed to sign messageHash")
		jsonError = append(jsonError, problems.InternalError())
		return
	}
	alg := types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm).BitSize()

	decoded, decodingErr := base64.StdEncoding.DecodeString(req.Data.Attributes.ZkProof)
	if decodingErr != nil {
		log.WithError(err).Error("failed to decode base64")
        jsonError = append(jsonError, problems.BadRequest(validation.Errors{
            "zk_proof": errors.New("proof decoding failed"),
        })...)
		return
	}
	writingError := os.WriteFile(fmt.Sprintf("proof%s", requestID), decoded, 0644)
	if writingError != nil {
		log.WithError(err).Error("failed to write decoded base64")
        jsonError = append(jsonError, problems.InternalError())
		return
	}

	command := fmt.Sprintf("bb verify -s ultra_honk -k ./verification_keys/registerIdentityLight%d.vk -p ./proof%s -v &> cmd%s.txt", alg, requestID, requestID)
	RunCommand(command)

	content, err := os.ReadFile(fmt.Sprintf("cmd%s.txt", requestID))
    if err != nil {
		log.WithError(err).Error("failed to write decoded base64")
        jsonError = append(jsonError, problems.InternalError())
        return
    }
	verified := false
	if parts := strings.Split(string(content), "verified: "); len(parts) > 1 {
		verified = strings.TrimSpace(parts[1]) == "1"
	}

	if !verified {
		log.WithError(err).Error("invalid proof")
        jsonError = append(jsonError, problems.BadRequest(validation.Errors{
            "zk_proof": errors.New("invalid proof"),
        })...)
		return 
	}

	signature[64] += 27

	response = &resources.SignatureResponse{
		Data: resources.Signature{
			Key: resources.NewKeyInt64(0, resources.SIGNATURE),
			Attributes: resources.SignatureAttributes{
				PassportHash: hexutil.Encode(passportHashBytes),
				PublicKey:    hexutil.Encode(passportPubkeyHash[:]),
				Verifier:     *verifierContract,
				Signature:    hexutil.Encode(signature),
			},
		},
	}

}


func RunCommand(command string) (string, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	return stdoutBuf.String(), stderrBuf.String(), err
}