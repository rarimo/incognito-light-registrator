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
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"github.com/rarimo/passport-identity-provider/internal/utils"

	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
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
	}
	verifierCfg := api.VerifierConfig(r)
	folderPath := verifierCfg.TmpFilePath
	proofFile := fmt.Sprintf("%sproof%s", folderPath, requestID)
	cmdFile := fmt.Sprintf("%scmd%s.txt", folderPath, requestID)

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

		if response != nil {
			ape.Render(w, response)
		}

		if err := os.Remove(proofFile); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Errorf("failed to remove file %s", proofFile)
		}
		if err := os.Remove(cmdFile); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Errorf("failed to remove file %s", cmdFile)
		}

		if jsonError != nil {
			ape.RenderErr(w, jsonError...)
			return
		}
	}()

	addressesCfg := api.AddressesConfig(r)
	alg := types.HashAlgorithmFromString(req.Data.Attributes.DocumentSod.HashAlgorithm).BitSize()

	dg1Hash, passportPubkeyHash, passportHashBytes, validateErr := validateAllExceptProof(
		addressesCfg,
		&documentSOD,
		log,
		algorithmPair,
		verifierCfg,
	)
	if validateErr != nil {
		jsonError = validateErr
		return
	}

	decoded, decodingErr := base64.StdEncoding.DecodeString(req.Data.Attributes.ZkProof)
	if decodingErr != nil {
		log.WithError(err).Error("failed to decode base64")
		jsonError = append(jsonError, problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("proof decoding failed"),
		})...)
		return
	}
	writingError := os.WriteFile(proofFile, decoded, 0644)
	if writingError != nil {
		log.WithError(writingError).Error("failed to write decoded base64")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	command := fmt.Sprintf("bb verify -s ultra_honk -k ./verification_keys/registerIdentityLight%d.vk -p %s -v &> %s", alg, proofFile, cmdFile)
	RunCommand(command)

	content, err := os.ReadFile(cmdFile)
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
		log.WithError(err).Error(string(content))
		jsonError = append(jsonError, problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("invalid proof"),
		})...)
		return
	}

	hexProof, err := base64.StdEncoding.DecodeString(req.Data.Attributes.ZkProof)
	if err != nil {
		log.WithError(err).Error("failed to decode base64")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return
	}

	proofDg1Decimal, ok := big.NewInt(0).SetString(hex.EncodeToString(hexProof[32:64]), 16)
	if !ok {
		log.Error("failed to convert proofDg1Decimal hex string to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofDg1Commitment, ok := big.NewInt(0).SetString(hex.EncodeToString(hexProof[0:32]), 16)
	if !ok {
		log.Error("failed to convert proofDg1Commitment hex string to big.Int")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofDg1CommitmentBytes := proofDg1Commitment.FillBytes(make([]byte, 32))

	dg1Truncated := utils.TruncateDg1Hash(dg1Hash)

	if !bytes.Equal(dg1Truncated[:], proofDg1Decimal.FillBytes(make([]byte, 32))) {
		log.WithFields(logan.F{
			"dg1Truncated":    hex.EncodeToString(dg1Truncated[:]),
			"proofDg1Decimal": hex.EncodeToString(proofDg1Decimal.FillBytes(make([]byte, 32))),
		}).Error("proof contains foreign data group 1")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": errors.New("proof contains foreign data group 1"),
		})
		return
	}

	verifierContract, ok := addressesCfg.VerifiersID[algorithmPair.DgHashAlgorithm]
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
