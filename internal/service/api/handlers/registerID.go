package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
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

	hexProof, err := base64.StdEncoding.DecodeString(req.Data.Attributes.ZkProof)
	if err != nil {
		log.WithError(err).Error("failed to decode base64")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return
	}
	contractABI, contractBin, err := GetContractArtifacts(alg)
	if err != nil {
		log.WithError(err).Error("failed to get contract artifacts")
		jsonError = append(jsonError, problems.InternalError())
		return
	}

	proofErr := VerifyProof(contractABI, contractBin, hex.EncodeToString(hexProof), log)
	if proofErr != nil {
		jsonError = proofErr
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

func GetContractArtifacts(algo int) (string, string, error) {
	abi := `[{"inputs":[],"name":"INVALID_VERIFICATION_KEY","type":"error"},{"inputs":[],"name":"MOD_EXP_FAILURE","type":"error"},{"inputs":[],"name":"OPENING_COMMITMENT_FAILED","type":"error"},{"inputs":[],"name":"PAIRING_FAILED","type":"error"},{"inputs":[],"name":"PAIRING_PREAMBLE_FAILED","type":"error"},{"inputs":[],"name":"POINT_NOT_ON_CURVE","type":"error"},{"inputs":[{"internalType":"uint256","name":"expected","type":"uint256"},{"internalType":"uint256","name":"actual","type":"uint256"}],"name":"PUBLIC_INPUT_COUNT_INVALID","type":"error"},{"inputs":[],"name":"PUBLIC_INPUT_GE_P","type":"error"},{"inputs":[],"name":"PUBLIC_INPUT_INVALID_BN128_G1_POINT","type":"error"},{"inputs":[],"name":"getVerificationKeyHash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"bytes","name":"_proof","type":"bytes"},{"internalType":"bytes32[]","name":"_publicInputs","type":"bytes32[]"}],"name":"verify","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]`
	filename := "./contract_artifacts/bin" + strconv.Itoa(algo) + ".hex"
	bin, err := readHexFile(filename)
	if err != nil {
		return "", "", err
	}
	return abi, bin, nil
}

func VerifyProof(contractABI string, contractBin string, proofHex string, log *logan.Entry) []*jsonapi.ErrorObject {
	var jsonError []*jsonapi.ErrorObject

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: GenerateKey")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: NewKeyedTransactorWithChainID")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}

	alloc := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 ETH
	}
	client := backends.NewSimulatedBackend(alloc, 8000000)
	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: parsedABI")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}

	nonce, err := client.PendingNonceAt(context.Background(), auth.From)
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: nonce")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: SuggestGasPrice")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}
	gasLimit := uint64(3000000)
	tx := ethTypes.NewContractCreation(nonce, big.NewInt(0), gasLimit, gasPrice, common.FromHex(contractBin))
	signedTx, err := ethTypes.SignTx(tx, ethTypes.LatestSignerForChainID(big.NewInt(1337)), privateKey)
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: signedTx")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: SendTransaction")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}
	client.Commit()

	receipt, err := client.TransactionReceipt(context.Background(), signedTx.Hash())
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: TransactionReceipt")
		jsonError = append(jsonError, problems.InternalError())
		return jsonError
	}

	contractAddress := receipt.ContractAddress

	caller := bind.NewBoundContract(contractAddress, parsedABI, client, client, client)

	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		log.WithError(err).Error("failed to decode proof hex")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return jsonError
	}
	var publicInputs [3][32]byte

	for i := 0; i < 3; i++ {
		start := i * 32
		end := start + 32
		copy(publicInputs[i][:], proofBytes[start:end])
	}
	proofBytes = proofBytes[96:]

	var results []interface{}
	results = make([]interface{}, 1)
	var ret bool
	results[0] = &ret

	err = caller.Call(nil, &results, "verify", proofBytes, publicInputs)
	if err != nil {
		log.WithError(err).Error("failed to simulate contract execution: Call")
		jsonError = problems.BadRequest(validation.Errors{
			"zk_proof": err,
		})
		return jsonError
	}

	if ret {
		log.Info("Valid proof provided")
		return nil
	}
	log.Error("invalid zk proof")
	jsonError = problems.BadRequest(validation.Errors{
		"zk_proof": fmt.Errorf("Invalid zk proof"),
	})
	return jsonError
}

func readHexFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	cleanStr := strings.TrimSpace(string(data))
	return cleanStr, nil
}
