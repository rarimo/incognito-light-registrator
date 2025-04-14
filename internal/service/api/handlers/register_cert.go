package handlers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/jsonapi"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/passport-identity-provider/internal/utils"

	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3/errors"
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

	err = validateCert(cert, cfg.MasterCerts, cfg.DisableTimeChecks, cfg.DisableNameChecks)
	if err != nil {
		log.WithError(err).Error("failed to validate certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	pubKey, err := extractPublicKey(cert.PublicKey)
	if err != nil {
		log.WithError(err).Error("failed to extract public key")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	pubKeyHash, err := hashPubKey(pubKey)
	if err != nil {
		log.WithError(err).Error("failed to hash public key")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	rawSignedData, err := utils.BuildSignedCertData([32]byte(pubKeyHash))
	if err != nil {
		log.WithError(err).Error("failed to build signed data")
		jsonError = append(jsonError, problems.InternalError())
		ape.RenderErr(w, jsonError...)
		return
	}

	signature, err := crypto.Sign(utils.ToEthSignedMessageHash(crypto.Keccak256(rawSignedData)), api.KeysConfig(r).SignatureKey)
	if err != nil {
		log.WithError(err).Error("failed to sign public key hash")
		jsonError = append(jsonError, problems.InternalError())
		ape.RenderErr(w, jsonError...)
		return
	}

	signature[64] += 27

	response = &resources.SignatureCertResponse{
		Data: resources.SignatureCert{
			Key: resources.NewKeyInt64(0, resources.SIGNATURE_CERT),
			Attributes: resources.SignatureCertAttributes{
				PublicKeyHash: hexutil.Encode(pubKeyHash[:]),
				Signature:     hexutil.Encode(signature),
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

func hashPubKey(pubKey any) ([32]byte, error) {
	var zeroHash [32]byte

	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		// ECDSA Key:
		// pubKey = Poseidon2(x mod 2^248, y mod 2^248)
		modulus := new(big.Int).Lsh(big.NewInt(1), 248) // 2^248

		xMod := new(big.Int).Mod(k.X, modulus)
		yMod := new(big.Int).Mod(k.Y, modulus)

		h, err := poseidon.Hash([]*big.Int{xMod, yMod})
		if err != nil {
			return zeroHash, err
		}
		return utils.BigIntTo32Bytes(h), nil
	case *rsa.PublicKey:
		// RSA Key:
		// pubKey = Poseidon5(200bit, 200bit, 200bit, 200bit, 224bit) = 1024 bits total
		N := k.N
		bitLen := N.BitLen()
		requiredBits := 200*4 + 224 // = 1024 bits total

		if bitLen < requiredBits {
			return zeroHash, errors.New("RSA modulus too small to extract required bits")
		}

		// Extract the top 1024 bits
		shift := bitLen - requiredBits
		topBits := new(big.Int).Rsh(N, uint(shift))

		// Split into chunks: 4 chunks of 200 bits + 1 chunk of 224 bits
		chunkSizes := []int{200, 200, 200, 200, 224}
		chunks := make([]*big.Int, len(chunkSizes))

		current := new(big.Int).Set(topBits)
		for i, size := range chunkSizes {
			mask := new(big.Int).Lsh(big.NewInt(1), uint(size))
			mask.Sub(mask, big.NewInt(1)) // mask = 2^size - 1

			chunk := new(big.Int).And(current, mask)
			chunks[len(chunkSizes)-1-i] = chunk // Fill in reverse order
			current.Rsh(current, uint(size))
		}

		h, err := poseidon.Hash(chunks)
		if err != nil {
			return zeroHash, err
		}
		return utils.BigIntTo32Bytes(h), nil
	default:
		return zeroHash, nil
	}
}
