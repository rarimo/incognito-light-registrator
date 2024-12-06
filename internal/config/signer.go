package config

import (
	"crypto/ecdsa"

	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type SignerConfiger interface {
	SignerConfig() SignerConfig
}

func NewSignerConfiger(getter kv.Getter) SignerConfiger {
	return &Signer{
		getter: getter,
	}
}

type Signer struct {
	SignerOnce comfig.Once
	getter     kv.Getter
}

type SignerConfig struct {
	SignatureKey *ecdsa.PrivateKey `fig:"signature_key,required"`
}

func (e *Signer) SignerConfig() SignerConfig {
	return e.SignerOnce.Do(func() interface{} {
		var result SignerConfig

		err := figure.
			Out(&result).
			With(figure.EthereumHooks).
			From(kv.MustGetStringMap(e.getter, "Signer")).
			Please()
		if err != nil {
			panic(errors.Wrap(err, "failed to figure out Signer config"))
		}

		// get sensitive data from vault
		clientSignerCfg := NewVaultConfiger(e.getter).ClientSignerCredentialsConfig()
		if clientSignerCfg != nil {
			logan.New().Info("Vault is configured, using config from vault")
			result.SignatureKey = clientSignerCfg.SignatureKey
		}

		return result
	}).(SignerConfig)
}
