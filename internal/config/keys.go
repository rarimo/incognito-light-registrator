package config

import (
	"crypto/ecdsa"

	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type KeysConfiger interface {
	KeysConfig() KeysConfig
}

func NewKeysConfiger(getter kv.Getter) KeysConfiger {
	return &Keys{
		getter: getter,
	}
}

type Keys struct {
	KeysOnce comfig.Once
	getter   kv.Getter
}

type KeysConfig struct {
	SignatureKey *ecdsa.PrivateKey `fig:"signature_key"`
}

func (e *Keys) KeysConfig() KeysConfig {
	return e.KeysOnce.Do(func() interface{} {
		var result KeysConfig

		err := figure.
			Out(&result).
			With(figure.EthereumHooks).
			From(kv.MustGetStringMap(e.getter, "Keys")).
			Please()
		if err != nil {
			panic(errors.Wrap(err, "failed to figure out Keys config"))
		}

		// get sensitive data from vault
		clientKeysCfg := NewVaultConfiger(e.getter).ClientKeysCredentialsConfig()
		if clientKeysCfg != nil {
			logan.New().Info("Vault is configured, using config from vault")
			result.SignatureKey = clientKeysCfg.SignatureKey
		}

		return result
	}).(KeysConfig)
}
