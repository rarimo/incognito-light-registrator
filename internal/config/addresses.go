package config

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/rarimo/passport-identity-provider/internal/types"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type AddressesConfiger interface {
	AddressesConfig() AddressesConfig
}

func NewAddressesConfiger(getter kv.Getter) AddressesConfiger {
	return &Addresses{
		getter: getter,
	}
}

type Addresses struct {
	addressesOnce comfig.Once
	getter        kv.Getter
}

type AddressesConfig struct {
	RegistrationContract *common.Address
	Verifiers            map[types.HashAlgorithm]*common.Address
	VerifiersID            map[types.HashAlgorithm]*common.Address
}

func (e *Addresses) AddressesConfig() AddressesConfig {
	return e.addressesOnce.Do(func() interface{} {
		newCfg := struct {
			RegistrationContract *common.Address   `fig:"registration_contract,required"`
			Verifiers            map[string]string `fig:"verifiers,required"`
			VerifiersID          map[string]string `fig:"verifiers,required"`
		}{}

		err := figure.
			Out(&newCfg).
			With(figure.BaseHooks, figure.EthereumHooks).
			From(kv.MustGetStringMap(e.getter, "addresses")).
			Please()
		if err != nil {
			panic(errors.Wrap(err, "failed to figure out addresses config"))
		}

		addresses := make(map[types.HashAlgorithm]*common.Address)
		for algo, address := range newCfg.Verifiers {
			address := common.HexToAddress(address)
			addresses[types.HashAlgorithmFromString(algo)] = &address
		}

		addressesID := make(map[types.HashAlgorithm]*common.Address)
		for algo, address := range newCfg.VerifiersID {
			address := common.HexToAddress(address)
			addressesID[types.HashAlgorithmFromString(algo)] = &address
		}

		return AddressesConfig{
			RegistrationContract: newCfg.RegistrationContract,
			Verifiers:            addresses,
			VerifiersID:          addressesID,
		}
	}).(AddressesConfig)
}
