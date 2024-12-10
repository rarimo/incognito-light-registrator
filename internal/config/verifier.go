package config

import (
	"os"

	"github.com/rarimo/passport-identity-provider/internal/types"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type VerifierConfiger interface {
	VerifierConfig() *VerifierConfig
}

type VerifierConfig struct {
	VerificationKeys  map[types.HashAlgorithm][]byte
	MasterCerts       []byte
	DisableTimeChecks bool
	DisableNameChecks bool
}

type verifier struct {
	once   comfig.Once
	getter kv.Getter
}

func NewVerifierConfiger(getter kv.Getter) VerifierConfiger {
	return &verifier{
		getter: getter,
	}
}

func (v *verifier) VerifierConfig() *VerifierConfig {
	return v.once.Do(func() interface{} {
		newCfg := struct {
			VerificationKeysPaths map[string]string `fig:"verification_keys_paths,required"`
			MasterCertsPath       string            `fig:"master_certs_path,required"`
			DisableTimeChecks     bool              `fig:"disable_time_checks"`
			DisableNameChecks     bool              `fig:"disable_name_checks"`
		}{}

		err := figure.
			Out(&newCfg).
			With(figure.BaseHooks).
			From(kv.MustGetStringMap(v.getter, "verifier")).
			Please()
		if err != nil {
			panic(err)
		}

		verificationKeys := make(map[types.HashAlgorithm][]byte)
		for algo, path := range newCfg.VerificationKeysPaths {
			verificationKey, err := os.ReadFile(path)
			if err != nil {
				panic(err)
			}

			verificationKeys[types.HashAlgorithmFromString(algo)] = verificationKey
		}

		masterCerts, err := os.ReadFile(newCfg.MasterCertsPath)
		if err != nil {
			panic(err)
		}

		return &VerifierConfig{
			VerificationKeys:  verificationKeys,
			MasterCerts:       masterCerts,
			DisableTimeChecks: newCfg.DisableTimeChecks,
			DisableNameChecks: newCfg.DisableNameChecks,
		}
	}).(*VerifierConfig)
}
