package config

import (
	"context"
	"crypto/ecdsa"
	"log"
	"os"
	"reflect"

	vault "github.com/hashicorp/vault/api"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type VaultConfiger interface {
	VaultConfig() *VaultConfig
	ClientKeysCredentialsConfig() *ClientKeysCredentialsConfig
}

type VaultConfig struct {
	MountPath      string `json:"VAULT_MOUNT_PATH"`
	PrivateKeyPath string `json:"VAULT_PRIVATE_KEY_PATH"`
	SecretPath     string `json:"VAULT_SECRET_PATH"`
}

type ClientKeysCredentialsConfig struct {
	SignatureKey *ecdsa.PrivateKey `fig:"signature_key,required"`
}

func NewVaultConfiger(getter kv.Getter) VaultConfiger {
	return &vaultConfig{
		getter: getter,
	}
}

type vaultConfig struct {
	getter    kv.Getter
	once      comfig.Once
	vaultOnce comfig.Once
}

func (c *vaultConfig) VaultConfig() *VaultConfig {
	return c.once.Do(func() interface{} {
		var config VaultConfig

		VaultMountPath := os.Getenv("VAULT_MOUNT_PATH")
		VaultSecretPath := os.Getenv("VAULT_SECRET_PATH")

		if (VaultMountPath+VaultSecretPath != "") && (VaultMountPath == "" || VaultSecretPath == "") {
			logan.New().Error("Vault config is not complete, fallback to yaml config")
			return &config
		}

		config = VaultConfig{
			MountPath:  VaultMountPath,
			SecretPath: VaultSecretPath,
		}
		return &config
	}).(*VaultConfig)
}

func (c *vaultConfig) isEmptyOrIncomplete() bool {
	return c.VaultConfig().MountPath == "" || c.VaultConfig().SecretPath == ""
}

func (c *vaultConfig) ClientKeysCredentialsConfig() *ClientKeysCredentialsConfig {
	if c.isEmptyOrIncomplete() {
		return nil //fallback to yaml config follows
	}
	config := new(ClientKeysCredentialsConfig)

	err := c.getVaultSecret(c.VaultConfig().SecretPath, config)
	if err != nil {
		panic(err)
	}

	if config == nil ||
		config.SignatureKey == nil {
		return nil
	}

	return config
}

func (c *vaultConfig) getVaultSecret(key string, out interface{}) error {
	vaultClient := c.vaultClient()
	secret, err := vaultClient.KVv2(c.VaultConfig().MountPath).Get(context.Background(), key)
	if err != nil {
		return errors.Wrap(err, "failed to get secret data")
	}

	return figure.
		Out(out).
		With(figure.BaseHooks, figure.EthereumHooks, VaultHook).
		From(secret.Data).
		Please()
}

func (c *vaultConfig) vaultClient() *vault.Client {
	return c.vaultOnce.Do(func() interface{} {
		conf := vault.DefaultConfig()
		client, err := vault.NewClient(conf)
		if err != nil {
			log.Panicf("unable to initialize Vault client: %v", err)
		}

		return client
	}).(*vault.Client)
}

var VaultHook = figure.Hooks{ // TODO: move to figure BaseHooks
	"map[string]interface{}": func(value interface{}) (reflect.Value, error) {
		if value == nil {
			return reflect.Value{}, nil
		}

		var params map[string]interface{}
		switch s := value.(type) {
		case map[interface{}]interface{}:
			params = make(map[string]interface{})
			for key, value := range s {
				params[key.(string)] = value
			}
		case map[string]interface{}:
			params = s
		default:
			return reflect.Value{}, errors.New("unexpected type while figure map[string]interface{}")
		}

		return reflect.ValueOf(params), nil
	},
	"map[string]string": func(value interface{}) (reflect.Value, error) {
		if value == nil {
			return reflect.Value{}, nil
		}

		var params map[string]string
		switch s := value.(type) {
		case map[interface{}]interface{}:
			params = make(map[string]string)
			for key, value := range s {
				params[key.(string)] = value.(string)
			}
		case map[interface{}]string:
			params = make(map[string]string)
			for key, value := range s {
				params[key.(string)] = value
			}
		case map[string]interface{}:
			params = make(map[string]string)
			for key, value := range s {
				params[key] = value.(string)
			}
		case map[string]string:
			params = s

		default:
			return reflect.Value{}, errors.New("unexpected type while figure map[string]interface{}")
		}

		return reflect.ValueOf(params), nil
	},
}
