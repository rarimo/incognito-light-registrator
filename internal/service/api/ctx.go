package api

import (
	"context"
	"net/http"

	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"gitlab.com/distributed_lab/logan/v3"
)

type ctxKey int

const (
	logCtxKey ctxKey = iota
	verifierConfigKey
	documentSODQKey
	keysConfigKey
)

func CtxLog(entry *logan.Entry) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, logCtxKey, entry)
	}
}

func Log(r *http.Request) *logan.Entry {
	return r.Context().Value(logCtxKey).(*logan.Entry)
}

func CtxVerifierConfig(entry *config.VerifierConfig) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, verifierConfigKey, entry)
	}
}

func VerifierConfig(r *http.Request) *config.VerifierConfig {
	return r.Context().Value(verifierConfigKey).(*config.VerifierConfig)
}

func CtxDocumentSODQ(entry data.DocumentSODQ) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, documentSODQKey, entry)
	}
}

func DocumentSODQ(r *http.Request) data.DocumentSODQ {
	return r.Context().Value(documentSODQKey).(data.DocumentSODQ).New()
}

func CtxKeysConfig(entry config.KeysConfig) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, keysConfigKey, entry)
	}
}

func KeysConfig(r *http.Request) config.KeysConfig {
	return r.Context().Value(keysConfigKey).(config.KeysConfig)
}
