package service

import (
	"github.com/go-chi/chi"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/handlers"
	"gitlab.com/distributed_lab/ape"
)

func (s *service) router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		ape.RecoverMiddleware(s.log),
		ape.LoganMiddleware(s.log),
		ape.CtxMiddleware(
			api.CtxLog(s.log),
			api.CtxVerifierConfig(s.cfg.VerifierConfig()),
		),
	)
	r.Route("/integrations/incognito-light-registrator", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Post("/verify-sod", handlers.VerifySod)
		})
	})

	return r
}
