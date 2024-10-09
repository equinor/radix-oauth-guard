package main

import (
	"net/http"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"github.com/urfave/negroni"
)

func NewZerologRequestIdMiddleware() negroni.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		logger := log.Ctx(r.Context()).With().Str("request_id", xid.New().String()).Logger()
		r = r.WithContext(logger.WithContext(r.Context()))

		next(w, r)
	}
}
