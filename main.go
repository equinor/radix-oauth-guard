package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/negroni"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGTERM, unix.SIGINT)
	defer cancel()

	config := MustParseConfig()

	authHandler, err := NewAuthHandler(config.Audience, config.Subjects, config.Issuers)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create auth handler")
	}
	router := NewRouter(authHandler)

	err = Serve(ctx, config.Port, router)
	log.Err(err).Msg("Terminated")
}

type RouteMapper func(mux *http.ServeMux)

func NewRouter(handlers ...RouteMapper) *negroni.Negroni {
	mux := http.NewServeMux()
	for _, handler := range handlers {
		handler(mux)
	}

	return negroni.New(
		NewZerologRequestIdMiddleware(),
		NewLoggingMiddleware(),
		negroni.Wrap(mux),
	)
}

func Serve(ctx context.Context, port int, router http.Handler) error {

	s := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf(":%d", port),
	}
	go func() {
		log.Ctx(ctx).Info().Msgf("Starting server on http://localhost:%d/", port)

		if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Ctx(ctx).Fatal().Msg(err.Error())
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	return s.Shutdown(shutdownCtx)
}
