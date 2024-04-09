package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/sethvargo/go-envconfig"
)

type Options struct {
	Issuer    string   `env:"ISSUER, required"`
	Audience  string   `env:"AUDIENCE, required"`
	LogLevel  string   `env:"LOG_LEVEL, default=info"`
	LogPretty bool     `env:"LOG_PRETTY"`
	Subjects  []string `env:"SUBJECTS, required"`
}

func main() {
	ctx := context.Background()
	var opts Options
	err := envconfig.Process(ctx, &opts)
	initLogger(opts)

	log.Info().Msg("Starting")
	log.Info().Str("ISSUER", opts.Issuer).Send()
	log.Info().Str("AUDIENCE", opts.Audience).Send()
	log.Info().Str("LOG_LEVEL", opts.LogLevel).Send()
	log.Info().Bool("LOG_PRETTY", opts.LogPretty).Send()
	log.Info().Strs("SUBJECTS", opts.Subjects).Send()

	// Print any failures from proccessing ENV here,
	// se we can see available options
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	Run(ctx, opts)
}

func initLogger(opts Options) {
	logLevel, err := zerolog.ParseLevel(opts.LogLevel)
	if err != nil {
		logLevel = zerolog.InfoLevel
		log.Warn().Msgf("Invalid log level '%s', fallback to '%s'", opts.LogLevel, logLevel.String())
	}

	if logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel
	}

	var logWriter io.Writer = os.Stderr
	if opts.LogPretty {
		logWriter = &zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.TimeOnly}
	}

	logger := zerolog.New(logWriter).Level(logLevel).With().Timestamp().Logger()

	log.Logger = logger
	zerolog.DefaultContextLogger = &logger
}

func Run(ctx context.Context, opts Options) {

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		log.Fatal().Err(err).Str("issuer", opts.Issuer).Msg("Failed to create oidc provider")
	}

	oidcConfig := &oidc.Config{
		ClientID: opts.Audience,
	}
	verifier := provider.Verifier(oidcConfig)

	authHandler := AuthHandler(opts.Subjects, verifier)
	http.Handle("/auth", authHandler)

	log.Info().Msg("Listening on http://localhost:8000...")
	err = http.ListenAndServe(":8000", nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msgf("listen: %s", err)
	}

	log.Info().Msg("Server exiting")
}
