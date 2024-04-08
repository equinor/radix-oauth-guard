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

	"github.com/spf13/viper"
)

type Options struct {
	Issuer       string   `mapstructure:"issuer"`
	Audience     string   `mapstructure:"audience"`
	SubjectRegex string   `mapstructure:"subject_regex"`
	LogLevel     string   `mapstructure:"log_level"`
	LogPretty    bool     `mapstructure:"log_pretty"`
	Subjects     []string `mapstructure:"subjects"`
}

func main() {
	var opts Options

	viper.SetConfigFile(".env")
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
	if err := viper.Unmarshal(&opts); err != nil {
		log.Fatal().Msg(err.Error())
	}

	initLogger(opts)

	Run(context.Background(), opts)
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
	log.Info().Interface("options", opts).Msg("Starting...")

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		log.Fatal().Err(err).Str("issuer", opts.Issuer).Msg("Failed to create oidc provider")
	}

	oidcConfig := &oidc.Config{
		ClientID: opts.Audience,
	}
	verifier := provider.Verifier(oidcConfig)

	authHandler := AuthHandler(opts.Subjects, verifier)
	http.Handle("POST /auth", authHandler)
	http.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("404 Not Found"))
	}))

	log.Info().Msg("Starting server on :8000...")
	err = http.ListenAndServe(":8000", nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msgf("listen: %s", err)
	}

	log.Info().Msg("Server exiting")
}
