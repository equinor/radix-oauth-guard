package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/equinor/radix-oauth-guard/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

type Options struct {
	Issuer       string `mapstructure:"issuer"`
	Audience     string `mapstructure:"audience"`
	SubjectRegex string `mapstructure:"subject_regex"`

	LogLevel  string `mapstructure:"log_level"`
	LogPretty bool   `mapstructure:"log_pretty"`
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

	Run(opts)
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

func Run(opts Options) {
	log.Info().Interface("options", opts).Msg("Starting...")

	subjectRegex, err := regexp.Compile(opts.SubjectRegex)
	if err != nil {
		log.Fatal().Str("regex", opts.SubjectRegex).Err(err).Msg("Failed to compile subject regex")
	}

	authoriation := middleware.NewAuthenticationFromConfig(opts.Issuer, opts.Audience, subjectRegex)
	http.Handle("POST /auth", authoriation.Handler())

	log.Info().Msg("Starting server on :8000...")
	err = http.ListenAndServe(":8000", nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msgf("listen: %s", err)
	}

	log.Info().Msg("Server exiting")
}
