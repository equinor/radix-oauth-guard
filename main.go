package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/equinor/radix-oauth-guard/middleware"
	"github.com/gin-gonic/gin"
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

func Run(opts Options) {
	log.Info().Interface("options", opts).Msg("Starting...")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	subjectRegex, err := regexp.Compile(opts.SubjectRegex)
	if err != nil {
		log.Fatal().Str("regex", opts.SubjectRegex).Err(err).Msg("Failed to compile subject regex")
	}
	authoriation := middleware.NewAuthenticationFromConfig(opts.Issuer, opts.Audience, subjectRegex)

	engine := newGinEngine(authoriation)
	engine.Handle(http.MethodPost, "/auth", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	server := &http.Server{Addr: ":8000", Handler: engine}
	go func() {
		log.Info().Msg("Starting server on :8000...")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msgf("listen: %s", err)
		}
	}()

	<-ctx.Done()
	stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msgf("Server forced to shutdown: %s", err)
	}

	log.Info().Msg("Server exiting")
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
