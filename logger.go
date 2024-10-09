package main

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/negroni"
)

func initLogger(opts Config) {
	logLevel, err := zerolog.ParseLevel(opts.LogLevel)
	if err != nil {
		logLevel = zerolog.InfoLevel
		log.Warn().Msgf("Invalid log level '%s', fallback to '%s'", opts.LogLevel, logLevel.String())
	}

	if logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel
	}
	opts.LogLevel = logLevel.String()

	var logWriter io.Writer = os.Stderr
	if opts.LogPretty {
		logWriter = &zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.TimeOnly}
	}

	zerolog.DurationFieldUnit = time.Millisecond
	logger := zerolog.New(logWriter).Level(logLevel).With().Timestamp().Logger()

	log.Logger = logger
	zerolog.DefaultContextLogger = &logger
}

func NewLoggingMiddleware() negroni.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
		metrics := httpsnoop.CaptureMetrics(next, writer, request)
		log.Info().
			Str("path", request.URL.Path).
			Str("referer", request.Referer()).
			Dur("duration", metrics.Duration).
			Int("status_code", metrics.Code).
			Int64("response_size", metrics.Written).
			Msg("Handled request")
	}
}
