package main

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Issuers  []string `envconfig:"ISSUERS" required:"true"`
	Audience string   `envconfig:"AUDIENCE" required:"true"`
	Subjects []string `envconfig:"SUBJECTS" required:"true"`

	LogLevel  string `envconfig:"LOG_LEVEL" default:"info"`
	LogPretty bool   `envconfig:"LOG_PRETTY" default:"false"`
	Port      int    `envconfig:"PORT" default:"8000"`
}

func MustParseConfig() Config {
	var c Config
	err := envconfig.Process("", &c)
	if err != nil {
		_ = envconfig.Usage("", &c)
		log.Fatal().Msg(err.Error())
	}

	initLogger(c)
	log.Info().Msg("Starting")
	log.Info().Int("Port", c.Port).Send()
	log.Info().Strs("ISSUER", c.Issuers).Send()
	log.Info().Str("AUDIENCE", c.Audience).Send()
	log.Info().Str("LOG_LEVEL", c.LogLevel).Send()
	log.Info().Bool("LOG_PRETTY", c.LogPretty).Send()
	log.Info().Strs("SUBJECTS", c.Subjects).Send()

	return c
}
