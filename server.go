package main

import (
	"github.com/equinor/radix-oauth-guard/middleware"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func newGinEngine(authoriation *middleware.Authentication) *gin.Engine {

	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		log.Debug().
			Str("method", httpMethod).
			Str("path", absolutePath).
			Str("handler", handlerName).
			Int("handlers", nuHandlers).
			Msg("registered endpoint")
	}
	engine := gin.New()
	engine.RemoveExtraSlash = true
	engine.Use(
		middleware.Logger(),
		gin.Recovery(),
		authoriation.Gin(),
	)

	return engine
}
