package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()

		// before request

		c.Next()

		// after request
		latency := time.Since(t)
		status := c.Writer.Status()

		log.Info().Dur("latency", latency).Int("status", status).Str("path", c.FullPath()).Msg("Handled")
	}
}
