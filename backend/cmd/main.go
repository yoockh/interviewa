package main

import (
	"context"
	"interviewa/config"
	"log/slog"
	"os"

	"github.com/go-playground/validator/v10"
)

var loggerOption = slog.HandlerOptions{AddSource: true}
var logger = slog.New(slog.NewJSONHandler(os.Stdout, &loggerOption))

func main() {
	ctx := context.Background()
	db := config.ConnectionDb()
	validate := validator.New()
	_ = ctx
	_ = db
	_ = validate

	logger.Info("Application started successfully")
}
