package main

import (
	"flag"
	"fmt"
	"os"
	"tasker/internal/adapters/http"
	"tasker/internal/adapters/logger"
)

func init() {
	fs := flag.NewFlagSet("main", flag.ContinueOnError)
	var w = fs.String("w", "/usr/lib/tasker", "work directory")
	fs.String("log-level", "debug", "default log level")
	fs.Parse(os.Args[1:])
	os.Chdir(*w)
}

func main() {

	logger.Init()
	logger.Logger.Info("start tasker")
	// Конфигурация HTTP-сервера
	config := http.Server{}.Config

	// Создание HTTP-сервера
	server := http.NewServer(config)

	// Запуск HTTP-сервера
	err := server.Start()
	if err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to start server: %v", err))
	}
}
