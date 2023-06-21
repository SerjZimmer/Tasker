package main

import (
	"fmt"
	"tasker/internal/adapters/http"
)

func main() {
	// Конфигурация HTTP-сервера
	config := http.Server{}.Config

	// Создание HTTP-сервера
	server := http.NewServer(config)

	// Запуск HTTP-сервера
	err := server.Start()
	if err != nil {
		fmt.Printf("Failed to start server: %v", err)
	}
}
