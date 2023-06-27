package logger

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"path/filepath"
	"time"
)

var Logger *zap.Logger

func Init() {
	// Путь к директории pmond
	pmondDir := "./"

	// Полный путь к папке logs в директории pmond
	logsDir := filepath.Join(pmondDir, "logs")

	// Проверяем наличие папки logs
	_, err := os.Stat(logsDir)
	if os.IsNotExist(err) {
		// Папка logs не существует, создаем ее
		err = os.MkdirAll(logsDir, os.ModePerm)
		if err != nil {
			log.Fatalf("Не удалось создать папку logs: %v", err)
		}
		log.Println("Папка logs успешно создана.")
	} else if err != nil {
		log.Fatalf("Ошибка при проверке папки logs: %v", err)
	}

	logFileNameFormat := "2006-01-02.log" // Формат: год-месяц-день
	currentTime := time.Now()
	currentDate := currentTime.Format(logFileNameFormat)
	logFilePath := fmt.Sprintf("./logs/%s", currentDate)

	// Проверка наличия файла и создание его при необходимости
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		_, err := os.Create(logFilePath)
		if err != nil {
			log.Fatal(err)
		}
	}

	encoderConfig := zapcore.EncoderConfig{
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeTime:     customTimeEncoder, // Функция для форматирования времени
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	cfg := zap.Config{
		Encoding:         "console",
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel), // Уровень логирования (можно изменить)
		OutputPaths:      []string{logFilePath},                   // Запись в stdout и файл
		ErrorOutputPaths: []string{logFilePath},                   // Запись ошибок в stdout и файл
		EncoderConfig:    encoderConfig,
	}

	logger, err := cfg.Build()
	if err != nil {
		log.Fatal(err)
	}

	zap.ReplaceGlobals(logger)

	Logger = logger
}

func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006/01/02 15:04:05.000"))
}
