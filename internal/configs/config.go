package configs

// Config представляет конфигурацию для HTTP-сервера
type Config struct {
	AccessSecret  []byte
	RefreshSecret []byte
	Port          string
}
