package http

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

// Мапа для хранения состояния отзыва refresh-токенов
var revokedTokens = make(map[string]bool)

// Server представляет HTTP-сервер
type Server struct {
	router *gin.Engine
	config Config
}

// Config представляет конфигурацию для HTTP-сервера
type Config struct {
	AccessSecret  []byte
	RefreshSecret []byte
	Port          string
}

// NewServer создает и возвращает новый HTTP-сервер с заданной конфигурацией
func NewServer(config Config) *Server {
	router := gin.Default()
	server := &Server{
		router: router,
		config: config,
	}

	router.GET("/login", server.handleLogin)
	router.GET("/logout", server.handleLogout)
	router.GET("/verify", server.handleVerify)

	return server
}

func (s *Server) Start() error {
	err := s.router.Run(":" + s.config.Port)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) handleLogin(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")

	// Проверка логина и пароля
	if !isValidCredentials(username, password) {
		c.String(http.StatusUnauthorized, "Неверный логин или пароль")
		return
	}

	refreshTokenValue := c.Query("refresh_token")
	if revokedTokens[refreshTokenValue] {
		c.String(http.StatusUnauthorized, "Refresh-токен невалидный.")
		return
	}

	// Создание access токена
	accessExp := time.Now().Add(5 * time.Minute)
	accessClaims := jwt.MapClaims{
		"username": username,
		"exp":      accessExp.Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessString, err := accessToken.SignedString(s.config.AccessSecret)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Создание refresh токена
	refreshExp := time.Now().Add(60 * time.Minute)
	refreshClaims := jwt.MapClaims{
		"username": username,
		"exp":      refreshExp.Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	refreshString, err := refreshToken.SignedString(s.config.RefreshSecret)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Установка токенов в виде cookie
	c.SetCookie("access_token", accessString, int(accessExp.Unix()), "/", "", false, true)
	c.SetCookie("refresh_token", refreshString, int(refreshExp.Unix()), "/", "", false, true)

	c.String(http.StatusOK, "Аутентификация успешна. Токены выданы.")
}

func (s *Server) handleVerify(c *gin.Context) {
	accessToken, err := c.Cookie("access_token")
	if err != nil {
		c.String(http.StatusUnauthorized, "Отсутствует access токен")
		return
	}

	// Проверка и верификация access токена
	accessClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(accessToken, accessClaims, func(token *jwt.Token) (interface{}, error) {
		return s.config.AccessSecret, nil
	})
	if err != nil {
		c.String(http.StatusUnauthorized, "Неверный access токен")
		return
	}

	// Проверка и обновление refresh токена, если он передан
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		refreshClaims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
			return s.config.RefreshSecret, nil
		})
		if err == nil && refreshClaims.VerifyExpiresAt(time.Now().Unix(), true) {
			// Создание нового access токена
			newAccessExp := time.Now().Add(5 * time.Minute)
			newAccessClaims := jwt.MapClaims{
				"username": accessClaims["username"],
				"exp":      newAccessExp.Unix(),
			}
			newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessClaims)
			newAccessString, err := newAccessToken.SignedString(s.config.AccessSecret)
			if err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}

			// Обновление токена в виде cookie
			c.SetCookie("access_token", newAccessString, int(newAccessExp.Unix()), "/", "", false, true)
		}
	}

	c.String(http.StatusOK, "Токены прошли верификацию и обновление, если необходимо.")
}

func (s *Server) handleLogout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.String(http.StatusUnauthorized, "Отсутствует refresh токен")
		return
	}

	// Проверка и верификация refresh токена
	refreshClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return s.config.RefreshSecret, nil
	})
	if err != nil {
		c.String(http.StatusUnauthorized, "Неверный refresh токен")
		return
	}

	// Пометка refresh-токена как невалидного
	revokedTokens[refreshToken] = true

	// Удаление refresh-токена из cookie
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)

	c.String(http.StatusOK, "Выход выполнен успешно. Refresh-токен помечен как невалидный.")
}

func isValidCredentials(username, password string) bool {
	// Фиктивный пользователь для тестирования
	fakeUsername := "admin"
	fakePassword := "password"
	fakeHashedPassword, err := bcrypt.GenerateFromPassword([]byte(fakePassword), bcrypt.DefaultCost)
	if err != nil {
		return false
	}

	if username != fakeUsername {
		return false
	}

	// Сравнение предоставленного пароля с хэшем фиктивного пароля
	err = bcrypt.CompareHashAndPassword(fakeHashedPassword, []byte(password))
	if err != nil {
		return false
	}

	return true
}
