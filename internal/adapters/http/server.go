package http

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"sync"
	"tasker/internal/configs"
	"tasker/internal/domain"
)

// Мапа для хранения состояния отзыва refresh-токенов
var revokedTokens = make(map[string]bool)
var accessClaims = make(map[string]string)

// hadler - валидация моделей + полученных из http-сервер
// logic - валидация доступа, генерация токенов
// storage - получение моделей пользователей из мапы и пометка токенов как невалидные

// Server представляет HTTP-сервер
type Server struct {
	router *gin.Engine
	Config configs.Config
	auth   *domain.AuthService
	logout *domain.LogOutService

	mu sync.RWMutex // sync.Mutex
}

// NewServer создает и возвращает новый HTTP-сервер с заданной конфигурацией
func NewServer(config configs.Config) *Server {
	router := gin.Default()
	server := &Server{
		router: router,
		Config: config,
	}

	// middleware1 -> middleware2 -> handler -> midlerware3
	router.Use(func(c *gin.Context) {
		c.Next()
		if c.Request.Response.StatusCode != http.StatusOK {
			log.Println("error", c)
		}
	})

	router.GET("/login", server.handleLogin)
	router.GET("/logout", server.handleLogout)
	router.GET("/verify", server.handleVerify)

	return server
}

func (s *Server) Start() error {
	err := s.router.Run(":" + s.Config.Port)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) handleLogin(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")
	refreshTokenValue := c.Query("refresh_token")
	username, _, err := s.auth.Auth(username, password)
	if err != nil {
		c.String(http.StatusUnauthorized, "Неверный логин или пароль")
		fmt.Println(err)
		return
	}
	accessString, refreshString, err := s.auth.Refresh(revokedTokens, username, refreshTokenValue)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		fmt.Println(err)
		return
	} else {
		// Установка токенов в виде cookie
		c.SetCookie("access_token", accessString, int(accessExp.Unix()), "/", "", false, true)
		c.SetCookie("refresh_token", refreshString, int(refreshExp.Unix()), "/", "", false, true)
		c.String(http.StatusOK, "Аутентификация успешна. Токены выданы.")
	}
}

func (s *Server) handleVerify(c *gin.Context) {
	// HANDLER LOGIC
	accessToken, err := c.Cookie("access_token")
	if err != nil {
		c.String(http.StatusUnauthorized, "Отсутствует access токен")
		return
	}

	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.String(http.StatusUnauthorized, "Отсутствует refresh токен")
		return
	}

	// BUSINESS LOGIC
	err = s.auth.Verify(accessToken, refreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrTokenNotValid) {
			c.String(http.StatusUnauthorized, "Неверный access токен")
			return
		}
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	newAccessString, _, err := s.auth.Generate(accessClaims)
	if err != nil {
		// Обработка ошибки
		return
	}

	// Обновление токена в виде cookie
	c.SetCookie("access_token", newAccessString, int(newAccessExp.Unix()), "/", "", false, true)

	c.String(http.StatusOK, "Токены прошли верификацию и обновление, если необходимо.")
}

func (s *Server) handleLogout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.String(http.StatusUnauthorized, err.Error())
	}
	err = s.logout.CheckToken(refreshToken, revokedTokens)
	if err != nil {
		c.String(http.StatusUnauthorized, err.Error())
	}
	c.String(http.StatusOK, "Выход выполнен успешно. Refresh-токен помечен как невалидный.")
}
