package domain

import (
	"github.com/golang-jwt/jwt"
	"sync"
	"tasker/internal/configs"
)

type LogOutService struct {
	config configs.Config
	mu     sync.RWMutex
}

func (d *LogOutService) CheckToken(refreshToken string, revokedTokens map[string]bool) error {

	// Проверка и верификация refresh токена
	refreshClaims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return d.config.RefreshSecret, nil
	})
	if err != nil {
		return ErrTokenNotValid
	}

	// Пометка refresh-токена как невалидного
	d.mu.Lock()
	revokedTokens[refreshToken] = true
	d.mu.Unlock()

	// Удаление refresh-токена из cookie
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	return nil

}
