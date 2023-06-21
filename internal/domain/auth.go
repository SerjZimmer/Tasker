package domain

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"sync"
	"tasker/internal/configs"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	ErrTokenNotValid   = errors.New("token not valid")
	ErrLogoPassInvalid = errors.New("invalid login or password")
	ErrMissingToken    = errors.New("missing token")
)

type AuthService struct {
	config configs.Config
	mu     sync.RWMutex
}

func (s *AuthService) Verify(accessToken, refreshToken string) error {
	// Проверка и верификация access токена
	accessClaims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, accessClaims, func(token *jwt.Token) (interface{}, error) {
		return s.config.AccessSecret, nil
	})
	if err != nil {
		return fmt.Errorf("%w: %s", ErrTokenNotValid, err.Error()) // error("parse error") -> error("token not valid")
	}

	// Проверка и обновление refresh токена, если он передан

	refreshClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return s.config.RefreshSecret, nil
	})
	if refreshClaims.VerifyExpiresAt(time.Now().Unix(), false) {
		return fmt.Errorf("expired")
	}
	return nil
}

func (s *AuthService) Auth(username, password string) (string, string, error) {

	// Проверка логина и пароля
	if !isValidCredentials(username, password) {
		return "", "", ErrLogoPassInvalid
	}
	return username, password, nil
}
func (s *AuthService) Refresh(revokedTokens map[string]bool, username, refreshTokenValue string) (string, error) {

	s.mu.RLock()
	// defer s.mu.RUnlock()
	if revokedTokens[refreshTokenValue] {
		s.mu.RUnlock()
		return "", ErrTokenNotValid
	}
	s.mu.RUnlock()

	// Создание access токена
	accessExp := time.Now().Add(5 * time.Minute)
	accessClaims := jwt.MapClaims{
		"username": username,
		"exp":      accessExp.Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	_, err := accessToken.SignedString(s.config.AccessSecret)
	if err != nil {
		return "", err
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
		return "", err
	}
	return refreshString, nil
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
func (s *AuthService) Generate(accessClaims map[string]string) (string, string, error) {
	// Создание нового access токена
	newAccessExp := time.Now().Add(5 * time.Minute)
	newAccessClaims := jwt.MapClaims{
		"username": accessClaims["username"],
		"exp":      newAccessExp.Unix(),
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessClaims)
	newAccessString, err := newAccessToken.SignedString(s.config.AccessSecret)
	if err != nil {
		return "", "", err
	}
	return "", newAccessString, nil
}
