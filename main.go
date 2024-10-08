package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var signingKey = []byte("ReallyVerySecretKey!!@312") // Секретный ключ для подписи токенов
var refreshKey = []byte("AndAnotherSecretKey456$%^") // Секретный ключ для рефреш токенов

// Claims - структура для JWT claims
type Claims struct {
	UserIP string `json:"user_ip"`
	jwt.StandardClaims
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	userIP := getIPFromRequest(r) // Получаем IP из запроса
	accessToken, refreshToken, err := generateJWTs(userIP)
	if err != nil {
		http.Error(w, "Could not generate tokens", http.StatusInternalServerError)
		return
	}

	// Отправляем токены клиенту
	fmt.Fprintf(w, "Access token: %s\nRefresh token: %s", accessToken, refreshToken)
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
		Email        string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userIP := getIPFromRequest(r) // Получаем IP из запроса
	newAccessToken, newRefreshToken, err := refreshJWT(req.RefreshToken, userIP, req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Отправляем обновлённые токены клиенту
	fmt.Fprintf(w, "New Access token: %s\nNew Refresh token: %s", newAccessToken, newRefreshToken)
}

// Основная функция
func main() {
	http.HandleFunc("/auth/sign-up", signUpHandler)
	http.HandleFunc("/auth/refresh", refreshHandler)
	http.ListenAndServe(":8080", nil)

	// Получаем данные пользователя из флагов командной строки
	username := flag.String("username", "test_user6", "username")
	password := flag.String("pass", "qwerty", "password")
	flag.Parse()

	// Хэшируем пароль с солью
	hashedPassword, salt := hashSalt(*password)

	// Создаем пользователя
	if err := createUser(*username, hashedPassword); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Salt used for hashing: %s\n", salt)
}

// Функция генерации соли
func generateSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// Хэширование пароля с использованием SHA-1 и соли
func hashSalt(password string) (string, string) {
	salt, err := generateSalt()
	if err != nil {
		log.Fatal(err)
	}
	hash := sha1.New()
	hash.Write([]byte(password + salt)) // Добавляем соль к паролю
	return hex.EncodeToString(hash.Sum(nil)), salt
}

// Создание пользователя
func createUser(username, password string) error {
	reqBody := map[string]string{
		"username": username,
		"password": password,
	}

	resp, err := request(reqBody, "http://localhost:8001/auth/sign-up")
	if err != nil {
		return err
	}

	if resp["status"] == "error" {
		return errors.New(fmt.Sprintf("error occurred during user creation: %s", resp["message"]))
	}

	return nil
}

// Генерация Access и Refresh JWT токенов
func generateJWTs(userIP string) (string, string, error) {
	// Access токен (жизнь 15 минут)
	accessClaims := &Claims{
		UserIP: userIP,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Issuer:    "test-service",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	accessTokenString, err := accessToken.SignedString(signingKey)
	if err != nil {
		return "", "", err
	}

	// Refresh токен (жизнь 7 дней)
	refreshClaims := &Claims{
		UserIP: userIP,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
			Issuer:    "test-service",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(refreshKey)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// Рефреш токена с проверкой IP-адреса
func refreshJWT(refreshTokenString, currentIP, email string) (string, string, error) {
	// Парсим рефреш токен
	token, err := jwt.ParseWithClaims(refreshTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return refreshKey, nil
	})
	if err != nil {
		return "", "", err
	}

	// Извлекаем claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid refresh token")
	}

	// Проверяем, изменился ли IP
	if claims.UserIP != currentIP {
		if err := sendEmail(email, "Warning: IP address has changed during refresh operation!"); err != nil {
			return "", "", err
		}
	}

	// Генерируем новые токены
	return generateJWTs(currentIP)
}

// Отправка email при попытке взлома
func sendEmail(to, body string) error {
	from := "alert@example.com"
	pass := "yourpassword" // Убедитесь, что пароль безопасен

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Security Alert!\n\n" +
		body

	err := smtp.SendMail("smtp.example.com:587",
		smtp.PlainAuth("", from, pass, "smtp.example.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		return err
	}

	fmt.Println("Alert email sent to", to)
	return nil
}

// Общий запрос для отправки данных
func request(reqBody map[string]string, endpoint string) (map[string]interface{}, error) {
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		endpoint,
		"application/json",
		bytes.NewBuffer(reqBodyBytes),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// Получение IP-адреса клиента из запроса
func getIPFromRequest(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}
