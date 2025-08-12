package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/joho/godotenv"
)

type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "static/login.html")
		return
	}

	email := strings.ToLower(r.FormValue("email"))
	password := r.FormValue("password")

	payload := map[string]string{"email": email, "password": password}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to prepare request", http.StatusInternalServerError)
		return
	}

	apiKey := os.Getenv("LOGINRADIUS_API_KEY")
	if apiKey == "" {
		log.Fatal("LOGINRADIUS_API_KEY environment variable is not set")
	}

	loginURL := "https://api.loginradius.com/identity/v2/auth/login?apikey=" + apiKey

	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Login request failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println("Login failed:", string(bodyBytes))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var lrResp LoginResponse
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &lrResp)

	sessionID := randomString(32)
	saveSession(sessionID, lrResp.AccessToken)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	setNoCacheHeaders(w)
	http.ServeFile(w, r, "static/home.html")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session_id"); err == nil {
		deleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		token := getSessionToken(c.Value)
		if token == "" || !validateToken(token) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func validateToken(token string) bool {
	apiKey := os.Getenv("LOGINRADIUS_API_KEY")
	url := "https://api.loginradius.com/identity/v2/auth/access_token/validate?apikey=" + apiKey + "&access_token=" + token

	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "static/forgot.html")
		return
	}

	email := strings.ToLower(r.FormValue("email"))
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("LOGINRADIUS_API_KEY")
	resetURL := os.Getenv("RESET_PASSWORD_URL")
	emailTemplate := os.Getenv("EMAIL_TEMPLATE")

	if apiKey == "" || resetURL == "" {
		http.Error(w, "Server configuration missing", http.StatusInternalServerError)
		return
	}

	payload := map[string]string{
		"email": email,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to prepare request", http.StatusInternalServerError)
		return
	}

	apiEndpoint := "https://api.loginradius.com/identity/v2/auth/password"
	apiReqURL := fmt.Sprintf("%s?apikey=%s&resetPasswordUrl=%s&emailTemplate=%s", apiEndpoint, apiKey, url.QueryEscape(resetURL), emailTemplate)
	if emailTemplate != "" {
		apiReqURL += "&emailTemplate=" + url.QueryEscape(emailTemplate)
	}

	resp, err := http.Post(apiReqURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to send reset request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, "Error: "+string(body), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; chatset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("If an account exists for that email, a password reset link has been sent."))
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := r.URL.Query().Get("vtoken")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			http.Error(w, "Invalid or missing reset token", http.StatusBadRequest)
			return
		}

		tmpl, err := template.ParseFiles("static/reset.html")
		if err != nil {
			http.Error(w, "Failed to load reset page", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, map[string]string{"Token": token})
		return
	}

	token := r.FormValue("token")
	if token == "" {
		token = r.FormValue("vtoken")
	}
	newPassword := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if token == "" {
		http.Error(w, "Missing reset token", http.StatusBadRequest)
	}

	if newPassword == "" || confirmPassword == "" {
		http.Error(w, "Password fields cannot be empty", http.StatusBadRequest)
		return
	}

	if newPassword != confirmPassword {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("LOGINRADIUS_API_KEY")
	if apiKey == "" {
		http.Error(w, "Server configuration missing", http.StatusInternalServerError)
		return
	}

	payload := map[string]string{
		"resetToken": token,
		"password":   newPassword,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to prepare request", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("PUT",
		"https://api.loginradius.com/identity/v2/auth/password/reset?apikey="+apiKey,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Password reset error: %s", string(body))
		http.Error(w, "Password reset failed. The link may be expired or invalid.", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
