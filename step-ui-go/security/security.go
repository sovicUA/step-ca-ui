package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Password ─────────────────────────────────────────────────────────────────

func HashPassword(pw string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		panic("bcrypt password hash failed: " + err.Error())
	}
	return string(hash)
}

func legacySHA256(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

func isLegacySHA256Hash(hash string) bool {
	if len(hash) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func VerifyPassword(pw, hash string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
	}
	if isLegacySHA256Hash(hash) {
		expected := legacySHA256(pw)
		return subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) == 1
	}
	return false
}

func NeedsPasswordRehash(hash string) bool {
	if isLegacySHA256Hash(hash) {
		return true
	}
	cost, err := bcrypt.Cost([]byte(hash))
	return err != nil || cost < bcrypt.DefaultCost
}

func ValidatePassword(pw string) (bool, string) {
	if len(pw) < 8 {
		return false, "Щонайменше 8 символів"
	}
	if len(pw) > 72 {
		return false, "Щонайбільше 72 символи"
	}
	hasDigit, hasLetter, hasSpecial := false, false, false
	for _, c := range pw {
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if strings.ContainsRune(`+!@#$%^&*()_-=[]{}|;:,.<>?`, c) {
			hasSpecial = true
		}
	}
	if !hasDigit {
		return false, "Потрібна хоча б одна цифра"
	}
	if !hasLetter {
		return false, "Потрібна хоча б одна літера"
	}
	if !hasSpecial {
		return false, "Потрібен хоча б один спецсимвол"
	}
	return true, ""
}

// ─── CSRF token ───────────────────────────────────────────────────────────────

func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

const (
	LimitCount  = 5
	LimitWindow = 5 * time.Minute
	BlockTime   = 15 * time.Minute
)

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var RL = &RateLimiter{attempts: make(map[string][]time.Time)}

func (r *RateLimiter) clean(ip string) {
	now := time.Now()
	var v []time.Time
	for _, t := range r.attempts[ip] {
		if now.Sub(t) < LimitWindow {
			v = append(v, t)
		}
	}
	r.attempts[ip] = v
}

func (r *RateLimiter) IsBlocked(ip string) bool {
	if ip == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clean(ip)
	return len(r.attempts[ip]) >= LimitCount
}

func (r *RateLimiter) Register(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clean(ip)
	r.attempts[ip] = append(r.attempts[ip], time.Now())
}

func (r *RateLimiter) Clear(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, ip)
}

func (r *RateLimiter) Left(ip string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clean(ip)
	n := LimitCount - len(r.attempts[ip])
	if n < 0 {
		return 0
	}
	return n
}

// ─── Secret Encryption (AES-256-GCM) ──────────────────────────────────────────

func deriveKey(secretKey string) []byte {
	h := sha256.Sum256([]byte(secretKey))
	return h[:]
}

// EncryptSecret encrypts plaintext using AES-256-GCM derived from master secretKey.
// Output format is hex(nonce || ciphertext).
func EncryptSecret(plaintext, masterSecret string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := deriveKey(masterSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(sealed), nil
}

// DecryptSecret decrypts hex(nonce || ciphertext) with AES-256-GCM.
func DecryptSecret(encoded, masterSecret string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	key := deriveKey(masterSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
