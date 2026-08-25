package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

// === AUDIT LOG ===

type AuditAction string

const (
	ActionSecretSet     AuditAction = "secret.set"
	ActionSecretGet     AuditAction = "secret.get"
	ActionSecretDelete  AuditAction = "secret.delete"
	ActionTokenCreate   AuditAction = "token.create"
	ActionTokenRevoke   AuditAction = "token.revoke"
	ActionTokenConsume  AuditAction = "token.consume"
	ActionProjectCreate AuditAction = "project.create"
	ActionProjectDelete AuditAction = "project.delete"
)

type AuditEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Action    AuditAction `json:"action"`
	Target    string      `json:"target"`
	Actor     string      `json:"actor"`
	Details   string      `json:"details,omitempty"`
}

// AuditLogger — ring buffer для аудит-лога последних N операций.
type AuditLogger struct {
	mu      sync.Mutex
	entries []AuditEntry
	maxSize int
}

func NewAuditLogger(maxSize int) *AuditLogger {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &AuditLogger{
		entries: make([]AuditEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (a *AuditLogger) Log(action AuditAction, target, actor, details string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Target:    target,
		Actor:     actor,
		Details:   details,
	}
	if len(a.entries) >= a.maxSize {
		// Shift: remove oldest
		a.entries = append(a.entries[1:], entry)
	} else {
		a.entries = append(a.entries, entry)
	}
}

func (a *AuditLogger) List() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]AuditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// === MODELS ===

type Secret struct {
	Name      string    `json:"name" yaml:"-"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretToken — токен доступа к конкретному секрету
type SecretToken struct {
	SecretName string    `json:"secret_name" yaml:"secret_name"`
	Token      string    `json:"token" yaml:"token"` // SHA-256 hash токена
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
	ExpiresAt  time.Time `json:"expires_at" yaml:"expires_at"` // zero = never
	Revoked    bool      `json:"revoked" yaml:"revoked"`
}

// Project — группа секретов с изолированным доступом
type Project struct {
	ID        string    `json:"id" yaml:"-"`
	Name      string    `json:"name"`
	SecretIDs []string  `json:"secret_ids" yaml:"secret_ids"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
}

// ProjectToken — токен доступа к проекту (ко всем секретам проекта)
type ProjectToken struct {
	ProjectID string    `json:"project_id" yaml:"project_id"`
	Token     string    `json:"token" yaml:"token"` // SHA-256 hash
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"` // zero = never
	Revoked   bool      `json:"revoked" yaml:"revoked"`
}

// hashToken возвращает SHA-256 хеш токена в hex-формате
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// === STORE ===

type Store struct {
	mu      sync.RWMutex
	secrets map[string]*Secret
	sealed  bool
	sealedKey []byte // ChaCha20-Poly1305 key (32 bytes), generated at init if sealed mode enabled
	audit   *AuditLogger
}

// NewStore создаёт Store. Если password не пустой — включается sealed mode.
// audit может быть nil — тогда логирование не ведётся.
func NewStore(password string, audit ...*AuditLogger) *Store {
	s := &Store{
		secrets: make(map[string]*Secret),
	}
	if len(audit) > 0 {
		s.audit = audit[0]
	}
	if password != "" {
		s.sealed = true
		s.sealedKey = make([]byte, 32)
		if _, err := rand.Read(s.sealedKey); err != nil {
			// fallback: derive from password (less secure but works without crypto/rand)
			s.sealedKey = deriveKey(password, []byte("agent-vault-sealed-salt"))
		}
	}
	return s
}

// sealedEncrypt шифрует plaintext через ChaCha20-Poly1305 с sealedKey.
// Формат: [nonce(12)][ciphertext+tag].
func (s *Store) sealedEncrypt(plaintext string) (string, error) {
	if !s.sealed {
		return plaintext, nil
	}
	aead, err := chacha20poly1305.New(s.sealedKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, snapshotNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
	result := make([]byte, snapshotNonceLen+len(ciphertext))
	copy(result, nonce)
	copy(result[snapshotNonceLen:], ciphertext)
	return hex.EncodeToString(result), nil
}

// sealedDecrypt расшифровывает ciphertext через ChaCha20-Poly1305 с sealedKey.
func (s *Store) sealedDecrypt(ciphertext string) (string, error) {
	if !s.sealed {
		return ciphertext, nil
	}
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("sealed decode: %w", err)
	}
	if len(data) < snapshotNonceLen {
		return "", fmt.Errorf("sealed data too short")
	}
	aead, err := chacha20poly1305.New(s.sealedKey)
	if err != nil {
		return "", err
	}
	nonce := data[:snapshotNonceLen]
	ct := data[snapshotNonceLen:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("sealed decrypt: %w", err)
	}
	return string(plaintext), nil
}

func (s *Store) Set(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	encrypted, err := s.sealedEncrypt(value)
	if err != nil {
		log.Printf("[store] CRITICAL: seal failed for secret %s, aborting storage: %v", name, err)
		return
	}
	if existing, ok := s.secrets[name]; ok {
		existing.Value = encrypted
		existing.UpdatedAt = now
	} else {
		s.secrets[name] = &Secret{Name: name, Value: encrypted, UpdatedAt: now}
	}
	if s.audit != nil {
		s.audit.Log(ActionSecretSet, name, "store", "")
	}
}

var ErrSecretNotFound = errors.New("secret not found")

func (s *Store) Get(name string) (Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.secrets[name]
	if !ok {
		return Secret{}, ErrSecretNotFound
	}
	value, err := s.sealedDecrypt(sec.Value)
	if err != nil {
		return Secret{}, fmt.Errorf("decryption failed: %w", err)
	}
	// Return a copy to prevent mutation of internal state
	result := Secret{
		Name:      sec.Name,
		Value:     value,
		UpdatedAt: sec.UpdatedAt,
	}
	if s.audit != nil {
		s.audit.Log(ActionSecretGet, name, "store", "")
	}
	return result, nil
}

func (s *Store) Delete(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[name]; ok {
		delete(s.secrets, name)
		if s.audit != nil {
			s.audit.Log(ActionSecretDelete, name, "store", "")
		}
		return true
	}
	return false
}

func (s *Store) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = make(map[string]*Secret)
}

func (s *Store) List() ([]Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Secret, 0, len(s.secrets))
	for _, sec := range s.secrets {
		value, err := s.sealedDecrypt(sec.Value)
		if err != nil {
			return nil, fmt.Errorf("decryption failed for secret %s: %w", sec.Name, err)
		}
		result = append(result, Secret{
			Name:      sec.Name,
			Value:     value,
			UpdatedAt: sec.UpdatedAt,
		})
	}
	return result, nil
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.secrets)
}

// === CONFIG ===

type Config struct {
	mu             sync.RWMutex               `yaml:"-"`
	SnapshotPath   string                     `yaml:"snapshot_path"`
	ListenAddr     string                     `yaml:"listen_addr"`
	TGBotToken     string                     `yaml:"tg_bot_token"`
	TGAdminID      int64                      `yaml:"tg_admin_id"`
	AdminToken     string                     `yaml:"admin_token"`
	TokenTTLHours  int                        `yaml:"token_ttl_hours"`
	SecretTokens   map[string]*SecretToken    `yaml:"secret_tokens"`
	Projects       map[string]*Project        `yaml:"projects"`
	ProjectTokens  map[string]*ProjectToken   `yaml:"project_tokens"`
	UseTLS         bool                       `yaml:"use_tls"`
	TLSCertPath    string                     `yaml:"tls_cert_path"`
	TLSKeyPath     string                     `yaml:"tls_key_path"`
	AuditLog       *AuditLogger              `yaml:"-"`
	cleanupStop    chan struct{}             `yaml:"-"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		SnapshotPath:  "snapshot.enc",
		ListenAddr:    "127.0.0.1:8301",
		SecretTokens:  make(map[string]*SecretToken),
		Projects:      make(map[string]*Project),
		ProjectTokens: make(map[string]*ProjectToken),
		TokenTTLHours: 720,
		AuditLog:      NewAuditLogger(1000),
		cleanupStop:   make(chan struct{}),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.SecretTokens == nil {
		cfg.SecretTokens = make(map[string]*SecretToken)
	}
	if cfg.Projects == nil {
		cfg.Projects = make(map[string]*Project)
	}
	if cfg.ProjectTokens == nil {
		cfg.ProjectTokens = make(map[string]*ProjectToken)
	}
	if envAdmin := os.Getenv("VAULT_ADMIN_TOKEN"); envAdmin != "" {
		cfg.AdminToken = envAdmin
	}
	if envBot := os.Getenv("VAULT_BOT_TOKEN"); envBot != "" {
		cfg.TGBotToken = envBot
	}
	// Purge dead tokens on every startup
	cfg.mu.Lock()
	cfg.cleanupRevokedTokens()
	cfg.mu.Unlock()
	return cfg, nil
}

// startCleanupWorker запускает background goroutine для периодической очистки
// expired/revoked токенов. Останавливается по сигналу из cleanupStop.
func (c *Config) startCleanupWorker(interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				c.cleanupRevokedTokens()
				c.mu.Unlock()
			case <-c.cleanupStop:
				return
			}
		}
	}()
}

// stopCleanupWorker останавливает background cleanup goroutine.
func (c *Config) stopCleanupWorker() {
	close(c.cleanupStop)
}

func (c *Config) save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cleanupRevokedTokens удаляет отозванные и просроченные токены из конфига.
// ВЫЗЫВАТЬ ПОД config.mu.Lock() — метод не берёт мьютекс сам.
// Не встраиваем в save(), чтобы не ломать промежуточные состояния
// (например, revoke с последующей проверкой).
func (c *Config) cleanupRevokedTokens() {
	now := time.Now()
	for hash, st := range c.SecretTokens {
		if st.Revoked || (!st.ExpiresAt.IsZero() && now.After(st.ExpiresAt)) {
			delete(c.SecretTokens, hash)
		}
	}
	for hash, pt := range c.ProjectTokens {
		if pt.Revoked || (!pt.ExpiresAt.IsZero() && now.After(pt.ExpiresAt)) {
			delete(c.ProjectTokens, hash)
		}
	}
}

// removeSecretFromProjects удаляет секрет из SecretIDs всех проектов.
// Должен вызываться под config.mu.Lock().
func (c *Config) removeSecretFromProjects(name string) {
	for _, proj := range c.Projects {
		cleaned := make([]string, 0, len(proj.SecretIDs))
		for _, sid := range proj.SecretIDs {
			if sid != name {
				cleaned = append(cleaned, sid)
			}
		}
		proj.SecretIDs = cleaned
	}
}

// === CRYPTO ===

const (
	snapshotSaltLen  = 16
	snapshotNonceLen = 12
	argon2Time       = 3
	argon2Memory     = 64 * 1024
	argon2Threads    = 4
	argon2KeyLen     = 32
)

// deriveKey генерирует ключ из пароля через Argon2id
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// encryptSnapshot шифрует данные через ChaCha20-Poly1305
// Формат: [salt(16)][nonce(12)][ciphertext+tag]
func encryptSnapshot(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, snapshotSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	nonce := make([]byte, snapshotNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, snapshotSaltLen+snapshotNonceLen+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

// decryptSnapshot расшифровывает данные через ChaCha20-Poly1305
func decryptSnapshot(data []byte, password string) ([]byte, error) {
	if len(data) < snapshotSaltLen+snapshotNonceLen {
		return nil, fmt.Errorf("snapshot too short")
	}

	salt := data[:snapshotSaltLen]
	nonce := data[snapshotSaltLen : snapshotSaltLen+snapshotNonceLen]
	ciphertext := data[snapshotSaltLen+snapshotNonceLen:]

	key := deriveKey(password, salt)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

// === SERVER ===

// ipRateLimiter — простой rate limiter на основе IP
type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rateVisitor
	rate     int           // запросов за период
	period   time.Duration // период
}

type rateVisitor struct {
	count    int
	lastSeen time.Time
}

func newIPRateLimiter(rate int, period time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		visitors: make(map[string]*rateVisitor),
		rate:     rate,
		period:   period,
	}
	// Периодическая очистка старых записей
	go func() {
		for {
			time.Sleep(period)
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > period*2 {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, ok := rl.visitors[ip]
	if !ok || time.Since(v.lastSeen) > rl.period {
		rl.visitors[ip] = &rateVisitor{count: 1, lastSeen: time.Now()}
		return true
	}

	v.count++
	v.lastSeen = time.Now()
	return v.count <= rl.rate
}

type Server struct {
	store      *Store
	config     *Config
	configPath string
	srv        *http.Server
	startTime  time.Time
	limiter    *ipRateLimiter
}

func NewServer(s *Store, cfg *Config, path string) *Server {
	return &Server{
		store:      s,
		config:     cfg,
		configPath: path,
		startTime:  time.Now(),
		limiter:    newIPRateLimiter(10, time.Minute), // 10 req/min на IP
	}
}

func (s *Server) isAdmin(r *http.Request) bool {
	token := r.Header.Get("X-Vault-Token")
	if token != "" && s.config.AdminToken != "" {
		return subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AdminToken)) == 1
	}
	return false
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/secrets", s.handleSecrets)
	mux.HandleFunc("/secret/", s.handleSecretByName)
	mux.HandleFunc("/export", s.handleExport)
	mux.HandleFunc("/access/", s.handleAccess)
	mux.HandleFunc("/projects", s.handleProjects)
	mux.HandleFunc("/project/", s.handleProjectByID)
	mux.HandleFunc("/audit", s.handleAudit)
	mux.HandleFunc("/token/", s.handleToken)
	mux.HandleFunc("/project-tokens/", s.handleProjectTokens)

	handler := s.recoveryMiddleware(s.loggingMiddleware(mux))

	s.srv = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if s.config.UseTLS && s.config.TLSCertPath != "" && s.config.TLSKeyPath != "" {
		log.Printf("[api] listening on %s (TLS)", s.config.ListenAddr)
		return s.srv.ListenAndServeTLS(s.config.TLSCertPath, s.config.TLSKeyPath)
	}

	log.Printf("[api] listening on %s", s.config.ListenAddr)
	return s.srv.ListenAndServe()
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[http] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"status":  "ok",
		"secrets": s.store.Count(),
		"uptime":  time.Since(s.startTime).String(),
	})
}

// handleSecretByName — GET /secret/<name> — returns a single secret by name (admin token required).
// DELETE /secret/<name> — deletes a single secret and revokes its tokens.
func (s *Server) handleSecretByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/secret/")
	if name == "" {
		http.Error(w, "secret name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleSecretGet(w, r, name)
	case http.MethodDelete:
		s.handleSecretDelete(w, r, name)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSecretGet(w http.ResponseWriter, r *http.Request, name string) {
	if !s.isAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	secret, err := s.store.Get(name)
	if err == ErrSecretNotFound {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"name":       secret.Name,
		"value":      secret.Value,
		"updated_at": secret.UpdatedAt,
	})
}

func (s *Server) handleSecretDelete(w http.ResponseWriter, r *http.Request, name string) {
	if !s.isAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.store.Delete(name) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}

	// Revoke and delete all tokens for this secret, clean project references
	s.config.mu.Lock()
	for hash, st := range s.config.SecretTokens {
		if st.SecretName == name {
			delete(s.config.SecretTokens, hash)
		}
	}
	s.config.removeSecretFromProjects(name)
	if err := s.config.save(s.configPath); err != nil {
		log.Printf("[api] config save error: %v", err)
	}
	s.config.mu.Unlock()

	if s.config.AuditLog != nil {
		s.config.AuditLog.Log(ActionSecretDelete, name, "api", "DELETE /secret/"+name)
	}
	jsonResponse(w, map[string]string{"status": "deleted", "name": name})
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secrets, err := s.store.List()
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, secrets)

	case http.MethodPost:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Value == "" {
			http.Error(w, "name and value required", http.StatusBadRequest)
			return
		}
		s.store.Set(req.Name, req.Value)
		if s.config.AuditLog != nil {
			s.config.AuditLog.Log(ActionSecretSet, req.Name, "api", "POST /secrets")
		}
		jsonResponse(w, map[string]string{"status": "created", "name": req.Name})

	case http.MethodDelete:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.store.DeleteAll()
		jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secrets, err := s.store.List()
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	export := make(map[string]string)
	for _, s := range secrets {
		export[s.Name] = s.Value
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"vault-export.json\"")
	json.NewEncoder(w).Encode(export)
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting по IP (с поддержкой reverse proxy)
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	} else {
		// X-Forwarded-For может содержать список: "client, proxy1, proxy2"
		if idx := strings.IndexByte(ip, ','); idx != -1 {
			ip = strings.TrimSpace(ip[:idx])
		}
	}
	if !s.limiter.allow(ip) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	tokenStr := strings.TrimPrefix(r.URL.Path, "/access/")
	if tokenStr == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	tokenHash := hashToken(tokenStr)

	// 1) Secret-scoped токены — O(1) lookup
	s.config.mu.Lock()
	if st, ok := s.config.SecretTokens[tokenHash]; ok && !st.Revoked {
		if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
			delete(s.config.SecretTokens, tokenHash)
			s.config.save(s.configPath)
			s.config.mu.Unlock()
			http.Error(w, "token expired", http.StatusForbidden)
			return
		}
		secretName := st.SecretName
		// One-time token: delete first, then save — all under the same lock
		delete(s.config.SecretTokens, tokenHash)
		if err := s.config.save(s.configPath); err != nil {
			// Rollback: restore token on save failure
			s.config.SecretTokens[tokenHash] = st
			s.config.mu.Unlock()
			log.Printf("[api] config save error on token consume: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.config.mu.Unlock()

		if s.config.AuditLog != nil {
			s.config.AuditLog.Log(ActionTokenConsume, secretName, "api", "one-time")
		}
		secret, err := s.store.Get(secretName)
		if err == ErrSecretNotFound {

			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, map[string]interface{}{
			"name":       secret.Name,
			"value":      secret.Value,
			"updated_at": secret.UpdatedAt,
		})
		return
	}
	s.config.mu.Unlock()

	// 2) Project-scoped токены — O(1) lookup
	s.config.mu.Lock()
	if pt, ok := s.config.ProjectTokens[tokenHash]; ok && !pt.Revoked {
		if !pt.ExpiresAt.IsZero() && time.Now().After(pt.ExpiresAt) {
			delete(s.config.ProjectTokens, tokenHash)
			s.config.save(s.configPath)
			s.config.mu.Unlock()
			http.Error(w, "token expired", http.StatusForbidden)
			return
		}
		project, ok := s.config.Projects[pt.ProjectID]
		if !ok {
			s.config.mu.Unlock()
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		projectName := project.Name
		projectID := project.ID
		secretIDs := make([]string, len(project.SecretIDs))
		copy(secretIDs, project.SecretIDs)
		// One-time token: delete first, then save — all under the same lock
		delete(s.config.ProjectTokens, tokenHash)
		if err := s.config.save(s.configPath); err != nil {
			// Rollback: restore token on save failure
			s.config.ProjectTokens[tokenHash] = pt
			s.config.mu.Unlock()
			log.Printf("[api] config save error on project token consume: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.config.mu.Unlock()

		result := make(map[string]interface{})
		for _, sid := range secretIDs {
			sec, err := s.store.Get(sid)
				if err == nil {
				result[sid] = map[string]interface{}{
					"name":       sec.Name,
					"value":      sec.Value,
					"updated_at": sec.UpdatedAt,
				}
			}
		}
		jsonResponse(w, map[string]interface{}{
			"project":    projectName,
			"project_id": projectID,
			"secrets":    result,
		})
		return
	}
	s.config.mu.Unlock()

	http.Error(w, "invalid or revoked token", http.StatusForbidden)
}

// === PROJECT HANDLERS ===

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.RLock()
		projects := make([]*Project, 0, len(s.config.Projects))
		for _, p := range s.config.Projects {
			projects = append(projects, p)
		}
		s.config.mu.RUnlock()
		jsonResponse(w, projects)

	case http.MethodPost:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			SecretIDs []string `json:"secret_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.ID == "" || req.Name == "" {
			http.Error(w, "id and name required", http.StatusBadRequest)
			return
		}
		s.config.mu.Lock()
		if _, exists := s.config.Projects[req.ID]; exists {
			s.config.mu.Unlock()
			http.Error(w, "project already exists", http.StatusConflict)
			return
		}
		s.config.Projects[req.ID] = &Project{
			ID:        req.ID,
			Name:      req.Name,
			SecretIDs: req.SecretIDs,
			CreatedAt: time.Now(),
		}
		if err := s.config.save(s.configPath); err != nil {
			delete(s.config.Projects, req.ID)
			s.config.mu.Unlock()
			log.Printf("[api] config save error: %v", err)
			http.Error(w, "failed to save project", http.StatusInternalServerError)
			return
		}
		s.config.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		jsonResponse(w, map[string]string{"status": "created", "id": req.ID})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProjectByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/project/")
	if id == "" {
		http.Error(w, "project id required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.RLock()
		project, ok := s.config.Projects[id]
		s.config.mu.RUnlock()
		if !ok {
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		type projectView struct {
			*Project
			Secrets []Secret `json:"secrets"`
		}
		view := projectView{Project: project}
		for _, sid := range project.SecretIDs {
			sec, err := s.store.Get(sid)
				if err == nil {
				view.Secrets = append(view.Secrets, sec)
			}
		}
		jsonResponse(w, view)

	case http.MethodDelete:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.Lock()
		if _, ok := s.config.Projects[id]; !ok {
			s.config.mu.Unlock()
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		delete(s.config.Projects, id)
		for hash, pt := range s.config.ProjectTokens {
			if pt.ProjectID == id {
				delete(s.config.ProjectTokens, hash)
			}
		}
		if err := s.config.save(s.configPath); err != nil {
			log.Printf("[api] config save error: %v", err)
		}
		s.config.mu.Unlock()
		jsonResponse(w, map[string]string{"status": "deleted", "id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProjectTokens(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimPrefix(r.URL.Path, "/project-tokens/")
	if projectID == "" {
		http.Error(w, "project_id required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.RLock()
		defer s.config.mu.RUnlock()
		tokens := make([]*ProjectToken, 0)
		for _, pt := range s.config.ProjectTokens {
			if pt.ProjectID == projectID {
				tokens = append(tokens, pt)
			}
		}
		jsonResponse(w, tokens)

	case http.MethodPost:
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.RLock()
		if _, ok := s.config.Projects[projectID]; !ok {
			s.config.mu.RUnlock()
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}
		s.config.mu.RUnlock()

		token, err := randomToken(32)
		if err != nil {
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		var expires time.Time
		if s.config.TokenTTLHours > 0 {
			expires = now.Add(time.Duration(s.config.TokenTTLHours) * time.Hour)
		}
		tokenHash := hashToken(token)

		s.config.mu.Lock()
		s.config.ProjectTokens[tokenHash] = &ProjectToken{
			ProjectID: projectID,
			Token:     tokenHash,
			CreatedAt: now,
			ExpiresAt: expires,
		}
		if err := s.config.save(s.configPath); err != nil {
			log.Printf("[api] config save error: %v", err)
		}
		s.config.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		jsonResponse(w, map[string]interface{}{
			"token":      token,
			"project_id": projectID,
			"expires_at": expires,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	tokenHash := strings.TrimPrefix(r.URL.Path, "/token/")
	if tokenHash == "" {
		http.Error(w, "token hash required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		// Revoke token by hash
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.Lock()
		if st, ok := s.config.SecretTokens[tokenHash]; ok {
			st.Revoked = true
			s.config.cleanupRevokedTokens()
			if s.config.AuditLog != nil {
				s.config.AuditLog.Log(ActionTokenRevoke, st.SecretName, "api", "hash="+tokenHash[:8])
			}
			s.config.save(s.configPath)
			s.config.mu.Unlock()
			jsonResponse(w, map[string]string{"status": "revoked"})
			return
		}
		if pt, ok := s.config.ProjectTokens[tokenHash]; ok {
			pt.Revoked = true
			s.config.cleanupRevokedTokens()
			if s.config.AuditLog != nil {
				s.config.AuditLog.Log(ActionTokenRevoke, pt.ProjectID, "api", "hash="+tokenHash[:8])
			}
			s.config.save(s.configPath)
			s.config.mu.Unlock()
			jsonResponse(w, map[string]string{"status": "revoked"})
			return
		}
		s.config.mu.Unlock()
		http.Error(w, "token not found", http.StatusNotFound)

	case http.MethodPut:
		// Rotate: revoke old + create new for same target
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.config.mu.Lock()
		var targetName, targetType string
		if st, ok := s.config.SecretTokens[tokenHash]; ok && !st.Revoked {
			targetName = st.SecretName
			targetType = "secret"
			st.Revoked = true
		} else if pt, ok := s.config.ProjectTokens[tokenHash]; ok && !pt.Revoked {
			targetName = pt.ProjectID
			targetType = "project"
			pt.Revoked = true
		}
		if targetName == "" {
			s.config.mu.Unlock()
			http.Error(w, "token not found or already revoked", http.StatusNotFound)
			return
		}
		s.config.cleanupRevokedTokens()

		// Create new token
		newToken, err := randomToken(32)
		if err != nil {
			s.config.mu.Unlock()
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		var expires time.Time
		if s.config.TokenTTLHours > 0 {
			expires = now.Add(time.Duration(s.config.TokenTTLHours) * time.Hour)
		}
		newHash := hashToken(newToken)

		if targetType == "secret" {
			s.config.SecretTokens[newHash] = &SecretToken{
				SecretName: targetName, Token: newHash,
				CreatedAt: now, ExpiresAt: expires,
			}
		} else {
			s.config.ProjectTokens[newHash] = &ProjectToken{
				ProjectID: targetName, Token: newHash,
				CreatedAt: now, ExpiresAt: expires,
			}
		}
		if s.config.AuditLog != nil {
			s.config.AuditLog.Log(ActionTokenCreate, targetName, "api", "rotated from "+tokenHash[:8])
		}
		s.config.save(s.configPath)
		s.config.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		jsonResponse(w, map[string]interface{}{
			"token":      newToken,
			"expires_at": expires,
			"rotated":    true,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.config.AuditLog == nil {
		jsonResponse(w, []AuditEntry{})
		return
	}
	jsonResponse(w, s.config.AuditLog.List())
}

// === BOT INTERFACE ===

// botAPI — минимальный интерфейс для тестирования
type botAPI interface {
	Send(c tgbotapi.Chattable) (tgbotapi.Message, error)
	Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error)
}

// === BOT ===

const (
	stateWaitingName              = "waiting_name"
	stateWaitingValue             = "waiting_value"
	stateWaitingProjectID         = "waiting_project_id"
	stateWaitingProjectName       = "waiting_project_name"
	stateWaitingProjectSecrets    = "waiting_project_secrets"
	stateWaitingAddSecretName     = "waiting_add_secret_name"
	stateWaitingReplaceSecrets    = "waiting_replace_secrets"
)

type session struct {
	state             string
	name              string
	value             string
	projectID         string
	projectName       string
	projectSecrets    []string
	addSecretProjectID string
	updatedAt         time.Time
}

type Bot struct {
	api        botAPI
	store      *Store
	config     *Config
	configPath string
	sessions   map[int64]*session
	mu         sync.RWMutex
}

func NewBot(api botAPI, store *Store, cfg *Config, path string) *Bot {
	return &Bot{
		api:        api,
		store:      store,
		config:     cfg,
		configPath: path,
		sessions:   make(map[int64]*session),
	}
}

const sessionTTL = 30 * time.Minute

func (b *Bot) getSession(chatID int64) *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[chatID]; ok {
		if time.Since(s.updatedAt) > sessionTTL {
			// Session expired — reset
			s = &session{updatedAt: time.Now()}
			b.sessions[chatID] = s
		}
		return s
	}
	s := &session{updatedAt: time.Now()}
	b.sessions[chatID] = s
	return s
}

func (b *Bot) resetSession(chatID int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, chatID)
}

// startSessionCleaner запускает фоновую горутину для очистки истёкших FSM-сессий.
func (b *Bot) startSessionCleaner(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.mu.Lock()
				for id, s := range b.sessions {
					if time.Since(s.updatedAt) > sessionTTL {
						delete(b.sessions, id)
					}
				}
				b.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func sendWithMenu(bot botAPI, chatID int64, text string, kb tgbotapi.InlineKeyboardMarkup) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "HTML"
	msg.ReplyMarkup = kb
	if _, err := bot.Send(msg); err != nil {
		log.Printf("[bot] send error: %v | text: %q", err, text)
	}
}

func sendText(bot botAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	if _, err := bot.Send(msg); err != nil {
		log.Printf("[bot] text error: %v", err)
	}
}

func escapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func mainMenuKB() tgbotapi.InlineKeyboardMarkup {
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("➕ Создать", "create"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📋 Секреты", "list"),
			tgbotapi.NewInlineKeyboardButtonData("📁 Проекты", "projects"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🗑 Удалить секреты", "wipe_secrets"),
			tgbotapi.NewInlineKeyboardButtonData("🚫 Удалить токены", "wipe_tokens"),
		),
	)
}

func confirmKB(yesData, noData string) tgbotapi.InlineKeyboardMarkup {
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Да", yesData),
			tgbotapi.NewInlineKeyboardButtonData("❌ Нет", noData),
		),
	)
}

func cancelKB() tgbotapi.InlineKeyboardMarkup {
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Отмена", "cancel"),
		),
	)
}

func (b *Bot) sendMainMenu(chatID int64) {
	b.resetSession(chatID)
	secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
	text := fmt.Sprintf("🔐 <b>Lab Vault</b>\n\n📋 Секретов: %d\n\nВыберите действие:", len(secrets))
	sendWithMenu(b.api, chatID, text, mainMenuKB())
}

func randomToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// === CALLBACKS ===

func (b *Bot) handleCallback(cb *tgbotapi.CallbackQuery) {
	if cb.From.ID != b.config.TGAdminID {
		log.Printf("[bot] unauthorized callback from %d", cb.From.ID)
		b.api.Request(tgbotapi.NewCallback(cb.ID, "Unauthorized"))
		return
	}
	chatID := cb.Message.Chat.ID
	data := cb.Data
	if _, err := b.api.Request(tgbotapi.NewCallback(cb.ID, "")); err != nil {
		log.Printf("[bot] callback answer error: %v", err)
	}

	switch {
	// --- Main menu ---
	case data == "create":
		b.getSession(chatID).state = stateWaitingName
		sendWithMenu(b.api, chatID, "➕ <b>Создание секрета</b>\n\nШаг 1/2: Введите имя секрета\n\n<i>Пример: smtp_pass</i>\n\nили /cancel для отмены", cancelKB())

	case data == "list":
		b.sendSecretList(chatID)

	case data == "wipe_secrets":
		sendWithMenu(b.api, chatID,
			"☠️ <b>Удалить все секреты?</b>\n\nЭто действие необратимо!\nВсе секреты будут потеряны.",
			confirmKB("wipe_secrets_yes", "cancel"))

	case data == "wipe_tokens":
		sendWithMenu(b.api, chatID,
			"🚫 <b>Удалить все токены?</b>\n\nВсе существующие токены доступа будут отозваны.",
			confirmKB("wipe_tokens_yes", "cancel"))

	case data == "wipe_tokens_yes":
		b.config.mu.Lock()
		b.config.SecretTokens = make(map[string]*SecretToken)
		b.config.ProjectTokens = make(map[string]*ProjectToken)
		if err := b.config.save(b.configPath); err != nil {
			log.Printf("[bot] config save error: %v", err)
		}
		b.config.mu.Unlock()
		sendWithMenu(b.api, chatID, "🚫 Все токены удалены", mainMenuKB())

	case data == "wipe_secrets_yes":
		b.store.DeleteAll()
		sendWithMenu(b.api, chatID, "☠️ Все секреты удалены", mainMenuKB())

	// --- Projects ---
	case data == "projects":
		b.sendProjectList(chatID)

	case data == "project_create":
		b.getSession(chatID).state = stateWaitingProjectID
		sendWithMenu(b.api, chatID, "📁 <b>Создание проекта</b>\n\nШаг 1/3: Введите ID проекта\n\n<i>Пример: myapp-prod</i>\n\nили /cancel для отмены", cancelKB())

	case strings.HasPrefix(data, "project_view:"):
		id := strings.TrimPrefix(data, "project_view:")
		b.sendProjectView(chatID, id)

	case strings.HasPrefix(data, "project_token:"):
		id := strings.TrimPrefix(data, "project_token:")
		b.createProjectToken(chatID, id)

	case strings.HasPrefix(data, "project_delete:"):
		id := strings.TrimPrefix(data, "project_delete:")
		b.deleteProject(chatID, id)

	case strings.HasPrefix(data, "project_add_secret:"):
		id := strings.TrimPrefix(data, "project_add_secret:")
		sess := b.getSession(chatID)
		sess.addSecretProjectID = id
		sess.state = stateWaitingAddSecretName
		secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
		var secretNames []string
		for _, s := range secrets {
			secretNames = append(secretNames, s.Name)
		}
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("➕ <b>Добавить секрет в проект</b>\n\nВведите имя секрета:\n\nДоступные:\n%s",
				escapeHTML(strings.Join(secretNames, ", "))),
			cancelKB())

	case strings.HasPrefix(data, "project_replace_secrets:"):
		id := strings.TrimPrefix(data, "project_replace_secrets:")
		sess := b.getSession(chatID)
		sess.projectID = id
		sess.state = stateWaitingReplaceSecrets
		b.config.mu.RLock()
		project, ok := b.config.Projects[id]
		b.config.mu.RUnlock()
		if !ok {
			sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
			break
		}
		secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
		var secretNames []string
		for _, s := range secrets {
			secretNames = append(secretNames, s.Name)
		}
		var current []string
		for _, sid := range project.SecretIDs {
			current = append(current, sid)
		}
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("✏️ <b>Заменить секреты проекта %s</b>\n\nТекущие: %s\n\nВведите новые имена секретов через запятую:\n\nДоступные:\n%s",
				escapeHTML(project.Name), escapeHTML(strings.Join(current, ", ")), escapeHTML(strings.Join(secretNames, ", "))),
			cancelKB())

	case data == "cancel":
		b.sendMainMenu(chatID)

	// --- Secret views ---
	case strings.HasPrefix(data, "view:"):
		name := strings.TrimPrefix(data, "view:")
		b.sendSecretView(chatID, name)

	case strings.HasPrefix(data, "token:"):
		name := strings.TrimPrefix(data, "token:")
		b.createSecretToken(chatID, name)

	case strings.HasPrefix(data, "revoke:"):
		name := strings.TrimPrefix(data, "revoke:")
		b.revokeAllTokensForSecret(chatID, name)

	case strings.HasPrefix(data, "delete:"):
		name := strings.TrimPrefix(data, "delete:")
		b.deleteSecret(chatID, name)

	case data == "export":
		b.sendExport(chatID)

	case data == "back":
		b.sendSecretList(chatID)
	}
}

// === SECRET LIST ===

func (b *Bot) sendSecretList(chatID int64) {
	secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
	if len(secrets) == 0 {
		sendWithMenu(b.api, chatID, "📭 Секретов нет\n\nСоздайте первый секрет:", mainMenuKB())
		return
	}

	var rows [][]tgbotapi.InlineKeyboardButton
	for _, s := range secrets {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔒 "+s.Name, "view:"+s.Name),
		))
	}
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("📦 Экспорт", "export"),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("◀️ Назад", "cancel"),
	))
	text := fmt.Sprintf("📋 <b>Секреты</b> (%d)\n\nВыберите секрет:", len(secrets))
	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(rows...))
}

// === SECRET VIEW ===

func (b *Bot) sendSecretView(chatID int64, name string) {
	secret, err := b.store.Get(name)
		if err == ErrSecretNotFound {
		sendWithMenu(b.api, chatID, "⚠️ Секрет не найден", mainMenuKB())
		return
	}

	// Count active tokens for this secret
	b.config.mu.RLock()
	tokenCount := 0
	for _, st := range b.config.SecretTokens {
		if st.SecretName == name && !st.Revoked && (st.ExpiresAt.IsZero() || time.Now().Before(st.ExpiresAt)) {
			tokenCount++
		}
	}
	b.config.mu.RUnlock()

	text := fmt.Sprintf("🔒 <b>%s</b>\n\nЗначение:\n<pre>%s</pre>\n\n📅 Обновлён: %s\n🔑 Активных токенов: %d",
		escapeHTML(secret.Name),
		escapeHTML(secret.Value),
		escapeHTML(secret.UpdatedAt.Format("02.01.2006 15:04")),
		tokenCount)

	var rows [][]tgbotapi.InlineKeyboardButton
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔑 Создать токен", "token:"+name),
	))
	if tokenCount > 0 {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🚫 Отозвать все токены", "revoke:"+name),
		))
	}
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🗑 Удалить секрет", "delete:"+name),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("◀️ К списку", "back"),
	))

	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(rows...))
}

// === CREATE TOKEN ===

func (b *Bot) createSecretToken(chatID int64, name string) {
	_, err := b.store.Get(name)
	if err != nil {
		sendWithMenu(b.api, chatID, "⚠️ Секрет не найден", mainMenuKB())
		return
	}

	token, err := randomToken(32)
	if err != nil {
		sendWithMenu(b.api, chatID, "⚠️ Ошибка генерации токена", mainMenuKB())
		return
	}

	now := time.Now()
	var expires time.Time
	if b.config.TokenTTLHours > 0 {
		expires = now.Add(time.Duration(b.config.TokenTTLHours) * time.Hour)
	}

	tokenHash := hashToken(token)

	b.config.mu.Lock()
	b.config.SecretTokens[tokenHash] = &SecretToken{
		SecretName: name,
		Token:      tokenHash,
		CreatedAt:  now,
		ExpiresAt:  expires,
		Revoked:    false,
	}
	if err := b.config.save(b.configPath); err != nil {
		log.Printf("[bot] config save error: %v", err)
	}
	if b.config.AuditLog != nil {
		b.config.AuditLog.Log(ActionTokenCreate, name, "bot", "")
	}
	b.config.mu.Unlock()

	ttlStr := "∞"
	if !expires.IsZero() {
		ttlStr = escapeHTML(expires.Format("02.01.2006 15:04"))
	}

	addr := b.config.ListenAddr
	text := fmt.Sprintf("🔑 <b>Токен для %s</b>\n\n<code>%s</code>\n\n⏳ TTL: %s\n\ncurl-команда:\n<pre>curl -s http://%s/access/%s</pre>",
		escapeHTML(name), token, ttlStr, addr, token)

	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("◀️ К секрету", "view:"+name),
		),
	))
}

// === REVOKE ALL TOKENS FOR SECRET ===

func (b *Bot) revokeAllTokensForSecret(chatID int64, name string) {
	b.config.mu.Lock()
	revoked := 0
	for _, st := range b.config.SecretTokens {
		if st.SecretName == name {
			st.Revoked = true
			revoked++
		}
	}
	b.config.cleanupRevokedTokens()
	if b.config.AuditLog != nil {
		b.config.AuditLog.Log(ActionTokenRevoke, name, "bot", fmt.Sprintf("revoked=%d", revoked))
	}
	if err := b.config.save(b.configPath); err != nil {
		log.Printf("[bot] config save error: %v", err)
	}
	b.config.mu.Unlock()

	if revoked > 0 {
		sendWithMenu(b.api, chatID, fmt.Sprintf("🚫 Отозвано токенов: %d", revoked), mainMenuKB())
	} else {
		sendWithMenu(b.api, chatID, "⚠️ Токены не найдены", mainMenuKB())
	}
}

// === DELETE SECRET ===

func (b *Bot) deleteSecret(chatID int64, name string) {
	if b.store.Delete(name) {
		// Also revoke and delete all tokens for this secret, clean project references
		b.config.mu.Lock()
		for hash, st := range b.config.SecretTokens {
			if st.SecretName == name {
				delete(b.config.SecretTokens, hash)
			}
		}
		b.config.removeSecretFromProjects(name)
		if err := b.config.save(b.configPath); err != nil {
			log.Printf("[bot] config save error: %v", err)
		}
		b.config.mu.Unlock()
		sendWithMenu(b.api, chatID, fmt.Sprintf("🗑 <b>%s</b> удалён", escapeHTML(name)), mainMenuKB())
	} else {
		sendWithMenu(b.api, chatID, "⚠️ Секрет не найден", mainMenuKB())
	}
}

// === EXPORT ===

func (b *Bot) sendExport(chatID int64) {
	secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
	if len(secrets) == 0 {
		sendWithMenu(b.api, chatID, "📭 Нечего экспортировать", mainMenuKB())
		return
	}

	export := make(map[string]string)
	for _, s := range secrets {
		export[s.Name] = s.Value
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		sendWithMenu(b.api, chatID, "⚠️ Ошибка экспорта", mainMenuKB())
		return
	}

	// Split into chunks if too big (Telegram limit 4096)
	text := "📦 <b>Экспорт секретов</b>\n\n<pre>"
	if len(data) > 3000 {
		text += string(data[:3000]) + "\n... (truncated)"
	} else {
		text += string(data)
	}
	text += "</pre>"

	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("◀️ К списку", "back"),
		),
	))
}

// === PROJECT BOT METHODS ===

func (b *Bot) sendProjectList(chatID int64) {
	b.config.mu.RLock()
	projects := make([]*Project, 0, len(b.config.Projects))
	for _, p := range b.config.Projects {
		projects = append(projects, p)
	}
	b.config.mu.RUnlock()

	if len(projects) == 0 {
		sendWithMenu(b.api, chatID, "📭 Проектов нет\n\nСоздайте первый проект:", mainMenuKB())
		return
	}

	var rows [][]tgbotapi.InlineKeyboardButton
	for _, p := range projects {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📁 "+p.Name, "project_view:"+p.ID),
		))
	}
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("➕ Создать проект", "project_create"),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("◀️ Назад", "cancel"),
	))
	text := fmt.Sprintf("📁 <b>Проекты</b> (%d)\n\nВыберите проект:", len(projects))
	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(rows...))
}

func (b *Bot) sendProjectView(chatID int64, id string) {
	b.config.mu.RLock()
	project, ok := b.config.Projects[id]
	if !ok {
		b.config.mu.RUnlock()
		sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
		return
	}
	tokenCount := 0
	for _, pt := range b.config.ProjectTokens {
		if pt.ProjectID == id && !pt.Revoked && (pt.ExpiresAt.IsZero() || time.Now().Before(pt.ExpiresAt)) {
			tokenCount++
		}
	}
	// Collect secret names for display
	secretNames := make([]string, 0, len(project.SecretIDs))
	for _, sid := range project.SecretIDs {
		sec, err := b.store.Get(sid)
			if err == nil {
			secretNames = append(secretNames, sec.Name)
		} else {
			secretNames = append(secretNames, sid+" (не найден)")
		}
	}
	b.config.mu.RUnlock()

	secretsStr := "—"
	if len(secretNames) > 0 {
		secretsStr = escapeHTML(strings.Join(secretNames, ", "))
	}

	text := fmt.Sprintf("📁 <b>%s</b>\n\nID: <code>%s</code>\n📋 Секретов: %d\n🔑 Активных токенов: %d\n📅 Создан: %s\n\n🔒 Секреты:\n%s",
		escapeHTML(project.Name), project.ID, len(project.SecretIDs), tokenCount,
		escapeHTML(project.CreatedAt.Format("02.01.2006 15:04")), secretsStr)

	var rows [][]tgbotapi.InlineKeyboardButton
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔑 Создать токен", "project_token:"+id),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("➕ Добавить секрет", "project_add_secret:"+id),
		tgbotapi.NewInlineKeyboardButtonData("✏️ Заменить секреты", "project_replace_secrets:"+id),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🗑 Удалить проект", "project_delete:"+id),
	))
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("◀️ К списку", "projects"),
	))
	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(rows...))
}

func (b *Bot) createProjectToken(chatID int64, id string) {
	b.config.mu.RLock()
	project, ok := b.config.Projects[id]
	b.config.mu.RUnlock()
	if !ok {
		sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
		return
	}

	token, err := randomToken(32)
	if err != nil {
		sendWithMenu(b.api, chatID, "⚠️ Ошибка генерации токена", mainMenuKB())
		return
	}
	now := time.Now()
	var expires time.Time
	if b.config.TokenTTLHours > 0 {
		expires = now.Add(time.Duration(b.config.TokenTTLHours) * time.Hour)
	}
	tokenHash := hashToken(token)

	b.config.mu.Lock()
	b.config.ProjectTokens[tokenHash] = &ProjectToken{
		ProjectID: id, Token: tokenHash, CreatedAt: now, ExpiresAt: expires,
	}
	if err := b.config.save(b.configPath); err != nil {
		log.Printf("[bot] config save error: %v", err)
	}
	b.config.mu.Unlock()

	ttlStr := "∞"
	if !expires.IsZero() {
		ttlStr = escapeHTML(expires.Format("02.01.2006 15:04"))
	}
	addr := b.config.ListenAddr
	text := fmt.Sprintf("🔑 <b>Токен для проекта %s</b>\n\n<code>%s</code>\n\n⏳ TTL: %s\n\ncurl:\n<pre>curl -s http://%s/access/%s</pre>",
		escapeHTML(project.Name), token, ttlStr, addr, token)
	sendWithMenu(b.api, chatID, text, tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("◀️ К проекту", "project_view:"+id),
		),
	))
}

func (b *Bot) deleteProject(chatID int64, id string) {
	b.config.mu.Lock()
	if _, ok := b.config.Projects[id]; !ok {
		b.config.mu.Unlock()
		sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
		return
	}
	delete(b.config.Projects, id)
	for hash, pt := range b.config.ProjectTokens {
		if pt.ProjectID == id {
			delete(b.config.ProjectTokens, hash)
		}
	}
	if err := b.config.save(b.configPath); err != nil {
		log.Printf("[bot] config save error: %v", err)
	}
	b.config.mu.Unlock()
	sendWithMenu(b.api, chatID, fmt.Sprintf("🗑 Проект <b>%s</b> удалён", escapeHTML(id)), mainMenuKB())
}

// === MESSAGE HANDLER (FSM) ===

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	// Проверка TG Admin ID — только админ может управлять ботом
	if b.config.TGAdminID != 0 && msg.Chat.ID != b.config.TGAdminID {
		log.Printf("[bot] unauthorized access from chat %d", msg.Chat.ID)
		return
	}

	sess := b.getSession(chatID)

	// /start or /cancel always resets
	if strings.ToLower(text) == "/start" || strings.ToLower(text) == "/cancel" {
		b.sendMainMenu(chatID)
		return
	}

	switch sess.state {
	case stateWaitingName:
		name := strings.TrimSpace(text)
		if name == "" {
			sendText(b.api, chatID, "⚠️ Имя не может быть пустым. Попробуйте ещё раз:")
			return
		}
		_, err := b.store.Get(name)
		if err == nil {
			sendText(b.api, chatID, fmt.Sprintf("⚠️ Секрет <b>%s</b> уже существует. Введите другое имя:", escapeHTML(name)))
			return
		}
		sess.name = name
		sess.state = stateWaitingValue
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("Шаг 2/2: Введите значение для <b>%s</b>:", escapeHTML(name)),
			cancelKB())

	case stateWaitingProjectID:
		id := strings.TrimSpace(text)
		if id == "" {
			sendText(b.api, chatID, "⚠️ ID не может быть пустым. Попробуйте ещё раз:")
			return
		}
		b.config.mu.RLock()
		_, exists := b.config.Projects[id]
		b.config.mu.RUnlock()
		if exists {
			sendText(b.api, chatID, fmt.Sprintf("⚠️ Проект <b>%s</b> уже существует. Введите другой ID:", escapeHTML(id)))
			return
		}
		sess.projectID = id
		sess.state = stateWaitingProjectName
		sendWithMenu(b.api, chatID, fmt.Sprintf("Шаг 2/3: Введите название для проекта <b>%s</b>:", escapeHTML(id)), cancelKB())

	case stateWaitingProjectName:
		name := strings.TrimSpace(text)
		if name == "" {
			sendText(b.api, chatID, "⚠️ Название не может быть пустым. Попробуйте ещё раз:")
			return
		}
		sess.projectName = name
		sess.state = stateWaitingProjectSecrets
		secrets, err := b.store.List()
		if err != nil {
			sendText(b.api, chatID, "❌ Ошибка расшифровки: " + err.Error())
			return
		}
		if len(secrets) == 0 {
			b.config.mu.Lock()
			b.config.Projects[sess.projectID] = &Project{
				ID: sess.projectID, Name: sess.projectName, SecretIDs: []string{}, CreatedAt: time.Now(),
			}
			if err := b.config.save(b.configPath); err != nil {
				log.Printf("[bot] config save error: %v", err)
			}
			b.config.mu.Unlock()
			b.resetSession(chatID)
			sendWithMenu(b.api, chatID,
				fmt.Sprintf("✅ Проект <b>%s</b> создан!\n\nID: <code>%s</code>\n📋 Секретов: 0\n\nДобавьте секреты и привяжите их через API.",
					escapeHTML(sess.projectName), sess.projectID),
				mainMenuKB())
			return
		}
		var secretNames []string
		for _, s := range secrets {
			secretNames = append(secretNames, s.Name)
		}
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("Шаг 3/3: Введите имена секретов для проекта <b>%s</b> (через запятую):\n\nДоступные:\n%s",
				escapeHTML(name), escapeHTML(strings.Join(secretNames, ", "))),
			cancelKB())

	case stateWaitingProjectSecrets:
		input := strings.TrimSpace(text)
		var secretIDs []string
		if input != "" {
			for _, s := range strings.Split(input, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					secretIDs = append(secretIDs, s)
				}
			}
		}
		b.config.mu.Lock()
		b.config.Projects[sess.projectID] = &Project{
			ID: sess.projectID, Name: sess.projectName, SecretIDs: secretIDs, CreatedAt: time.Now(),
		}
		if err := b.config.save(b.configPath); err != nil {
			log.Printf("[bot] config save error: %v", err)
		}
		b.config.mu.Unlock()
		b.resetSession(chatID)
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("✅ Проект <b>%s</b> создан!\n\nID: <code>%s</code>\n📋 Секретов: %d\n\nИспользуйте кнопку «🔑 Создать токен» для выдачи доступа.",
				escapeHTML(sess.projectName), sess.projectID, len(secretIDs)),
			mainMenuKB())

	case stateWaitingAddSecretName:
		secretName := strings.TrimSpace(text)
		if secretName == "" {
			sendText(b.api, chatID, "⚠️ Имя не может быть пустым. Попробуйте ещё раз:")
			return
		}
		// Check secret exists
		_, err := b.store.Get(secretName)
		if err != nil {
			sendText(b.api, chatID, fmt.Sprintf("⚠️ Секрет <b>%s</b> не найден. Введите существующий:", escapeHTML(secretName)))
			return
		}
		// Add to project
		projectID := sess.addSecretProjectID
		b.config.mu.Lock()
		project, ok := b.config.Projects[projectID]
		if !ok {
			b.config.mu.Unlock()
			b.resetSession(chatID)
			sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
			return
		}
		// Check for duplicates
		for _, existing := range project.SecretIDs {
			if existing == secretName {
				b.config.mu.Unlock()
				sendWithMenu(b.api, chatID, fmt.Sprintf("⚠️ Секрет <b>%s</b> уже в проекте", escapeHTML(secretName)),
					tgbotapi.NewInlineKeyboardMarkup(
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("◀️ К проекту", "project_view:"+projectID),
						),
					))
				b.resetSession(chatID)
				return
			}
		}
		project.SecretIDs = append(project.SecretIDs, secretName)
		if err := b.config.save(b.configPath); err != nil {
			log.Printf("[bot] config save error: %v", err)
		}
		b.config.mu.Unlock()
		b.resetSession(chatID)
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("✅ Секрет <b>%s</b> добавлен в проект <b>%s</b>", escapeHTML(secretName), escapeHTML(project.Name)),
			tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("◀️ К проекту", "project_view:"+projectID),
				),
			))

	case stateWaitingReplaceSecrets:
		input := strings.TrimSpace(text)
		var secretIDs []string
		if input != "" {
			for _, s := range strings.Split(input, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					// Verify secret exists
					_, err := b.store.Get(s)
		if err != nil {
						sendText(b.api, chatID, fmt.Sprintf("⚠️ Секрет <b>%s</b> не найден. Попробуйте заново:", escapeHTML(s)))
						return
					}
					secretIDs = append(secretIDs, s)
				}
			}
		}
		projectID := sess.projectID
		b.config.mu.Lock()
		project, ok := b.config.Projects[projectID]
		if !ok {
			b.config.mu.Unlock()
			b.resetSession(chatID)
			sendWithMenu(b.api, chatID, "⚠️ Проект не найден", mainMenuKB())
			return
		}
		project.SecretIDs = secretIDs
		if err := b.config.save(b.configPath); err != nil {
			log.Printf("[bot] config save error: %v", err)
		}
		b.config.mu.Unlock()
		b.resetSession(chatID)
		sendWithMenu(b.api, chatID,
			fmt.Sprintf("✅ Секреты проекта <b>%s</b> обновлены\n\n📋 Теперь: %d секретов", escapeHTML(project.Name), len(secretIDs)),
			tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("◀️ К проекту", "project_view:"+projectID),
				),
			))

	case stateWaitingValue:
		value := text
		if value == "" {
			sendText(b.api, chatID, "⚠️ Значение не может быть пустым. Попробуйте ещё раз:")
			return
		}
		b.store.Set(sess.name, value)

		// Auto-create token
		token, err := randomToken(32)
		if err == nil {
			now := time.Now()
			var expires time.Time
			if b.config.TokenTTLHours > 0 {
				expires = now.Add(time.Duration(b.config.TokenTTLHours) * time.Hour)
			}
			tokenHash := hashToken(token)
			b.config.mu.Lock()
			b.config.SecretTokens[tokenHash] = &SecretToken{
				SecretName: sess.name,
				Token:      tokenHash,
				CreatedAt:  now,
				ExpiresAt:  expires,
			}
			saveErr := b.config.save(b.configPath)
			b.config.mu.Unlock()
			if saveErr != nil {
				log.Printf("[bot] config save error: %v", saveErr)
			}

			ttlStr := "∞"
			if !expires.IsZero() {
				ttlStr = escapeHTML(expires.Format("02.01.2006 15:04"))
			}
			addr := b.config.ListenAddr

			b.resetSession(chatID)
			sendWithMenu(b.api, chatID,
				fmt.Sprintf("✅ <b>%s</b> создан!\n\n🔑 Автотокен:\n<code>%s</code>\n\n⏳ TTL: %s\n\ncurl:\n<pre>curl -s http://%s/access/%s</pre>",
					escapeHTML(sess.name), token, ttlStr, addr, token),
				mainMenuKB())
		} else {
			b.resetSession(chatID)
			sendWithMenu(b.api, chatID,
				fmt.Sprintf("✅ <b>%s</b> создан!", escapeHTML(sess.name)),
				mainMenuKB())
		}

	default:
		b.sendMainMenu(chatID)
	}
}

// === MAIN ===

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.TGBotToken == "" {
		log.Fatal("Telegram bot token not set (tg_bot_token in config or VAULT_BOT_TOKEN env)")
	}
	if cfg.AdminToken == "" {
		log.Fatal("Admin token not set (admin_token in config or VAULT_ADMIN_TOKEN env)")
	}

	store := NewStore(os.Getenv("VAULT_PASSWORD"), cfg.AuditLog)
	cfg.startCleanupWorker(time.Hour)

	// Load secrets from encrypted snapshot if exists
	if _, err := os.Stat(cfg.SnapshotPath); err == nil {
		data, err := os.ReadFile(cfg.SnapshotPath)
		if err == nil && len(data) > 0 {
			vaultPassword := os.Getenv("VAULT_PASSWORD")
			if vaultPassword != "" {
				decrypted, decErr := decryptSnapshot(data, vaultPassword)
				if decErr == nil {
					var secrets map[string]*Secret
					if json.Unmarshal(decrypted, &secrets) == nil {
						for name, sec := range secrets {
							store.Set(name, sec.Value)
						}
					}
				} else {
					log.Printf("[main] snapshot decrypt failed (wrong password?): %v", decErr)
				}
			} else {
				log.Printf("[main] VAULT_PASSWORD not set, skipping snapshot load")
			}
		}
	}

	botAPI, err := tgbotapi.NewBotAPI(cfg.TGBotToken)
	if err != nil {
		log.Fatalf("telegram bot: %v", err)
	}
	log.Printf("[main] authorized as %s", botAPI.Self.UserName)

	// Register bot commands in Telegram menu
	_, err = botAPI.Request(tgbotapi.NewSetMyCommands(
		tgbotapi.BotCommand{Command: "start", Description: "🔐 Главное меню — управление секретами"},
		tgbotapi.BotCommand{Command: "cancel", Description: "❌ Отменить текущее действие"},
	))
	if err != nil {
		log.Printf("[main] setMyCommands failed: %v", err)
	} else {
		log.Print("[main] bot commands registered: /start, /cancel")
	}

	bot := NewBot(botAPI, store, cfg, *configPath)
	server := NewServer(store, cfg, *configPath)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)

	bot.startSessionCleaner(ctx)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Print("[main] terminated — shutting down...")
		cancel()
		cfg.stopCleanupWorker()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("[main] shutdown error: %v", err)
		}
	}()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[main] server error: %v", err)
			cancel()
		}
	}()

	// Snapshot on exit (encrypted)
	defer func() {
		vaultPassword := os.Getenv("VAULT_PASSWORD")
		if vaultPassword == "" {
			log.Print("[main] VAULT_PASSWORD not set, skipping snapshot save")
			return
		}
		cfg.mu.Lock()
		cfg.cleanupRevokedTokens()
		cfg.mu.Unlock()
		if err := cfg.save(*configPath); err != nil {
			log.Printf("[main] config save error: %v", err)
		}
		data, err := json.Marshal(store.secrets)
		if err != nil {
			log.Printf("[main] snapshot marshal error: %v", err)
			return
		}
		encrypted, err := encryptSnapshot(data, vaultPassword)
		if err != nil {
			log.Printf("[main] snapshot encrypt error: %v", err)
			return
		}
		if err := os.WriteFile(cfg.SnapshotPath, encrypted, 0600); err != nil {
			log.Printf("[main] snapshot write error: %v", err)
		}
		log.Print("[main] encrypted snapshot saved, bye")
	}()

	log.Printf("[main] agent-vault ready on %s (%d secrets)", cfg.ListenAddr, store.Count())

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := botAPI.GetUpdatesChan(u)

	for {
		select {
		case update := <-updates:
			if update.CallbackQuery != nil {
				bot.handleCallback(update.CallbackQuery)
			} else if update.Message != nil {
				bot.handleMessage(update.Message)
			}
		case <-ctx.Done():
			botAPI.StopReceivingUpdates()
			return
		}
	}
}
