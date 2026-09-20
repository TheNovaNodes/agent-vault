package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// === MOCK BOT API ===

type mockBotAPI struct {
	mu        sync.Mutex
	messages  []tgbotapi.MessageConfig
	callbacks []tgbotapi.CallbackConfig
}

func newMockBotAPI() *mockBotAPI {
	return &mockBotAPI{}
}

func (m *mockBotAPI) Send(c tgbotapi.Chattable) (tgbotapi.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch v := c.(type) {
	case tgbotapi.MessageConfig:
		m.messages = append(m.messages, v)
		return tgbotapi.Message{MessageID: len(m.messages)}, nil
	case tgbotapi.EditMessageTextConfig:
		var replyMarkup tgbotapi.InlineKeyboardMarkup
		if v.ReplyMarkup != nil {
			replyMarkup = *v.ReplyMarkup
		}
		m.messages = append(m.messages, tgbotapi.MessageConfig{
			BaseChat: tgbotapi.BaseChat{
				ChatID:      v.ChatID,
				ReplyMarkup: replyMarkup,
			},
			Text:      v.Text,
			ParseMode: v.ParseMode,
		})
		return tgbotapi.Message{MessageID: v.MessageID}, nil
	}
	return tgbotapi.Message{}, nil
}

func (m *mockBotAPI) AnswerCallbackQuery(config tgbotapi.CallbackConfig) (tgbotapi.APIResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, config)
	return tgbotapi.APIResponse{Ok: true}, nil
}

func (m *mockBotAPI) Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch v := c.(type) {
	case tgbotapi.CallbackConfig:
		m.callbacks = append(m.callbacks, v)
	}
	return &tgbotapi.APIResponse{Ok: true}, nil
}

func (m *mockBotAPI) GetChatMember(tgbotapi.ChatConfigWithUser) (tgbotapi.ChatMember, error) {
	return tgbotapi.ChatMember{}, nil
}

func (m *mockBotAPI) GetUpdatesChan(tgbotapi.UpdateConfig) tgbotapi.UpdatesChannel {
	return make(chan tgbotapi.Update)
}

func (m *mockBotAPI) StopReceivingUpdates() {}

func (m *mockBotAPI) GetMe() (tgbotapi.User, error) {
	return tgbotapi.User{UserName: "test_bot"}, nil
}

func (m *mockBotAPI) LastMessage() tgbotapi.MessageConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.messages) == 0 {
		return tgbotapi.MessageConfig{}
	}
	return m.messages[len(m.messages)-1]
}

func (m *mockBotAPI) AllMessages() []tgbotapi.MessageConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]tgbotapi.MessageConfig, len(m.messages))
	copy(result, m.messages)
	return result
}

func (m *mockBotAPI) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *mockBotAPI) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = nil
	m.callbacks = nil
}

// === TEST HELPERS ===

func newTestBot(store *Store, cfg *Config) (*Bot, *mockBotAPI) {
	api := newMockBotAPI()
	bot := &Bot{
		api:        api,
		store:      store,
		config:     cfg,
		configPath: "/tmp/test-config.yaml",
		sessions:   make(map[int64]*session),
	}
	return bot, api
}

func newTestConfig() *Config {
	return &Config{
		AdminToken:    "admin-token",
		SecretTokens:  make(map[string]*SecretToken),
		Projects:      make(map[string]*Project),
		ProjectTokens: make(map[string]*ProjectToken),
		TokenTTLHours: 0,
		ListenAddr:    "127.0.0.1:8301",
		TGAdminID:     100, // same as test chat IDs
	}
}

func makeCallback(chatID int64, data string) *tgbotapi.CallbackQuery {
	return &tgbotapi.CallbackQuery{
		ID: "cb-1", From: &tgbotapi.User{ID: chatID},
		Message: &tgbotapi.Message{MessageID: 10, Chat: &tgbotapi.Chat{ID: chatID}},
		Data:    data,
	}
}

func makeMessage(chatID int64, text string) *tgbotapi.Message {
	return &tgbotapi.Message{
		Chat: &tgbotapi.Chat{ID: chatID},
		Text: text,
	}
}

// === CALLBACK: MAIN MENU ===

func TestCallbackCreate(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "create"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Создание секрета") {
		t.Fatalf("expected create prompt, got: %s", msg.Text)
	}
	if bot.getSession(100).state != stateWaitingName {
		t.Fatalf("expected waiting_name state, got %s", bot.getSession(100).state)
	}
}

func TestCallbackListEmpty(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "list"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Секретов нет") {
		t.Fatalf("expected empty message, got: %s", msg.Text)
	}
}

func TestCallbackListWithSecrets(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("api_key", "val123")
	store.Set("db_pass", "pass456")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "list"))

	if api.Count() == 0 {
		t.Fatal("expected at least one message")
	}
	msg := api.LastMessage()
	// In HTML mode, parentheses are not escaped
	text := msg.Text
	if !strings.Contains(text, "(2)") {
		t.Fatalf("expected count 2 in list message, got: %s", text)
	}
	if !strings.Contains(text, "Секреты") {
		t.Fatalf("expected title, got: %s", text)
	}
}

func TestCallbackWipeSecrets(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("k", "v")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "wipe_secrets"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Удалить все секреты") {
		t.Fatalf("expected wipe confirmation, got: %s", msg.Text)
	}
}

func TestCallbackWipeSecretsYes(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("k1", "v1")
	store.Set("k2", "v2")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "wipe_secrets_yes"))

	if store.Count() != 0 {
		t.Fatal("expected all secrets deleted")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "удалены") {
		t.Fatalf("expected deletion confirmation, got: %s", msg.Text)
	}
}

func TestCallbackWipeTokens(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "wipe_tokens"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Удалить все токены") {
		t.Fatalf("expected wipe tokens confirmation, got: %s", msg.Text)
	}
}

func TestCallbackWipeTokensYes(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.SecretTokens[hashToken("tok1")] = &SecretToken{SecretName: "s1", Token: hashToken("tok1")}
	cfg.SecretTokens[hashToken("tok2")] = &SecretToken{SecretName: "s2", Token: hashToken("tok2")}
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "wipe_tokens_yes"))

	if len(cfg.SecretTokens) != 0 {
		t.Fatal("expected all tokens wiped")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "токены удалены") {
		t.Fatalf("expected confirmation, got: %s", msg.Text)
	}
}

func TestCallbackCancel(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	// Set some state first
	bot.getSession(100).state = stateWaitingName

	bot.handleCallback(makeCallback(100, "cancel"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Lab Vault") {
		t.Fatalf("expected main menu, got: %s", msg.Text)
	}
}

// === CALLBACK: SECRET VIEW ===

func TestCallbackViewSecret(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("my_secret", "my_value")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "view:my_secret"))

	if api.Count() == 0 {
		t.Fatal("expected message")
	}
	msg := api.LastMessage()
	text := strings.ReplaceAll(msg.Text, "\\_", "_")
	if !strings.Contains(text, "my_secret") {
		t.Fatalf("expected secret name, got: %s", msg.Text)
	}
	if !strings.Contains(text, "my_value") {
		t.Fatalf("expected secret value, got: %s", msg.Text)
	}
}

func TestCallbackViewSecretNotFound(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "view:nonexistent"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не найден") {
		t.Fatalf("expected not found, got: %s", msg.Text)
	}
}

// === CALLBACK: TOKEN CREATION ===

func TestCallbackTokenCreate(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("s1", "v1")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "token:s1"))

	if api.Count() == 0 {
		t.Fatal("expected message")
	}
	msg := api.LastMessage()
	// Should contain a token
	if !strings.Contains(msg.Text, "Токен для") {
		t.Fatalf("expected token message, got: %s", msg.Text)
	}

	// Config should have the token
	if len(cfg.SecretTokens) != 1 {
		t.Fatalf("expected 1 token in config, got %d", len(cfg.SecretTokens))
	}
}

func TestCallbackTokenCreateSecretNotFound(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "token:nonexistent"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не найден") {
		t.Fatalf("expected not found, got: %s", msg.Text)
	}
}

// === CALLBACK: REVOKE TOKENS ===

func TestCallbackRevokeTokens(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("s1", "v1")
	cfg := newTestConfig()
	cfg.SecretTokens[hashToken("tok1")] = &SecretToken{SecretName: "s1", Token: hashToken("tok1"), Revoked: false}
	cfg.SecretTokens[hashToken("tok2")] = &SecretToken{SecretName: "s1", Token: hashToken("tok2"), Revoked: false}
	cfg.SecretTokens[hashToken("tok3")] = &SecretToken{SecretName: "s2", Token: hashToken("tok3"), Revoked: false}
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "revoke:s1"))

	// After revoke + cleanup, s1 tokens are removed from the map (revoked → cleaned up)
	if _, ok := cfg.SecretTokens[hashToken("tok1")]; ok {
		t.Fatal("tok1 should be deleted after revoke+cleanup")
	}
	if _, ok := cfg.SecretTokens[hashToken("tok2")]; ok {
		t.Fatal("tok2 should be deleted after revoke+cleanup")
	}
	// s2 token should still exist and NOT be revoked
	if tok3, ok := cfg.SecretTokens[hashToken("tok3")]; !ok {
		t.Fatal("tok3 should still exist (not targeted by revoke)")
	} else if tok3.Revoked {
		t.Fatal("tok3 should NOT be revoked")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Отозвано токенов: 2") {
		t.Fatalf("expected 2 revoked, got: %s", msg.Text)
	}
}

// === CALLBACK: DELETE SECRET ===

func TestCallbackConfirmDeleteSecret(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("to_delete", "val")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "confirm_delete:to_delete"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Вы уверены") {
		t.Fatalf("expected confirmation message, got: %s", msg.Text)
	}
}

func TestCallbackConfirmDeleteProject(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.Projects["proj1"] = &Project{ID: "proj1", Name: "Test Project"}
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "confirm_project_delete:proj1"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Вы уверены") {
		t.Fatalf("expected confirmation message, got: %s", msg.Text)
	}
}

func TestCallbackDeleteSecret(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("to_delete", "val")
	cfg := newTestConfig()
	cfg.SecretTokens[hashToken("tok1")] = &SecretToken{SecretName: "to_delete", Token: hashToken("tok1"), Revoked: false}
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "delete:to_delete"))

	if store.Count() != 0 {
		t.Fatal("expected secret deleted")
	}
	if _, exists := cfg.SecretTokens[hashToken("tok1")]; exists {
		t.Fatal("token should be deleted from config when secret deleted")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "удалён") {
		t.Fatalf("expected deletion confirmation, got: %s", msg.Text)
	}
}

func TestCallbackDeleteSecretNotFound(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "delete:nonexistent"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не найден") {
		t.Fatalf("expected not found, got: %s", msg.Text)
	}
}

// === CALLBACK: EXPORT ===

func TestCallbackExport(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("k1", "v1")
	store.Set("k2", "v2")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "export"))

	msgs := api.AllMessages()
	if len(msgs) != 4 {
		t.Fatalf("expected 4 messages (1 intro + 2 cards + 1 completion), got %d", len(msgs))
	}
	allText := ""
	for _, m := range msgs {
		allText += m.Text + "\n"
	}
	if !strings.Contains(allText, "k1") || !strings.Contains(allText, "k2") {
		t.Fatalf("expected secret names in export cards, got: %s", allText)
	}
}

func TestCallbackExportEmpty(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "export"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Нечего экспортировать") {
		t.Fatalf("expected empty export message, got: %s", msg.Text)
	}
}

// === CALLBACK: BACK ===

func TestCallbackBack(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("k1", "v1")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(100, "back"))

	msg := api.LastMessage()
	// Should show secret list with count
	if !strings.Contains(msg.Text, "(1)") {
		t.Fatalf("expected secret list with count 1, got: %s", msg.Text)
	}
}

// === CALLBACK: UNKNOWN ===

func TestCallbackUnknown(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	// Should not panic
	bot.handleCallback(makeCallback(100, "unknown_data"))

	// Should show main menu
	if api.Count() > 0 {
		msg := api.LastMessage()
		if !strings.Contains(msg.Text, "Lab Vault") {
			t.Logf("got: %s", msg.Text)
		}
	}
}

// === FSM: MESSAGE HANDLER ===

func TestFSMStart(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleMessage(makeMessage(100, "/start"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Lab Vault") {
		t.Fatalf("expected main menu, got: %s", msg.Text)
	}
}

func TestFSMCancel(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingName

	bot.handleMessage(makeMessage(100, "/cancel"))

	sess := bot.getSession(100)
	if sess.state != "" {
		t.Fatalf("expected empty state after cancel, got %s", sess.state)
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Lab Vault") {
		t.Fatalf("expected main menu after cancel, got: %s", msg.Text)
	}
}

func TestFSMDefaultShowsMenu(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.handleMessage(makeMessage(100, "random text"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Lab Vault") {
		t.Fatalf("expected main menu, got: %s", msg.Text)
	}
}

// === FSM: CREATE SECRET FLOW ===

func TestFSMCreateStep1_Name(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingName

	bot.handleMessage(makeMessage(100, "new_secret"))

	sess := bot.getSession(100)
	if sess.state != stateWaitingValue {
		t.Fatalf("expected waiting_value, got %s", sess.state)
	}
	if sess.name != "new_secret" {
		t.Fatalf("expected name 'new_secret', got %q", sess.name)
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Шаг 2/2") {
		t.Fatalf("expected step 2 prompt, got: %s", msg.Text)
	}
}

func TestFSMCreateStep1_EmptyName(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingName

	bot.handleMessage(makeMessage(100, "  "))

	sess := bot.getSession(100)
	if sess.state != stateWaitingName {
		t.Fatal("state should not change on empty name")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не может быть пустым") {
		t.Fatalf("expected empty name error, got: %s", msg.Text)
	}
}

func TestFSMCreateStep1_DuplicateName(t *testing.T) {
	store := MustNewStore("", "")
	store.Set("existing", "val")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingName

	bot.handleMessage(makeMessage(100, "existing"))

	sess := bot.getSession(100)
	if sess.state != stateWaitingName {
		t.Fatal("state should not change on duplicate")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "уже существует") {
		t.Fatalf("expected duplicate error, got: %s", msg.Text)
	}
}

func TestFSMCreateStep2_Value(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	sess := bot.getSession(100)
	sess.state = stateWaitingValue
	sess.name = "my_secret"

	bot.handleMessage(makeMessage(100, "my_value"))

	// Secret should be stored
	sec, err := store.Get("my_secret")
	if err != nil {
		t.Fatal("expected secret to be stored")
	}
	if sec.Value != "my_value" {
		t.Fatalf("expected my_value, got %s", sec.Value)
	}

	// Session should be reset
	sess = bot.getSession(100)
	if sess.state != "" {
		t.Fatalf("expected empty state, got %s", sess.state)
	}

	// Should show success message with token
	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "создан") {
		t.Fatalf("expected creation confirmation, got: %s", msg.Text)
	}
	if !strings.Contains(msg.Text, "Автотокен") {
		t.Fatalf("expected auto-token, got: %s", msg.Text)
	}
}

func TestFSMCreateStep2_EmptyValue(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	sess := bot.getSession(100)
	sess.state = stateWaitingValue
	sess.name = "my_secret"

	bot.handleMessage(makeMessage(100, ""))

	if sess.state != stateWaitingValue {
		t.Fatal("state should not change on empty value")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не может быть пустым") {
		t.Fatalf("expected empty value error, got: %s", msg.Text)
	}
}

func TestFSMCreateFullFlow(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	// Step 1: Name
	bot.handleMessage(makeMessage(100, "/start"))
	bot.handleCallback(makeCallback(100, "create"))
	bot.handleMessage(makeMessage(100, "smtp_pass"))

	// Step 2: Value
	bot.handleMessage(makeMessage(100, "s3cret!"))

	// Verify
	sec, err := store.Get("smtp_pass")
	if err != nil {
		t.Fatal("expected secret")
	}
	if sec.Value != "s3cret!" {
		t.Fatalf("expected s3cret!, got %s", sec.Value)
	}

	// Token should be auto-created
	if len(cfg.SecretTokens) != 1 {
		t.Fatalf("expected 1 auto-token, got %d", len(cfg.SecretTokens))
	}

	// Last message should contain token
	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "curl") {
		t.Fatalf("expected curl command in success message, got: %s", msg.Text)
	}
}

// === SESSION ISOLATION ===

func TestSessionIsolation(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, _ := newTestBot(store, cfg)

	// User 1 starts creating
	bot.getSession(1).state = stateWaitingName

	// User 2 should have separate session
	sess2 := bot.getSession(2)
	if sess2.state != "" {
		t.Fatal("user 2 should have fresh session")
	}

	// User 1's state unchanged
	if bot.getSession(1).state != stateWaitingName {
		t.Fatal("user 1 state should be unchanged")
	}
}

func TestResetSession(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, _ := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingValue
	bot.getSession(100).name = "test"

	bot.resetSession(100)

	sess := bot.getSession(100)
	if sess.state != "" || sess.name != "" {
		t.Fatal("session should be reset")
	}
}

// === CONCURRENCY ===

func TestConcurrentSecretCreation(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.TGAdminID = -1 // -1 = test mode, allow simulated chats for concurrency test
	bot, _ := newTestBot(store, cfg)

	// Simulate concurrent secret creation from different chats
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			chatID := int64(n + 1)
			sess := bot.getSession(chatID)
			sess.state = stateWaitingValue
			sess.name = fmt.Sprintf("secret_%d", n)
			bot.handleMessage(makeMessage(chatID, fmt.Sprintf("value_%d", n)))
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if store.Count() != 10 {
		t.Fatalf("expected 10 secrets, got %d", store.Count())
	}
}

// === TG ADMIN ID CHECK ===

func TestHandleMessage_NonAdminRejected(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.TGAdminID = 100
	bot, api := newTestBot(store, cfg)

	// Chat ID 200 != TGAdminID 100 → should be rejected
	bot.handleMessage(makeMessage(200, "/start"))

	// No messages should be sent to non-admin
	if api.Count() != 0 {
		t.Fatalf("expected no messages for non-admin, got %d", api.Count())
	}
}

func TestHandleMessage_AdminAllowed(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.TGAdminID = 100
	bot, api := newTestBot(store, cfg)

	// Chat ID 100 == TGAdminID 100 → should work
	bot.handleMessage(makeMessage(100, "/start"))

	if api.Count() == 0 {
		t.Fatal("expected messages for admin")
	}
	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Lab Vault") {
		t.Fatalf("expected main menu, got: %s", msg.Text)
	}
}

func TestHandleMessage_NoAdminIDRejectsAll(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.TGAdminID = 0 // 0 = not set -> fail-closed
	bot, api := newTestBot(store, cfg)

	// Any chat should be rejected when TGAdminID is 0
	bot.handleMessage(makeMessage(999, "/start"))

	if api.Count() != 0 {
		t.Fatalf("expected no messages when TGAdminID not set (fail-closed), got %d", api.Count())
	}
}

func TestHandleCallback_NoAdminIDRejectsAll(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.TGAdminID = 0 // 0 = not set -> fail-closed
	bot, api := newTestBot(store, cfg)

	bot.handleCallback(makeCallback(999, "create"))

	if api.Count() != 0 {
		t.Fatalf("expected no messages when TGAdminID not set (fail-closed), got %d", api.Count())
	}
}

func TestFSMCreateStep1_InvalidName(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	bot.getSession(100).state = stateWaitingName
	bot.handleMessage(makeMessage(100, "bad;name`rm`"))

	sess := bot.getSession(100)
	if sess.state != stateWaitingName {
		t.Fatal("state should not change on invalid name format")
	}

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "Недопустимое имя") {
		t.Fatalf("expected invalid name error, got: %s", msg.Text)
	}
}

// === PROJECT TESTS ===

func TestCallback_ProjectAddSecret(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	// Pre-create a secret and project
	store.Set("db_password", "secret123")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{}, CreatedAt: time.Now(),
	}

	// Trigger add secret callback
	bot.handleCallback(makeCallback(100, "project_add_secret:myapp"))

	// Should show available secrets
	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "db_password") {
		t.Fatalf("expected available secrets list, got: %s", msg.Text)
	}

	// Now send the secret name
	api.Reset()
	bot.handleMessage(makeMessage(100, "db_password"))

	msg = api.LastMessage()
	if !strings.Contains(msg.Text, "добавлен") {
		t.Fatalf("expected success message, got: %s", msg.Text)
	}
}

func TestCallback_ProjectAddSecret_Duplicate(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	store.Set("db_password", "secret123")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{"db_password"}, CreatedAt: time.Now(),
	}

	// Try to add same secret again
	bot.handleCallback(makeCallback(100, "project_add_secret:myapp"))
	bot.handleMessage(makeMessage(100, "db_password"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "уже в проекте") {
		t.Fatalf("expected duplicate warning, got: %s", msg.Text)
	}
}

func TestCallback_ProjectAddSecret_NotFound(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{}, CreatedAt: time.Now(),
	}

	bot.handleCallback(makeCallback(100, "project_add_secret:myapp"))
	bot.handleMessage(makeMessage(100, "nonexistent"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не найден") {
		t.Fatalf("expected not found warning, got: %s", msg.Text)
	}
}

func TestCallback_ProjectReplaceSecrets(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	store.Set("key1", "val1")
	store.Set("key2", "val2")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{"old_key"}, CreatedAt: time.Now(),
	}

	// Trigger replace callback
	bot.handleCallback(makeCallback(100, "project_replace_secrets:myapp"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "old_key") {
		t.Fatalf("expected current secrets shown, got: %s", msg.Text)
	}

	// Replace with new secrets
	api.Reset()
	bot.handleMessage(makeMessage(100, "key1, key2"))

	msg = api.LastMessage()
	if !strings.Contains(msg.Text, "обновлены") {
		t.Fatalf("expected success message, got: %s", msg.Text)
	}

	// Verify project was updated
	if len(cfg.Projects["myapp"].SecretIDs) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(cfg.Projects["myapp"].SecretIDs))
	}
}

func TestCallback_ProjectReplaceSecrets_InvalidSecret(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	store.Set("key1", "val1")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{"key1"}, CreatedAt: time.Now(),
	}

	bot.handleCallback(makeCallback(100, "project_replace_secrets:myapp"))
	api.Reset()
	bot.handleMessage(makeMessage(100, "key1, nonexistent"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "не найден") {
		t.Fatalf("expected not found warning, got: %s", msg.Text)
	}
}

func TestCallback_ProjectReplaceSecrets_ClearAll(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	store.Set("key1", "val1")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{"key1"}, CreatedAt: time.Now(),
	}

	bot.handleCallback(makeCallback(100, "project_replace_secrets:myapp"))
	api.Reset()
	bot.handleMessage(makeMessage(100, "")) // empty = clear all

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "обновлены") {
		t.Fatalf("expected success message, got: %s", msg.Text)
	}

	if len(cfg.Projects["myapp"].SecretIDs) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(cfg.Projects["myapp"].SecretIDs))
	}
}

func TestCallback_ProjectView_ShowsSecrets(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)

	store.Set("api_key", "val123")
	cfg.Projects["myapp"] = &Project{
		ID: "myapp", Name: "My App", SecretIDs: []string{"api_key"}, CreatedAt: time.Now(),
	}

	bot.handleCallback(makeCallback(100, "project_view:myapp"))

	msg := api.LastMessage()
	if !strings.Contains(msg.Text, "api_key") {
		t.Fatalf("expected secret names in project view, got: %s", msg.Text)
	}
}


func TestBot_SessionAndWorker(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	mockAPI := &mockBotAPI{}
	bot := NewBot(mockAPI, store, cfg, "/dev/null")

	sess := bot.getSession(123)
	if sess == nil {
		t.Fatalf("expected session")
	}

	bot.resetSession(123)
	
	ctx, cancel := context.WithCancel(context.Background())
	go bot.startSessionCleaner(ctx)
	cancel()
}

func TestBot_Callback_ProjectList(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	mockAPI := &mockBotAPI{}
	bot := NewBot(mockAPI, store, cfg, "/dev/null")
	
	cb := &tgbotapi.CallbackQuery{From: &tgbotapi.User{ID: 1},
		Message: &tgbotapi.Message{
			Chat: &tgbotapi.Chat{ID: 1},
		},
		Data: "projects_list",
	}
	bot.handleCallback(cb)
}

func TestBot_Callback_ProjectTokenCreate(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.Projects["proj1"] = &Project{ID: "proj1", Name: "Proj 1"}
	mockAPI := &mockBotAPI{}
	bot := NewBot(mockAPI, store, cfg, "/dev/null")
	
	cb := &tgbotapi.CallbackQuery{From: &tgbotapi.User{ID: 1},
		Message: &tgbotapi.Message{
			Chat: &tgbotapi.Chat{ID: 1},
		},
		Data: "project_create_token_proj1",
	}
	bot.handleCallback(cb)
}

func TestBot_Callback_ProjectDelete(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	cfg.Projects["proj1"] = &Project{ID: "proj1", Name: "Proj 1"}
	mockAPI := &mockBotAPI{}
	bot := NewBot(mockAPI, store, cfg, "/dev/null")
	
	cb := &tgbotapi.CallbackQuery{From: &tgbotapi.User{ID: 1},
		Message: &tgbotapi.Message{
			Chat: &tgbotapi.Chat{ID: 1},
		},
		Data: "project_delete_proj1",
	}
	bot.handleCallback(cb)
}

func TestBot_Message_HandleMessage(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	mockAPI := &mockBotAPI{}
	bot := NewBot(mockAPI, store, cfg, "/dev/null")
	
	msg := &tgbotapi.Message{
		Chat: &tgbotapi.Chat{ID: 1},
		Text: "Hello",
	}
	bot.handleMessage(msg)
}

func TestCallback_NilMessageHandled(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	mockAPI := newMockBotAPI()
	bot := NewBot(mockAPI, store, cfg, "/dev/null")

	// Ensure no panic when Message is nil
	cb := &tgbotapi.CallbackQuery{
		ID:      "cb-nil-msg",
		From:    &tgbotapi.User{ID: cfg.TGAdminID},
		Message: nil,
		Data:    "list",
	}
	bot.handleCallback(cb)
}

func TestCallback_ResetsSessionOnListAndProjects(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, _ := newTestBot(store, cfg)
	chatID := int64(100)

	bot.getSession(chatID).state = stateWaitingName

	bot.handleCallback(makeCallback(chatID, "list"))
	if state := bot.getSession(chatID).state; state != "" {
		t.Fatalf("expected state to be reset on list callback, got %q", state)
	}

	bot.getSession(chatID).state = stateWaitingName
	bot.handleCallback(makeCallback(chatID, "projects"))
	if state := bot.getSession(chatID).state; state != "" {
		t.Fatalf("expected state to be reset on projects callback, got %q", state)
	}
}

func TestSendExport_HTMLEscaping(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)
	chatID := int64(100)

	store.Set("xml_secret", "<script>alert('xss')</script>&foo")
	bot.sendExport(chatID)

	msgs := api.AllMessages()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (intro + 1 card + completion), got %d", len(msgs))
	}

	card := msgs[1]
	if strings.Contains(card.Text, "<script>") {
		t.Fatalf("expected raw XML/HTML tags to be escaped in export card, got: %s", card.Text)
	}
	if !strings.Contains(card.Text, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;&amp;foo") {
		t.Fatalf("expected escaped HTML in export card, got: %s", card.Text)
	}
	if card.ReplyMarkup == nil {
		t.Fatal("expected inline keyboard markup on export card")
	}
}

func TestSendExport_MultiCardStream(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)
	chatID := int64(100)

	now := time.Now()
	store.mu.Lock()
	store.secrets["sec1"] = &Secret{Name: "sec1", Value: "val1", UpdatedAt: now.Add(-2 * time.Hour)}
	store.secrets["sec2"] = &Secret{Name: "sec2", Value: "val2", UpdatedAt: now.Add(-1 * time.Hour)}
	store.secrets["sec3"] = &Secret{Name: "sec3", Value: "val3", UpdatedAt: now}
	store.mu.Unlock()

	bot.sendExport(chatID)

	msgs := api.AllMessages()
	// 1 intro + 3 secret cards + 1 completion = 5 messages
	if len(msgs) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(msgs))
	}

	expectedOrder := []string{"sec1", "sec2", "sec3"}
	for i, exp := range expectedOrder {
		card := msgs[i+1]
		if !strings.Contains(card.Text, exp) {
			t.Fatalf("card %d: expected secret name %s, got: %s", i, exp, card.Text)
		}
		if !strings.Contains(card.Text, "val"+exp[3:]) {
			t.Fatalf("card %d: expected value val%s, got: %s", i, exp[3:], card.Text)
		}
		// Verify inline action buttons
		kb, ok := card.ReplyMarkup.(tgbotapi.InlineKeyboardMarkup)
		if !ok || len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 2 {
			t.Fatalf("card %d: expected 2 inline action buttons", i)
		}
		btnToken := kb.InlineKeyboard[0][0]
		btnManage := kb.InlineKeyboard[0][1]
		if *btnToken.CallbackData != "token:"+exp {
			t.Fatalf("card %d: expected token callback data token:%s, got %s", i, exp, *btnToken.CallbackData)
		}
		if *btnManage.CallbackData != "view:"+exp {
			t.Fatalf("card %d: expected view callback data view:%s, got %s", i, exp, *btnManage.CallbackData)
		}
	}

	// Verify completion message
	last := msgs[4]
	if !strings.Contains(last.Text, "Экспорт завершён") || !strings.Contains(last.Text, "3 карточек") {
		t.Fatalf("expected completion text, got: %s", last.Text)
	}
}

// === BATCH DELETION TESTS ===

func TestBatchDelete_InteractiveFlow(t *testing.T) {
	store := MustNewStore("", "")
	now := time.Now()
	store.mu.Lock()
	store.secrets["alpha"] = &Secret{Name: "alpha", Value: "val-a", UpdatedAt: now}
	store.secrets["beta"] = &Secret{Name: "beta", Value: "val-b", UpdatedAt: now.Add(time.Second)}
	store.secrets["gamma"] = &Secret{Name: "gamma", Value: "val-c", UpdatedAt: now.Add(2 * time.Second)}
	store.mu.Unlock()

	cfg := newTestConfig()
	cfg.SecretTokens[hashToken("tok-beta")] = &SecretToken{SecretName: "beta", Token: hashToken("tok-beta")}
	cfg.Projects["p1"] = &Project{ID: "p1", Name: "Proj1", SecretIDs: []string{"beta", "gamma"}, CreatedAt: now}

	bot, api := newTestBot(store, cfg)
	chatID := int64(100)

	// 1. Open batch deletion view
	bot.handleCallback(makeCallback(chatID, "batch_delete"))
	last := api.LastMessage()
	if !strings.Contains(last.Text, "Пакетное удаление") {
		t.Fatalf("expected batch delete header, got: %s", last.Text)
	}
	kb := last.ReplyMarkup.(tgbotapi.InlineKeyboardMarkup)
	// Check initial buttons have empty checkboxes ⬜
	if !strings.Contains(kb.InlineKeyboard[0][0].Text, "⬜ alpha") {
		t.Fatalf("expected ⬜ alpha, got: %s", kb.InlineKeyboard[0][0].Text)
	}

	// 2. Toggle alpha (idx 0)
	bot.handleCallback(makeCallback(chatID, "b_tog:0"))
	last = api.LastMessage()
	kb = last.ReplyMarkup.(tgbotapi.InlineKeyboardMarkup)
	if !strings.Contains(kb.InlineKeyboard[0][0].Text, "✅ alpha") {
		t.Fatalf("expected ✅ alpha after toggle, got: %s", kb.InlineKeyboard[0][0].Text)
	}
	if !strings.Contains(last.Text, "Выбрано: <b>1</b>") {
		t.Fatalf("expected selected count 1, got: %s", last.Text)
	}

	// 3. Toggle beta (idx 1)
	bot.handleCallback(makeCallback(chatID, "b_tog:1"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Выбрано: <b>2</b>") {
		t.Fatalf("expected selected count 2, got: %s", last.Text)
	}

	// 4. Select all (b_all)
	bot.handleCallback(makeCallback(chatID, "b_all"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Выбрано: <b>3</b>") {
		t.Fatalf("expected selected count 3, got: %s", last.Text)
	}

	// 5. Deselect all (b_none)
	bot.handleCallback(makeCallback(chatID, "b_none"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Выбрано: <b>0</b>") {
		t.Fatalf("expected selected count 0, got: %s", last.Text)
	}

	// 6. Select beta only (b_tog:1)
	bot.handleCallback(makeCallback(chatID, "b_tog:1"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Выбрано: <b>1</b>") {
		t.Fatalf("expected selected count 1, got: %s", last.Text)
	}

	// 7. Click confirm (b_confirm)
	bot.handleCallback(makeCallback(chatID, "b_confirm"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Подтверждение пакетного удаления") || !strings.Contains(last.Text, "beta") {
		t.Fatalf("expected confirmation message for beta, got: %s", last.Text)
	}

	// 8. Execute deletion (b_exec)
	bot.handleCallback(makeCallback(chatID, "b_exec"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Пакетное удаление завершено") || !strings.Contains(last.Text, "Удалено секретов: <b>1</b>") {
		t.Fatalf("expected completion message, got: %s", last.Text)
	}

	// Verify store state
	if store.Count() != 2 {
		t.Fatalf("expected 2 secrets left in store, got %d", store.Count())
	}
	if _, err := store.Get("beta"); err == nil {
		t.Fatal("expected beta to be deleted from store")
	}
	if _, err := store.Get("alpha"); err != nil {
		t.Fatal("expected alpha to remain in store")
	}
	if _, err := store.Get("gamma"); err != nil {
		t.Fatal("expected gamma to remain in store")
	}

	// Verify token was revoked
	if _, exists := cfg.SecretTokens[hashToken("tok-beta")]; exists {
		t.Fatal("expected token for beta to be deleted from SecretTokens")
	}

	// Verify project references cleaned
	if len(cfg.Projects["p1"].SecretIDs) != 1 || cfg.Projects["p1"].SecretIDs[0] != "gamma" {
		t.Fatalf("expected project secretIDs to only contain gamma, got: %v", cfg.Projects["p1"].SecretIDs)
	}
}

func TestBatchDelete_Pagination(t *testing.T) {
	store := MustNewStore("", "")
	now := time.Now()
	store.mu.Lock()
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("sec_%02d", i)
		store.secrets[name] = &Secret{Name: name, Value: "v", UpdatedAt: now.Add(time.Duration(i) * time.Second)}
	}
	store.mu.Unlock()

	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)
	chatID := int64(100)

	// Open batch delete
	bot.handleCallback(makeCallback(chatID, "batch_delete"))
	last := api.LastMessage()
	if !strings.Contains(last.Text, "Страница: <b>1/3</b>") {
		t.Fatalf("expected page 1/3, got: %s", last.Text)
	}

	// Next page
	bot.handleCallback(makeCallback(chatID, "b_page:1"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Страница: <b>2/3</b>") {
		t.Fatalf("expected page 2/3, got: %s", last.Text)
	}

	// Prev page
	bot.handleCallback(makeCallback(chatID, "b_page:0"))
	last = api.LastMessage()
	if !strings.Contains(last.Text, "Страница: <b>1/3</b>") {
		t.Fatalf("expected page 1/3, got: %s", last.Text)
	}
}

func TestSecretNameValidation_CyrillicAndExtendedChars(t *testing.T) {
	store := MustNewStore("", "")
	cfg := newTestConfig()
	bot, api := newTestBot(store, cfg)
	chatID := int64(100)

	validNames := []string{
		"Тайлер",
		"Марла Сингер",
		"Набор для Трикстера",
		"app.dev-key's",
		"test_key 123",
	}

	for _, name := range validNames {
		bot.resetSession(chatID)
		bot.getSession(chatID).state = stateWaitingName
		bot.handleMessage(makeMessage(chatID, name))
		sess := bot.getSession(chatID)
		if sess.state != stateWaitingValue {
			t.Fatalf("expected valid name %q to transition to stateWaitingValue, got state: %q", name, sess.state)
		}
		if sess.name != name {
			t.Fatalf("expected session name %q, got %q", name, sess.name)
		}
	}

	invalidNames := []string{
		"bad/slash",
		"bad;semicolon",
		"bad\nnewline",
		"bad\x00null",
		"a_very_long_secret_name_that_exceeds_forty_eight_bytes_limit_abcdefghijklmnop",
	}

	for _, name := range invalidNames {
		bot.resetSession(chatID)
		bot.getSession(chatID).state = stateWaitingName
		bot.handleMessage(makeMessage(chatID, name))
		sess := bot.getSession(chatID)
		if sess.state != stateWaitingName {
			t.Fatalf("expected invalid name %q to stay in stateWaitingName, got state: %q", name, sess.state)
		}
		last := api.LastMessage()
		if !strings.Contains(last.Text, "Недопустимое имя секрета") {
			t.Fatalf("expected validation warning for %q, got: %s", name, last.Text)
		}
	}
}
