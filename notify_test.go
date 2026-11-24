package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

const testBotToken = "123456:TESTTOKEN_abc-DEF"

// tgMock is a Telegram Bot API that keeps every sendMessage it receives.
type tgMock struct {
	srv    *httptest.Server
	mu     sync.Mutex
	paths  []string
	bodies []map[string]any
	status int // 0: 200 ok
}

func startTgMock(t *testing.T) *tgMock {
	t.Helper()
	m := &tgMock{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.paths = append(m.paths, r.URL.Path)
		m.bodies = append(m.bodies, body)
		if m.status != 0 {
			http.Error(w, `{"ok":false,"description":"injected"}`, m.status)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *tgMock) setStatus(code int) {
	m.mu.Lock()
	m.status = code
	m.mu.Unlock()
}

// texts returns the text of every message received so far.
func (m *tgMock) texts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, b := range m.bodies {
		s, _ := b["text"].(string)
		out = append(out, s)
	}
	return out
}

// useTelegram points OVPN_TELEGRAM_* at the mock.
func useTelegram(t *testing.T, m *tgMock) {
	t.Helper()
	t.Setenv("OVPN_TELEGRAM_ENABLED", "true")
	t.Setenv("OVPN_TELEGRAM_BOT_TOKEN", testBotToken)
	t.Setenv("OVPN_TELEGRAM_BOT_TOKEN_FILE", "")
	t.Setenv("OVPN_TELEGRAM_CHAT_ID", "42")
	t.Setenv("OVPN_TELEGRAM_THREAD_ID", "")
	t.Setenv("OVPN_TELEGRAM_API_BASE", m.srv.URL)
	t.Setenv("OVPN_TELEGRAM_ALLOW_HTTP", "true")
}

func clearTelegram(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ENABLED", "BOT_TOKEN", "BOT_TOKEN_FILE", "CHAT_ID", "THREAD_ID", "API_BASE", "ALLOW_HTTP"} {
		t.Setenv("OVPN_TELEGRAM_"+k, "")
	}
}

func TestTelegramConfigFromEnv(t *testing.T) {
	m := startTgMock(t)
	t.Run("not enabled", func(t *testing.T) {
		clearTelegram(t)
		if cfg, why := telegramConfigFromEnv(); cfg.enabled || why == "" {
			t.Fatalf("empty settings: enabled=%v why=%q", cfg.enabled, why)
		}
		t.Setenv("OVPN_TELEGRAM_ENABLED", "false")
		if cfg, _ := telegramConfigFromEnv(); cfg.enabled {
			t.Fatal("ENABLED=false is enabled")
		}
		t.Setenv("OVPN_TELEGRAM_ENABLED", "yes")
		if cfg, why := telegramConfigFromEnv(); cfg.enabled || !strings.Contains(why, "true or false") {
			t.Fatalf("ENABLED=yes: enabled=%v why=%q", cfg.enabled, why)
		}
	})
	t.Run("valid", func(t *testing.T) {
		useTelegram(t, m)
		t.Setenv("OVPN_TELEGRAM_THREAD_ID", "77")
		cfg, why := telegramConfigFromEnv()
		if !cfg.enabled || why != "" || cfg.token != testBotToken || cfg.chatID != "42" || cfg.threadID != "77" || cfg.apiBase != m.srv.URL {
			t.Fatalf("cfg = %+v why=%q", cfg, why)
		}
	})
	t.Run("the token file wins and an unusable one is an error", func(t *testing.T) {
		useTelegram(t, m)
		f := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(f, []byte("654321:FILETOKEN_xyz\r\nsecond line\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("OVPN_TELEGRAM_BOT_TOKEN_FILE", f)
		if cfg, why := telegramConfigFromEnv(); !cfg.enabled || cfg.token != "654321:FILETOKEN_xyz" {
			t.Fatalf("token file: %+v %q", cfg, why)
		}
		t.Setenv("OVPN_TELEGRAM_BOT_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
		if cfg, why := telegramConfigFromEnv(); cfg.enabled || strings.Contains(why, testBotToken) {
			t.Fatalf("missing token file must disable, without echoing a value: %+v %q", cfg, why)
		}
	})
	t.Run("malformed values are refused and never echoed", func(t *testing.T) {
		for _, c := range []struct{ k, v string }{
			{"OVPN_TELEGRAM_BOT_TOKEN", "not-a-token"},
			{"OVPN_TELEGRAM_CHAT_ID", "abc def"},
			{"OVPN_TELEGRAM_THREAD_ID", "0"},
			{"OVPN_TELEGRAM_ALLOW_HTTP", "maybe"},
			{"OVPN_TELEGRAM_API_BASE", "ftp://example.org"},
			{"OVPN_TELEGRAM_API_BASE", "http://user:pw@127.0.0.1:1/x"},
			{"OVPN_TELEGRAM_API_BASE", "http://127.0.0.1:99999"},
		} {
			useTelegram(t, m)
			t.Setenv(c.k, c.v)
			cfg, why := telegramConfigFromEnv()
			if cfg.enabled || why == "" {
				t.Errorf("%s=%q is accepted", c.k, c.v)
			}
			if strings.Contains(why, c.v) && len(c.v) > 6 {
				t.Errorf("%s=%q is echoed in %q", c.k, c.v, why)
			}
		}
		// http:// needs ALLOW_HTTP=true
		useTelegram(t, m)
		t.Setenv("OVPN_TELEGRAM_ALLOW_HTTP", "false")
		if cfg, _ := telegramConfigFromEnv(); cfg.enabled {
			t.Error("an http:// base is accepted without ALLOW_HTTP=true")
		}
	})
}

func TestTelegramSendIsPlainText(t *testing.T) {
	m := startTgMock(t)
	useTelegram(t, m)
	t.Setenv("OVPN_TELEGRAM_THREAD_ID", "77")
	cfg, _ := telegramConfigFromEnv()
	if err := telegramSend(context.Background(), cfg, "Certificate: alice *not* _markdown_ <b>x</b>"); err != nil {
		t.Fatal(err)
	}
	if len(m.bodies) != 1 {
		t.Fatalf("%d requests", len(m.bodies))
	}
	if want := "/bot" + testBotToken + "/sendMessage"; m.paths[0] != want {
		t.Errorf("path %q, want %q", m.paths[0], want)
	}
	b := m.bodies[0]
	if _, has := b["parse_mode"]; has {
		t.Error("parse_mode is set: the text must go out as plain text")
	}
	if b["chat_id"] != "42" || b["message_thread_id"] != float64(77) || b["text"] != "Certificate: alice *not* _markdown_ <b>x</b>" {
		t.Errorf("body = %v", b)
	}
}

func TestTelegramSendErrorsNeverCarryTheToken(t *testing.T) {
	m := startTgMock(t)
	useTelegram(t, m)
	cfg, _ := telegramConfigFromEnv()
	for _, code := range []int{400, 401, 429, 500} {
		m.setStatus(code)
		err := telegramSend(context.Background(), cfg, "x")
		if err == nil || strings.Contains(err.Error(), testBotToken) || strings.Contains(err.Error(), "TESTTOKEN") {
			t.Errorf("HTTP %d: err = %v", code, err)
		}
	}
	// a redirect is not followed (it would carry the token to another place)
	redirectTarget := startTgMock(t)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	cfg.apiBase = redir.URL
	if err := telegramSend(context.Background(), cfg, "x"); err == nil {
		t.Error("a redirect was accepted as delivered")
	}
	if len(redirectTarget.bodies) != 0 {
		t.Error("the redirect was followed")
	}
	// nobody listening
	dead := httptest.NewServer(http.NotFoundHandler())
	cfg.apiBase = dead.URL
	dead.Close()
	if err := telegramSend(context.Background(), cfg, "x"); err == nil || strings.Contains(err.Error(), testBotToken) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("connection error = %v", err)
	}
	// ok=false in a 200
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":false}`)) }))
	defer odd.Close()
	cfg.apiBase = odd.URL
	if err := telegramSend(context.Background(), cfg, "x"); err == nil {
		t.Error("ok=false was taken as delivered")
	}
}

func TestSplitTelegramText(t *testing.T) {
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, strings.Repeat("é", 30)+" line")
	}
	text := strings.Join(lines, "\n")
	parts := splitTelegramText(text, telegramMaxText)
	if len(parts) < 2 {
		t.Fatalf("%d parts for %d characters", len(parts), utf8.RuneCountInString(text))
	}
	for i, p := range parts {
		if n := utf8.RuneCountInString(p); n > telegramMaxText || n == 0 {
			t.Errorf("part %d has %d characters", i, n)
		}
	}
	if strings.Join(parts, "\n") != text {
		t.Error("the parts do not add up to the text (they are cut at line breaks)")
	}
	long := strings.Repeat("x", 9500)
	parts = splitTelegramText(long, telegramMaxText)
	if len(parts) != 3 || strings.Join(parts, "") != long {
		t.Errorf("one long line: %d parts", len(parts))
	}
	if got := splitTelegramText("short", telegramMaxText); len(got) != 1 || got[0] != "short" {
		t.Errorf("short text: %v", got)
	}
}

// The port of OVPN_TELEGRAM_API_BASE: a host with a port is valid (the mock of every test has one), a port out
// of 1-65535 or an empty one is not.
func TestTelegramAPIBasePort(t *testing.T) {
	for _, ok := range []string{"https://api.telegram.org", "https://example.com:443/x", "https://[::1]:8443", "https://10.0.0.5:65535"} {
		if got, err := telegramAPIBase(ok, false); err != nil || got != ok {
			t.Errorf("%s: %q %v, want it accepted", ok, got, err)
		}
	}
	if got, err := telegramAPIBase("http://127.0.0.1:8080/", true); err != nil || got != "http://127.0.0.1:8080" {
		t.Errorf("http with the switch: %q %v", got, err)
	}
	for _, bad := range []string{"https://example.com:0", "https://example.com:65536", "https://example.com:", "https://example.com:+80", "https://example.com:80a", "https://[::1]:70000"} {
		if got, err := telegramAPIBase(bad, false); err == nil {
			t.Errorf("%s accepted as %q", bad, got)
		}
	}
}
