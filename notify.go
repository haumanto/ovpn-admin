package main

// Telegram messages that the panel sends by itself (certificate expiry notices). It is a second, independent
// sender: the ban script has its own shell and Python path (setup/ovpn-telegram-notify.py) and is not reused. The
// settings are the same OVPN_TELEGRAM_* variables, with the same validation rules as that script, so a value
// that one refuses is refused by the other. Plain text only (no parse_mode), at most 4000 characters a message.
//
// The bot token is a secret: it is part of the request URL, so no error that leaves this file carries a URL,
// and nothing here writes the token, the chat id or the response body to a log.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	telegramDefaultAPIBase = "https://api.telegram.org"
	telegramMaxText        = 4000
	telegramTimeout        = 10 * time.Second
	telegramTokenFileMax   = 300
)

var (
	telegramTokenRe  = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{1,128}$`)
	telegramChatIDRe = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$`)
	telegramThreadRe = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	telegramHostRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
)

// telegramConfig is what OVPN_TELEGRAM_* says. enabled is only true for a complete, valid set of values.
type telegramConfig struct {
	enabled  bool
	token    string // secret
	chatID   string
	threadID string
	apiBase  string
}

// telegramConfigFromEnv reads the settings. A disabled or an invalid configuration is not an error for the
// caller: enabled is false and why says so in one sentence that never holds a value (the token, the chat id).
func telegramConfigFromEnv() (cfg telegramConfig, why string) {
	switch v := os.Getenv("OVPN_TELEGRAM_ENABLED"); v {
	case "true":
	case "", "false":
		return cfg, "OVPN_TELEGRAM_ENABLED is not true"
	default:
		return cfg, "OVPN_TELEGRAM_ENABLED must be true or false"
	}

	var problems []string
	token := os.Getenv("OVPN_TELEGRAM_BOT_TOKEN")
	tokenSrc := "OVPN_TELEGRAM_BOT_TOKEN"
	if file := os.Getenv("OVPN_TELEGRAM_BOT_TOKEN_FILE"); file != "" {
		// the file wins; an unusable file is an error, never a silent fall back to the variable
		tokenSrc = "OVPN_TELEGRAM_BOT_TOKEN_FILE"
		token = ""
		if t, err := readTelegramTokenFile(file); err != nil {
			problems = append(problems, "OVPN_TELEGRAM_BOT_TOKEN_FILE is not a readable regular file")
		} else {
			token = t
		}
	}
	if token == "" {
		if tokenSrc == "OVPN_TELEGRAM_BOT_TOKEN" || len(problems) == 0 {
			problems = append(problems, tokenSrc+" is not set or the file is empty")
		}
	} else if !telegramTokenRe.MatchString(token) {
		problems = append(problems, tokenSrc+" does not hold a bot token")
	}

	chat := os.Getenv("OVPN_TELEGRAM_CHAT_ID")
	if !telegramChatIDRe.MatchString(chat) {
		problems = append(problems, "OVPN_TELEGRAM_CHAT_ID is missing or malformed")
	}
	thread := os.Getenv("OVPN_TELEGRAM_THREAD_ID")
	if thread != "" && !telegramThreadRe.MatchString(thread) {
		problems = append(problems, "OVPN_TELEGRAM_THREAD_ID must be a positive integer")
	}
	allowHTTP := false
	switch os.Getenv("OVPN_TELEGRAM_ALLOW_HTTP") {
	case "true":
		allowHTTP = true
	case "", "false":
	default:
		problems = append(problems, "OVPN_TELEGRAM_ALLOW_HTTP must be true or false")
	}
	base, err := telegramAPIBase(os.Getenv("OVPN_TELEGRAM_API_BASE"), allowHTTP)
	if err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return cfg, strings.Join(problems, "; ")
	}
	return telegramConfig{enabled: true, token: token, chatID: chat, threadID: thread, apiBase: base}, ""
}

// readTelegramTokenFile returns the first line of a regular file, at most telegramTokenFileMax characters, without
// the trailing CR: the same rule as configure.sh.
func readTelegramTokenFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, telegramTokenFileMax)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	line := string(buf[:n])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSuffix(line, "\r"), nil
}

// telegramAPIBase is the validator of OVPN_TELEGRAM_API_BASE (api_base of setup/ovpn-telegram-notify.py): https://,
// http:// only with allowHTTP; a host name, an IPv4 address or a bracketed IPv6 address; an optional numeric port
// 1-65535; an optional path. No user info, query, fragment, whitespace, control character or backslash. The error
// text never echoes the value. It returns the base without a trailing slash.
func telegramAPIBase(raw string, allowHTTP bool) (string, error) {
	base := raw
	if base == "" {
		base = telegramDefaultAPIBase
	}
	for _, r := range base {
		if r >= 0x80 || r < 32 || r == 127 || r == ' ' || r == '\\' {
			return "", errors.New("OVPN_TELEGRAM_API_BASE must be plain ASCII without spaces, control characters or backslashes")
		}
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", errors.New("OVPN_TELEGRAM_API_BASE has a malformed host, bracket or port")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("OVPN_TELEGRAM_API_BASE must be an https:// URL (http:// only with OVPN_TELEGRAM_ALLOW_HTTP=true)")
	}
	if u.Scheme == "http" && !allowHTTP {
		return "", errors.New("OVPN_TELEGRAM_API_BASE uses http://: refused unless OVPN_TELEGRAM_ALLOW_HTTP=true (local mock tests only)")
	}
	if strings.ContainsAny(base, "?#") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("OVPN_TELEGRAM_API_BASE must not carry a query or a fragment")
	}
	if strings.Contains(u.Host, "@") || u.User != nil {
		return "", errors.New("OVPN_TELEGRAM_API_BASE must not carry user info (credentials)")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("OVPN_TELEGRAM_API_BASE needs a host name")
	}
	if strings.ContainsAny(u.Host, "[]") {
		if _, err := netip.ParseAddr(host); err != nil || !strings.Contains(host, ":") {
			return "", errors.New("OVPN_TELEGRAM_API_BASE has a malformed bracket (not an IPv6 address)")
		}
		if !strings.HasPrefix(u.Host, "[") || !strings.Contains(u.Host, "]") {
			return "", errors.New("OVPN_TELEGRAM_API_BASE has a malformed bracket")
		}
	} else if !telegramHostRe.MatchString(host) || len(host) > 253 {
		return "", errors.New("OVPN_TELEGRAM_API_BASE needs a valid host name or IPv4 address")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("OVPN_TELEGRAM_API_BASE has an empty port (write host:PORT or leave the colon out)")
	}
	portText := u.Port()
	if portText != "" {
		n, err := strconv.Atoi(portText)
		if err != nil || n < 1 || n > 65535 || strings.TrimLeft(portText, "0123456789") != "" {
			return "", errors.New("OVPN_TELEGRAM_API_BASE port must be a number from 1 to 65535")
		}
	}
	return strings.TrimRight(base, "/"), nil
}

// telegramHTTPClient never follows a redirect: it would forward the request, and with it the token in the URL
// path, to another place. Tests replace it.
var telegramHTTPClient = &http.Client{
	Timeout: telegramTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// telegramSend posts one message. The error names the class of the failure (HTTP status, timeout, connection),
// never the URL, the token or the response body.
func telegramSend(ctx context.Context, cfg telegramConfig, text string) error {
	payload := map[string]any{"chat_id": cfg.chatID, "text": text, "disable_web_page_preview": true}
	if cfg.threadID != "" {
		n, err := strconv.ParseInt(cfg.threadID, 10, 64)
		if err != nil {
			return errors.New("OVPN_TELEGRAM_THREAD_ID is not a number")
		}
		payload["message_thread_id"] = n
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("the message could not be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.apiBase+"/bot"+cfg.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("the request could not be built")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := telegramHTTPClient.Do(req)
	if err != nil {
		// *url.Error holds the URL, which holds the token: only its class leaves
		var ne net.Error
		switch {
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
			return errors.New("cannot reach the Telegram API (timeout)")
		case errors.Is(err, context.Canceled):
			return errors.New("the request was cancelled")
		}
		return errors.New("cannot reach the Telegram API (connection failed)")
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram answered HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Ok bool `json:"ok"`
	}
	if json.Unmarshal(answer, &parsed) != nil || !parsed.Ok {
		return errors.New("Telegram answered without ok=true")
	}
	return nil
}

// splitTelegramText cuts text into messages of at most limit characters, at line breaks where it can. A single
// line that is longer than limit is cut inside the line.
func splitTelegramText(text string, limit int) []string {
	if limit <= 0 {
		limit = telegramMaxText
	}
	var out []string
	var cur []string
	curLen := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.Join(cur, "\n"))
			cur, curLen = nil, 0
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for utf8.RuneCountInString(line) > limit {
			flush()
			r := []rune(line)
			out = append(out, string(r[:limit]))
			line = string(r[limit:])
		}
		n := utf8.RuneCountInString(line)
		add := n
		if len(cur) > 0 {
			add++
		}
		if curLen+add > limit {
			flush()
			add = n
		}
		cur = append(cur, line)
		curLen += add
	}
	flush()
	return out
}
