package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

const testCode = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func TestMappings(t *testing.T) {
	for _, encoding := range []string{"json", "form", "none"} {
		t.Run(encoding, func(t *testing.T) {
			b := Backend{URL: "https://example.com/oauth/login", Method: "POST", Encoding: encoding, Headers: map[string]string{"Accept": "application/json"}, Fields: []Field{
				{Source: "userdata.username", Target: "login", Location: "query", Type: "string", Required: true, MaxBytes: 200},
				{Source: "userdata.password", Target: "X-Credential", Location: "header", Type: "string", MaxBytes: 200},
			}}
			if encoding != "none" {
				b.Fields = append(b.Fields, Field{Source: "userdata.device.os", Target: "client.os", Location: "body", Type: "string", MaxBytes: 30}, Field{Value: true, Target: "remember", Location: "body", Type: "bool", MaxBytes: 10})
			}
			req, err := buildRequest(context.Background(), b, &common.AgentKnockMsg{UserData: map[string]any{"username": "a+b@example.com", "password": "secret", "device": map[string]any{"os": "ios"}, "url": "https://evil.example"}})
			if err != nil {
				t.Fatal(err)
			}
			if req.URL.Host != "example.com" || req.URL.Query().Get("login") != "a+b@example.com" || req.Header.Get("X-Credential") != "secret" {
				t.Fatal("incorrect mapping")
			}
			raw, _ := io.ReadAll(req.Body)
			if strings.Contains(string(raw), "evil") {
				t.Fatal("unmapped input forwarded")
			}
			if encoding == "json" {
				var data map[string]any
				json.Unmarshal(raw, &data)
				v, ok := lookup(data, "client.os")
				if !ok || v != "ios" || data["remember"] != true {
					t.Fatalf("wrong JSON: %s", raw)
				}
			}
			if encoding == "form" {
				req.Body = io.NopCloser(strings.NewReader(string(raw)))
				if err := req.ParseForm(); err != nil || req.PostForm.Get("client.os") != "ios" || req.PostForm.Get("remember") != "true" {
					t.Fatal("wrong form")
				}
			}
		})
	}
}
func TestSampleAndStrictConfig(t *testing.T) {
	raw, err := os.ReadFile("etc/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseConfig(raw); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"unknown":  strings.Replace(string(raw), "version = 1", "version = 1\nunknown = true", 1),
		"http":     strings.Replace(string(raw), "https://domain.com", "http://domain.com", 1),
		"status":   strings.Replace(string(raw), "statuses = [200]", "statuses = [302]", 1),
		"overlap":  string(raw) + "\n[[backends.application-login.fields]]\nvalue = 'x'\ntarget = 'client'\nlocation = 'body'\ntype = 'string'\n",
		"binding":  strings.Replace(string(raw), "login = \"application-login\"", "login = \"missing\"", 1),
		"override": strings.Replace(string(raw), "Accept = \"application/json\"", "Host = \"evil.example\"", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig([]byte(data)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}
func install(t *testing.T, url string, timeout int) {
	t.Helper()
	Close()
	t.Cleanup(func() { Close() })
	raw, _ := os.ReadFile("etc/config.toml")
	text := strings.Replace(string(raw), "https://domain.com/nhp/authorize", url+"/login", 1)
	text = strings.Replace(text, "https://domain.com/nhp/renew", url+"/renew", 1)
	text = strings.ReplaceAll(text, "allow_http = false", "allow_http = true")
	text = strings.Replace(text, "timeout_ms = 3000", "timeout_ms = "+jsonNumber(timeout), 1)
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "etc"), 0700)
	os.WriteFile(filepath.Join(dir, "etc", "config.toml"), []byte(text), 0600)
	resources, _ := os.ReadFile("etc/resource.toml")
	os.WriteFile(filepath.Join(dir, "etc", "resource.toml"), resources, 0600)
	if err := Init(&plugins.PluginParamsIn{PluginDirPath: &dir}); err != nil {
		t.Fatal(err)
	}
}
func jsonNumber(n int) string { b, _ := json.Marshal(n); return string(b) }
func TestAuthorizationGate(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		delay      time.Duration
		want       bool
	}{
		{"success", `{"authorized":true,"code":"` + testCode + `","expires_in":30,"secret":"hidden"}`, 200, 0, true},
		{"denied", `{"authorized":false}`, 200, 0, false},
		{"wrong-type", `{"authorized":"true"}`, 200, 0, false},
		{"http-error", `{"authorized":true}`, 401, 0, false},
		{"redirect", "", 302, 0, false},
		{"malformed", `not json`, 200, 0, false},
		{"missing-code", `{"authorized":true}`, 200, 0, false},
		{"large-response", strings.Repeat("x", 8193), 200, 0, false},
		{"short-code", `{"authorized":true,"code":"short","expires_in":30}`, 200, 0, false},
		{"non-string-code", `{"authorized":true,"code":123,"expires_in":30}`, 200, 0, false},
		{"json-code", `{"authorized":true,"code":"{\"access_token\":\"abcdefghijklmnopqrstuvwxyz0123456789\"}","expires_in":30}`, 200, 0, false},
		{"missing-expiry", `{"authorized":true,"code":"` + testCode + `"}`, 200, 0, false},
		{"expired-code", `{"authorized":true,"code":"` + testCode + `","expires_in":0}`, 200, 0, false},
		{"excessive-expiry", `{"authorized":true,"code":"` + testCode + `","expires_in":31}`, 200, 0, false},
		{"fractional-expiry", `{"authorized":true,"code":"` + testCode + `","expires_in":1.5}`, 200, 0, false},
		{"string-expiry", `{"authorized":true,"code":"` + testCode + `","expires_in":"30"}`, 200, 0, false},
		{"large-code", `{"authorized":true,"code":"` + strings.Repeat("x", 129) + `","expires_in":30}`, 200, 0, false},
		{"timeout", `{}`, 200, 100 * time.Millisecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				time.Sleep(tc.delay)
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			timeout := 2000
			if tc.name == "timeout" {
				timeout = 20
			}
			install(t, server.URL, timeout)
			invoked := false
			req := &common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", AuthServiceId: "auth-bridge", UserData: map[string]any{"username": "u@example.com", "password": "pw"}}, Ack: &common.ServerKnockAckMsg{}}
			ack, err := AuthWithNHP(req, &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(r *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
				invoked = true
				if res.AuthServiceId != "auth-bridge" || res.OpenTime != 60 {
					t.Error("wrong resource")
				}
				r.Ack.ErrCode = common.ErrSuccess.ErrorCode()
				return r.Ack, nil
			}})
			if invoked != tc.want || (err == nil) != tc.want {
				t.Fatalf("callback=%v err=%v", invoked, err)
			}
			if tc.want {
				if ack.AuthProviderToken != testCode {
					t.Fatal("incorrect exchange code")
				}
			} else if ack.AuthProviderToken != "" {
				t.Fatal("leaked login result")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect followed or duplicate request")
			}
		})
	}
}
func TestInvalidInputDoesNotReachBackend(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	install(t, server.URL, 1000)
	for _, data := range []map[string]any{{"username": "u"}, {"username": true, "password": "pw"}, {"username": "u", "password": strings.Repeat("x", 1025)}} {
		_, err := AuthWithNHP(&common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: data}, Ack: &common.ServerKnockAckMsg{}}, &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Fatal("AC invoked")
			return nil, nil
		}})
		if err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input sent to backend")
	}
}

func TestACFailureWithholdsLoginResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"authorized":true,"code":"`+testCode+`","expires_in":30}`)
	}))
	defer server.Close()
	install(t, server.URL, 1000)
	for _, mode := range []string{"error", "nil", "denial"} {
		t.Run(mode, func(t *testing.T) {
			req := &common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: map[string]any{"username": "u", "password": "p"}}, Ack: &common.ServerKnockAckMsg{}}
			ack, err := AuthWithNHP(req, &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
				if mode == "nil" {
					return nil, nil
				}
				if mode == "error" {
					return req.Ack, context.DeadlineExceeded
				}
				req.Ack.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
				return req.Ack, nil
			}})
			if err == nil || ack == nil || ack.AuthProviderToken != "" {
				t.Fatal("AC failure exposed exchange code")
			}
		})
	}
}
func TestTLSVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS accepted") }))
	defer server.Close()
	install(t, server.URL, 1000)
	_, err := AuthWithNHP(&common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: map[string]any{"username": "u", "password": "p"}}, Ack: &common.ServerKnockAckMsg{}}, &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		t.Fatal("AC invoked")
		return nil, nil
	}})
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
func TestConcurrencyAndShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	install(t, server.URL, 5000)
	stateMu.Lock()
	state.backends["application-login"].slots = make(chan struct{}, 1)
	stateMu.Unlock()
	request := func() error {
		_, err := AuthWithNHP(&common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: map[string]any{"username": "u", "password": "p"}}, Ack: &common.ServerKnockAckMsg{}}, &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("AC invoked")
			return nil, nil
		}})
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- request() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not start")
	}
	if request() == nil || calls.Load() != 1 {
		t.Fatal("concurrency limit not enforced")
	}
	Close()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("shutdown granted access")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel request")
	}
	if request() == nil {
		t.Fatal("closed plugin accepted request")
	}
}
func TestInvalidReplacementDisablesPlugin(t *testing.T) {
	install(t, "http://127.0.0.1:1", 1000)
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "etc"), 0700)
	os.WriteFile(filepath.Join(dir, "etc", "config.toml"), []byte("version = 999"), 0600)
	if Init(&plugins.PluginParamsIn{PluginDirPath: &dir}) == nil {
		t.Fatal("invalid config accepted")
	}
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state != nil {
		t.Fatal("invalid replacement retained prior configuration")
	}
}
func TestHeaderInjection(t *testing.T) {
	b := Backend{URL: "https://example.com/login", Method: "POST", Encoding: "none", Fields: []Field{{Source: "userdata.token", Target: "Authorization", Location: "header", Type: "string", MaxBytes: 100}}}
	if _, err := buildRequest(context.Background(), b, &common.AgentKnockMsg{UserData: map[string]any{"token": "valid\r\nHost: evil.example"}}); err == nil {
		t.Fatal("header injection accepted")
	}
}

func TestOperationRouting(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["resource"] != "existing-api" {
			t.Error("resource binding not forwarded")
		}
		switch r.URL.Path {
		case "/login":
			if body["username"] != "u" || body["password"] != "p" || body["refresh_token"] != nil {
				t.Error("wrong login fields")
			}
		case "/renew":
			if body["refresh_token"] != "refresh" || body["password"] != nil || body["operation"] != nil {
				t.Error("wrong renewal fields")
			}
		default:
			t.Error("unconfigured endpoint")
		}
		io.WriteString(w, `{"authorized":true,"code":"`+testCode+`","expires_in":30}`)
	}))
	defer server.Close()
	install(t, server.URL, 2000)
	helper := &plugins.NhpServerPluginHelper{AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		if req.Ack.AuthProviderToken != "" {
			t.Error("code exposed before AC result")
		}
		req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
		return req.Ack, nil
	}}
	for _, data := range []map[string]any{
		{"username": "u", "password": "p"},
		{"operation": "login", "username": "u", "password": "p"},
		{"operation": "renew", "refresh_token": "refresh", "password": "ignored", "url": "http://evil.invalid"},
	} {
		ack, err := AuthWithNHP(&common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: data}, Ack: &common.ServerKnockAckMsg{}}, helper)
		if err != nil || ack.AuthProviderToken != testCode {
			t.Fatalf("operation failed: %v", err)
		}
		encoded, _ := json.Marshal(ack)
		if strings.Contains(string(encoded), "authData") {
			t.Fatal("core extension remains")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("wrong request count")
	}
	for _, data := range []map[string]any{{"operation": "unknown"}, {"operation": true}, {"operation": ""}, {"operation": "renew", "password": "p"}} {
		ack, err := AuthWithNHP(&common.NhpAuthRequest{Msg: &common.AgentKnockMsg{ResourceId: "existing-api", UserData: data}, Ack: &common.ServerKnockAckMsg{AuthProviderToken: "stale"}}, helper)
		if err == nil || ack.AuthProviderToken != "" {
			t.Fatal("invalid operation accepted")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("invalid operation reached backend")
	}
}
