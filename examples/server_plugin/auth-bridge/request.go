package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func lookup(m map[string]any, path string) (any, bool) {
	var v any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return v, v != nil
}
func put(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, part := range parts[:len(parts)-1] {
		if m[part] == nil {
			m[part] = map[string]any{}
		}
		m = m[part].(map[string]any)
	}
	m[parts[len(parts)-1]] = v
}
func typed(v any, kind string) (any, string, error) {
	switch kind {
	case "string":
		if s, ok := v.(string); ok {
			return s, s, nil
		}
	case "bool":
		if b, ok := v.(bool); ok {
			return b, strconv.FormatBool(b), nil
		}
	case "number":
		raw, err := json.Marshal(v)
		if err == nil && len(raw) > 0 && (raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
			var n json.Number
			if json.Unmarshal(raw, &n) == nil {
				return n, string(raw), nil
			}
		}
	}
	return nil, "", fmt.Errorf("unexpected field type")
}
func buildRequest(ctx context.Context, b Backend, msg *common.AgentKnockMsg) (*http.Request, error) {
	u, err := url.Parse(b.URL)
	if err != nil {
		// parseConfig already validated every backend URL; re-check so a future
		// caller cannot reach http.NewRequestWithContext with a nil *url.URL.
		return nil, fmt.Errorf("cannot construct authentication request")
	}
	q := u.Query()
	form := url.Values{}
	body := map[string]any{}
	headers := http.Header{}
	for k, v := range b.Headers {
		headers.Set(k, v)
	}
	for _, f := range b.Fields {
		v := f.Value
		present := v != nil
		switch f.Source {
		case "user_id":
			v = msg.UserId
			present = true
		case "device_id":
			v = msg.DeviceId
			present = true
		case "organization_id":
			v = msg.OrganizationId
			present = true
		default:
			if f.Source != "" {
				v, present = lookup(msg.UserData, strings.TrimPrefix(f.Source, "userdata."))
			}
		}
		if !present {
			if f.Required {
				return nil, fmt.Errorf("missing required input")
			}
			continue
		}
		value, s, err := typed(v, f.Type)
		if err != nil || len(s) > f.MaxBytes || f.Required && s == "" {
			return nil, fmt.Errorf("invalid input")
		}
		switch f.Location {
		case "body":
			if b.Encoding == "json" {
				put(body, f.Target, value)
			} else {
				form.Set(f.Target, s)
			}
		case "query":
			q.Set(f.Target, s)
		case "header":
			if !validHeader(f.Target, s) {
				return nil, fmt.Errorf("invalid header value")
			}
			headers.Set(f.Target, s)
		}
	}
	var payload []byte
	// A GET carries no request body: body-location fields are rejected for GET
	// at config time, so there is nothing to encode, and sending an empty "{}"
	// body plus a Content-Type on a GET only trips up strict backends.
	if b.Method != "GET" {
		if b.Encoding == "json" {
			payload, _ = json.Marshal(body)
			headers.Set("Content-Type", "application/json")
		}
		if b.Encoding == "form" {
			payload = []byte(form.Encode())
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, b.Method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("cannot construct authentication request")
	}
	req.Header = headers
	return req, nil
}
func authenticate(ctx context.Context, client *http.Client, b Backend, msg *common.AgentKnockMsg) (string, error) {
	req, err := buildRequest(ctx, b, msg)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("authentication backend unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, b.MaxResponseBytes+1))
	if err != nil || int64(len(raw)) > b.MaxResponseBytes {
		return "", fmt.Errorf("invalid backend response")
	}
	success := false
	for _, s := range b.Success.Statuses {
		if resp.StatusCode == s {
			success = true
		}
	}
	if !success {
		return "", fmt.Errorf("authentication denied")
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		return "", fmt.Errorf("invalid backend JSON")
	}
	if b.Success.Path != "" {
		v, ok := lookup(data, b.Success.Path)
		want, _ := json.Marshal(b.Success.Equals)
		got, _ := json.Marshal(v)
		if !ok || !bytes.Equal(got, want) {
			return "", fmt.Errorf("authorization denied")
		}
	}
	value, ok := lookup(data, b.Code.Path)
	code, isString := value.(string)
	if !ok || !isString || len(code) < 32 || len(code) > b.Code.MaxBytes {
		return "", fmt.Errorf("invalid exchange code")
	}
	// Restrict codes to bounded base64url-compatible opaque values, never JSON/JWTs.
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "", fmt.Errorf("invalid exchange code")
		}
	}
	// The code lifetime is validated only as a sanity gate: reject a backend
	// that hands back a long-lived credential. It is not propagated anywhere;
	// the access window comes from the resource's OpenTime, not this value.
	expiry, ok := lookup(data, b.Code.ExpiresInPath)
	seconds, isNumber := expiry.(float64)
	if !ok || !isNumber || seconds < 1 || seconds > float64(b.Code.MaxTTLSeconds) || seconds != float64(int(seconds)) {
		return "", fmt.Errorf("invalid exchange code lifetime")
	}
	return code, nil
}
