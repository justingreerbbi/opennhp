package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Version int `toml:"version"`
	// AllowGET must be set true for a backend to use method GET. The default
	// (false) blocks GET, so an administrator opts in deliberately rather than
	// reaching for a method that cannot carry a request body.
	AllowGET bool               `toml:"allow_get"`
	Backends map[string]Backend `toml:"backends"`
	Bindings map[string]Binding `toml:"bindings"`
}

// Binding permits only administrator-defined operations for a resource.
type Binding struct {
	DefaultOperation string            `toml:"default_operation"`
	Operations       map[string]string `toml:"operations"`
}

type Code struct {
	Path          string `toml:"path"`
	ExpiresInPath string `toml:"expires_in_path"`
	MaxBytes      int    `toml:"max_bytes"`
	MaxTTLSeconds int    `toml:"max_ttl_seconds"`
}

type Backend struct {
	URL              string            `toml:"url"`
	Method           string            `toml:"method"`
	Encoding         string            `toml:"encoding"`
	AllowHTTP        bool              `toml:"allow_http"`
	TimeoutMS        int               `toml:"timeout_ms"`
	MaxResponseBytes int64             `toml:"max_response_bytes"`
	MaxConcurrent    int               `toml:"max_concurrent"`
	Headers          map[string]string `toml:"headers"`
	Fields           []Field           `toml:"fields"`
	Success          Success           `toml:"success"`
	Code             Code              `toml:"code"`
}
type Field struct {
	Source   string `toml:"source"`
	Value    any    `toml:"value"`
	Target   string `toml:"target"`
	Location string `toml:"location"`
	Type     string `toml:"type"`
	Required bool   `toml:"required"`
	MaxBytes int    `toml:"max_bytes"`
}
type Success struct {
	Statuses []int  `toml:"statuses"`
	Path     string `toml:"path"`
	Equals   any    `toml:"equals"`
}

func parseConfig(data []byte) (*Config, error) {
	var c Config
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&c); err != nil {
		return nil, err
	}
	if c.Version != 1 || len(c.Backends) == 0 || len(c.Bindings) == 0 {
		return nil, fmt.Errorf("version 1, backends and bindings are required")
	}
	for name, b := range c.Backends {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("empty backend name")
		}
		u, err := url.Parse(b.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "https" && !(u.Scheme == "http" && b.AllowHTTP)) {
			return nil, fmt.Errorf("backend %s: invalid URL (HTTPS required unless allow_http)", name)
		}
		switch b.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return nil, fmt.Errorf("backend %s: unsupported method", name)
		}
		if b.Method == "GET" && !c.AllowGET {
			return nil, fmt.Errorf("backend %s: GET is blocked by default; set allow_get = true to permit it", name)
		}
		if b.Encoding != "json" && b.Encoding != "form" && b.Encoding != "none" {
			return nil, fmt.Errorf("backend %s: invalid encoding", name)
		}
		if b.TimeoutMS == 0 {
			b.TimeoutMS = 3000
		}
		if b.MaxResponseBytes == 0 {
			b.MaxResponseBytes = 65536
		}
		if b.MaxConcurrent == 0 {
			b.MaxConcurrent = 32
		}
		if b.TimeoutMS < 1 || b.TimeoutMS > 30000 || b.MaxResponseBytes < 1 || b.MaxResponseBytes > 1048576 || b.MaxConcurrent < 1 || b.MaxConcurrent > 1024 {
			return nil, fmt.Errorf("backend %s: invalid limits", name)
		}
		if len(b.Success.Statuses) == 0 {
			return nil, fmt.Errorf("backend %s: explicit success statuses required", name)
		}
		for _, s := range b.Success.Statuses {
			if s < 200 || s > 299 {
				return nil, fmt.Errorf("success status must be 2xx")
			}
		}
		if (b.Success.Path == "") != (b.Success.Equals == nil) {
			return nil, fmt.Errorf("success path and equals must be configured together")
		}
		seen := map[string]bool{}
		for k, v := range b.Headers {
			if !validHeader(k, v) {
				return nil, fmt.Errorf("invalid static header")
			}
			if seen["header:"+strings.ToLower(k)] {
				return nil, fmt.Errorf("duplicate static header")
			}
			seen["header:"+strings.ToLower(k)] = true
		}
		for i, f := range b.Fields {
			if f.Target == "" || (f.Source == "") == (f.Value == nil) {
				return nil, fmt.Errorf("field needs target and exactly one source or value")
			}
			if f.Source != "" && !strings.HasPrefix(f.Source, "userdata.") && f.Source != "user_id" && f.Source != "device_id" && f.Source != "organization_id" {
				return nil, fmt.Errorf("invalid field source")
			}
			if strings.HasPrefix(f.Source, "userdata.") && !validPath(strings.TrimPrefix(f.Source, "userdata.")) {
				return nil, fmt.Errorf("invalid source path")
			}
			if f.Type != "string" && f.Type != "number" && f.Type != "bool" {
				return nil, fmt.Errorf("field type must be string, number or bool")
			}
			if f.MaxBytes == 0 {
				f.MaxBytes = 4096
			}
			if f.MaxBytes < 1 || f.MaxBytes > 16384 {
				return nil, fmt.Errorf("invalid field size limit")
			}
			if f.Value != nil {
				_, value, err := typed(f.Value, f.Type)
				if err != nil || len(value) > f.MaxBytes || (f.Required && value == "") {
					return nil, fmt.Errorf("invalid static field value")
				}
				if f.Location == "header" && !validHeader(f.Target, value) {
					return nil, fmt.Errorf("invalid static header value")
				}
			}
			key := f.Location + ":" + f.Target
			switch f.Location {
			case "header":
				if !validHeader(f.Target, "") {
					return nil, fmt.Errorf("invalid mapped header")
				}
				key = "header:" + strings.ToLower(f.Target)
			case "query":
			case "body":
				if b.Encoding == "none" || b.Method == "GET" || !validPath(f.Target) {
					return nil, fmt.Errorf("invalid body mapping")
				}
			default:
				return nil, fmt.Errorf("invalid field location")
			}
			if seen[key] {
				return nil, fmt.Errorf("duplicate mapping target")
			}
			seen[key] = true
			b.Fields[i] = f
		}
		// Reject ambiguous nested JSON destinations, independent of field order.
		for _, a := range b.Fields {
			for _, z := range b.Fields {
				if a.Location == "body" && z.Location == "body" && b.Encoding == "json" && strings.HasPrefix(z.Target, a.Target+".") {
					return nil, fmt.Errorf("overlapping body targets")
				}
			}
		}
		if b.Success.Path != "" && !validPath(b.Success.Path) {
			return nil, fmt.Errorf("invalid success path")
		}
		if !validPath(b.Code.Path) || !validPath(b.Code.ExpiresInPath) {
			return nil, fmt.Errorf("backend %s: code and expiry paths required", name)
		}
		if b.Code.MaxBytes == 0 {
			b.Code.MaxBytes = 128
		}
		if b.Code.MaxTTLSeconds == 0 {
			b.Code.MaxTTLSeconds = 30
		}
		if b.Code.MaxBytes < 32 || b.Code.MaxBytes > 256 || b.Code.MaxTTLSeconds < 1 || b.Code.MaxTTLSeconds > 60 {
			return nil, fmt.Errorf("backend %s: invalid code limits", name)
		}

		c.Backends[name] = b
	}
	for resource, binding := range c.Bindings {
		if resource == "" || len(binding.Operations) == 0 {
			return nil, fmt.Errorf("resource and operations required")
		}
		if binding.DefaultOperation != "" {
			if _, ok := binding.Operations[binding.DefaultOperation]; !ok {
				return nil, fmt.Errorf("default operation is not configured")
			}
		}
		for operation, backend := range binding.Operations {
			if operation == "" {
				return nil, fmt.Errorf("empty operation")
			}
			if _, ok := c.Backends[backend]; !ok {
				return nil, fmt.Errorf("operation references unknown backend")
			}
		}
	}

	return &c, nil
}
func validPath(s string) bool {
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
	}
	return s != ""
}
func validHeader(k, v string) bool {
	if k == "" || strings.ContainsAny(v, "\r\n\x00") {
		return false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	switch http.CanonicalHeaderKey(k) {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Trailer", "Te", "Proxy-Authorization", "Proxy-Connection", "Content-Type":
		return false
	}
	return true
}
