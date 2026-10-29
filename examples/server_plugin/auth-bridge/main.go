// auth-bridge adapts an administrator-defined HTTPS authentication API to NHP.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type runtimeBackend struct {
	config Backend
	client *http.Client
	slots  chan struct{}
}
type runtimeState struct {
	config    *Config
	resources common.ResourceGroupMap
	backends  map[string]*runtimeBackend
	ctx       context.Context
	cancel    context.CancelFunc
}

var stateMu sync.RWMutex
var state *runtimeState

func Version() string                        { return "auth-bridge v0.1.0-alpha.1" }
func Signature() string                      { return "auth-bridge/0.1.0-alpha.1" }
func ExportedData() *plugins.PluginParamsOut { return &plugins.PluginParamsOut{} }
func Init(in *plugins.PluginParamsIn) error {
	if in == nil || in.PluginDirPath == nil {
		return fmt.Errorf("plugin directory required")
	}
	// Clear the old runtime first: invalid replacement configuration cannot retain access.
	Close()
	raw, err := os.ReadFile(filepath.Join(*in.PluginDirPath, "etc", "config.toml"))
	if err != nil {
		return fmt.Errorf("read plugin config: %w", err)
	}
	conf, err := parseConfig(raw)
	if err != nil {
		return fmt.Errorf("invalid plugin config: %w", err)
	}
	raw, err = os.ReadFile(filepath.Join(*in.PluginDirPath, "etc", "resource.toml"))
	if err != nil {
		return fmt.Errorf("read resource config: %w", err)
	}
	resources := common.ResourceGroupMap{}
	if err = toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields().Decode(&resources); err != nil {
		return fmt.Errorf("invalid resource config: %w", err)
	}
	for id := range conf.Bindings {
		res := resources[id]
		if res == nil || res.SkipAuth || res.OpenTime == 0 || len(res.Resources) == 0 {
			return fmt.Errorf("binding %s requires resources, positive OpenTime and SkipAuth=false", id)
		}
		for _, info := range res.Resources {
			if info == nil || info.ACId == "" || info.Addr == nil || net.ParseIP(info.Addr.Ip) == nil || info.Addr.Port < 1 || info.Addr.Port > 65535 || (info.Addr.Protocol != "tcp" && info.Addr.Protocol != "udp") {
				return fmt.Errorf("resource %s requires explicit AC, IP, port and tcp/udp protocol", id)
			}
		}
		res.ResourceId = id
	}
	for id := range resources {
		if _, ok := conf.Bindings[id]; !ok {
			return fmt.Errorf("resource %s has no backend binding", id)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	next := &runtimeState{config: conf, resources: resources, backends: map[string]*runtimeBackend{}, ctx: ctx, cancel: cancel}
	for name, b := range conf.Backends {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil // Do not inherit an environment proxy for credential-bearing requests.
		transport.MaxConnsPerHost = b.MaxConcurrent
		transport.MaxIdleConnsPerHost = b.MaxConcurrent
		next.backends[name] = &runtimeBackend{config: b, slots: make(chan struct{}, b.MaxConcurrent), client: &http.Client{Transport: transport, Timeout: time.Duration(b.TimeoutMS) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	stateMu.Lock()
	state = next
	stateMu.Unlock()
	return nil
}
func Close() error {
	stateMu.Lock()
	old := state
	state = nil
	stateMu.Unlock()
	if old != nil {
		old.cancel()
		for _, b := range old.backends {
			b.client.CloseIdleConnections()
		}
	}
	return nil
}
func deny(req *common.NhpAuthRequest) (*common.ServerKnockAckMsg, error) {
	ack := &common.ServerKnockAckMsg{}
	if req != nil && req.Ack != nil {
		ack = req.Ack
	}
	ack.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
	ack.ErrMsg = "authentication denied"
	ack.AuthProviderToken = ""
	return ack, fmt.Errorf("authentication denied")
}
func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if req == nil || req.Msg == nil || req.Ack == nil || helper == nil || helper.AuthWithNhpCallbackFunc == nil {
		return deny(req)
	}
	stateMu.RLock()
	current := state
	stateMu.RUnlock()
	if current == nil {
		return deny(req)
	}
	res := current.resources[req.Msg.ResourceId]
	binding, found := current.config.Bindings[req.Msg.ResourceId]
	if !found {
		return deny(req)
	}
	operation := binding.DefaultOperation
	if supplied, exists := req.Msg.UserData["operation"]; exists {
		var ok bool
		operation, ok = supplied.(string)
		if !ok || operation == "" {
			return deny(req)
		}
	}
	profile, allowed := binding.Operations[operation]
	if !allowed {
		return deny(req)
	}
	backend := current.backends[profile]
	if res == nil || backend == nil {
		return deny(req)
	}
	select {
	case backend.slots <- struct{}{}:
		defer func() { <-backend.slots }()
	default:
		return deny(req)
	}
	ctx, cancel := context.WithTimeout(current.ctx, time.Duration(backend.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-helper.StopSignal:
			cancel()
		case <-done:
		}
	}()
	code, err := authenticate(ctx, backend.client, backend.config, req.Msg)
	if err != nil || ctx.Err() != nil {
		return deny(req)
	}
	// Do not mutate shared resource configuration or trust client-provided resource metadata.
	resource := *res
	resource.AuthServiceId = req.Msg.AuthServiceId
	req.Ack.OpenTime = resource.OpenTime
	req.Ack.AuthProviderToken = ""
	ack, err := helper.AuthWithNhpCallbackFunc(req, &resource)
	if err != nil || ack == nil || ack.ErrCode != common.ErrSuccess.ErrorCode() {
		if err == nil {
			err = fmt.Errorf("access controller did not grant access")
		}
		if ack == nil {
			return deny(req)
		}
		ack.AuthProviderToken = ""
		return ack, err
	}
	ack.AuthProviderToken = code
	return ack, nil
}
func AuthWithHttp(*gin.Context, *common.HttpKnockRequest, *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, fmt.Errorf("use an encrypted NHP knock")
}
