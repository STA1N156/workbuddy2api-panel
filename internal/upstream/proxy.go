package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

type proxyTransportKey struct {
	base *http.Transport
	url  string
}

// NormalizeProxyURL accepts explicit proxy endpoints; an empty value removes a binding.
func NormalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("代理地址格式错误")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("代理协议须为 http、https、socks5 或 socks5h")
	}
	_, port, err := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(port)
	if err != nil || u.Hostname() == "" || n < 1 || n > 65535 || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("代理地址须包含主机和端口，且不能带路径或查询参数")
	}
	u.Path = ""
	return u.String(), nil
}

// LoadAccountProxies keeps credentials in a private file alongside state.json.
func (c *Client) LoadAccountProxies(path string) error {
	bindings := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(raw, &bindings); err != nil {
			return fmt.Errorf("parse account proxies: %w", err)
		}
		for uid, proxy := range bindings {
			value, err := NormalizeProxyURL(proxy)
			if err != nil {
				return fmt.Errorf("account %s: %w", uid, err)
			}
			bindings[uid] = value
		}
	}
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	c.proxyFile, c.proxyBindings = path, bindings
	return nil
}

func (c *Client) proxyFor(uid string) string {
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	return c.proxyBindings[uid]
}

// ProxyLabels deliberately excludes proxy usernames/passwords from API responses.
func (c *Client) ProxyLabels() map[string]string {
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	labels := make(map[string]string, len(c.proxyBindings))
	for uid, raw := range c.proxyBindings {
		if u, err := url.Parse(raw); err == nil && raw != "" {
			labels[uid] = u.Scheme + "://" + u.Host
		}
	}
	return labels
}

func (c *Client) SetAccountProxies(updates map[string]string) error {
	normalized := make(map[string]string, len(updates))
	for uid, raw := range updates {
		value, err := NormalizeProxyURL(raw)
		if err != nil {
			return err
		}
		normalized[uid] = value
	}
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	next := make(map[string]string, len(c.proxyBindings)+len(updates))
	for uid, raw := range c.proxyBindings {
		next[uid] = raw
	}
	for uid, raw := range normalized {
		if raw == "" {
			delete(next, uid)
		} else {
			next[uid] = raw
		}
	}
	owners := map[string]string{}
	for uid, raw := range next {
		if previous, exists := owners[raw]; exists && previous != uid {
			return fmt.Errorf("同一代理不能重复绑定多个账号")
		}
		owners[raw] = uid
	}
	if c.proxyFile != "" {
		if err := os.MkdirAll(filepath.Dir(c.proxyFile), 0700); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return err
		}
		tmp := c.proxyFile + ".tmp"
		if err := os.WriteFile(tmp, raw, 0600); err != nil {
			return err
		}
		if err := os.Rename(tmp, c.proxyFile); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	c.proxyBindings = next
	for _, tr := range c.proxyTransports {
		tr.CloseIdleConnections()
	}
	c.proxyTransports = nil
	return nil
}

// do uses the account's fixed proxy for every request type. It never retries directly.
func (c *Client) do(req *http.Request, a *auth.Auth, client *http.Client) (*http.Response, error) {
	proxy := ""
	if a != nil {
		proxy = c.proxyFor(a.UID)
	}
	if proxy == "" {
		return client.Do(req)
	}
	base, ok := client.Transport.(*http.Transport)
	if client.Transport == nil {
		base, ok = http.DefaultTransport.(*http.Transport)
	}
	if !ok {
		return nil, fmt.Errorf("代理连接不可用：不支持的传输类型")
	}
	key := proxyTransportKey{base, proxy}
	c.proxyMu.Lock()
	tr := c.proxyTransports[key]
	if tr == nil {
		u, err := url.Parse(proxy)
		if err != nil {
			c.proxyMu.Unlock()
			return nil, fmt.Errorf("代理地址无效")
		}
		tr = base.Clone()
		tr.Proxy = http.ProxyURL(u)
		if c.proxyTransports == nil {
			c.proxyTransports = make(map[proxyTransportKey]*http.Transport)
		}
		c.proxyTransports[key] = tr
	}
	c.proxyMu.Unlock()
	proxied := *client
	proxied.Transport = tr
	resp, err := proxied.Do(req)
	if err == nil && resp.StatusCode == http.StatusProxyAuthRequired {
		resp.Body.Close()
		err = fmt.Errorf("代理认证失败")
	}
	if err != nil {
		tr.CloseIdleConnections()
		if c.ProxyFailure != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			c.ProxyFailure(a.UID)
		}
		// Do not include the transport's error text: it may contain proxy credentials.
		return nil, fmt.Errorf("账号代理连接失败，请检查代理地址、认证或网络")
	}
	return resp, nil
}

type ProxyCheck struct {
	UID          string `json:"uid"`
	IP           string `json:"ip,omitempty"`
	Milliseconds int64  `json:"milliseconds"`
	Error        string `json:"error,omitempty"`
}

// CheckAccountProxy sends no account token to the IP echo service.
func (c *Client) CheckAccountProxy(ctx context.Context, uid string) ProxyCheck {
	result := ProxyCheck{UID: uid}
	if c.proxyFor(uid) == "" {
		result.Error = "账号尚未绑定代理"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	start := time.Now()
	resp, err := c.do(req, &auth.Auth{UID: uid}, c.HTTP)
	result.Milliseconds = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	var payload struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload) != nil || net.ParseIP(payload.IP) == nil {
		result.Error = "代理出口检测未返回有效 IP"
		return result
	}
	result.IP = payload.IP
	return result
}
