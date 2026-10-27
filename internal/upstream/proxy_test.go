package upstream

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestAccountProxiesSeparateAndPersist(t *testing.T) {
	c := New()
	file := filepath.Join(t.TempDir(), "nested", "account_proxies.json")
	if err := c.LoadAccountProxies(file); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var visits []string
	proxy := func(id string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			visits = append(visits, id+":"+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(r.URL.Path, "chat/completions"):
				io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n")
			case strings.Contains(r.URL.Path, "token/refresh"):
				io.WriteString(w, `{"code":0,"data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}}`)
			case strings.Contains(r.URL.Path, "get-user-resource"):
				io.WriteString(w, `{"code":0,"data":{"Response":{"Data":{"Accounts":[{"PackageName":"p","CycleCapacitySize":30,"CycleCapacityRemain":30}]}}}}`)
			default:
				io.WriteString(w, `{"code":0,"data":{}}`)
			}
		}))
	}
	p1, p2 := proxy("a"), proxy("b")
	defer p1.Close()
	defer p2.Close()
	u, _ := url.Parse(p1.URL)
	u.User = url.UserPassword("user", "private-password")
	if err := c.SetAccountProxies(map[string]string{"a": u.String(), "b": p2.URL}); err != nil {
		t.Fatal(err)
	}
	reloaded := New()
	if err := reloaded.LoadAccountProxies(file); err != nil {
		t.Fatal(err)
	}
	if reloaded.proxyFor("a") != u.String() {
		t.Fatal("binding did not survive restart")
	}
	if strings.Contains(c.ProxyLabels()["a"], "private-password") || strings.Contains(c.ProxyLabels()["a"], "user@") {
		t.Fatal("proxy credentials leaked")
	}
	c.ChatBaseCN, c.BillingBaseCN, c.WebBaseCN = "http://upstream.invalid", "http://upstream.invalid", "http://upstream.invalid"
	for _, uid := range []string{"a", "b"} {
		a := &auth.Auth{UID: uid, AccessToken: "at", RefreshToken: "rt"}
		stream, _, _, err := c.ChatStream(a, []byte(`{"model":"test","messages":[{"role":"user","content":"hi"}],"stream":true}`), "", ChatMeta{})
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, stream)
		stream.Close()
		if err := c.RefreshToken(a); err != nil {
			t.Fatal(err)
		}
		if err := c.DailyCheckin(a); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.UserResource(a); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range []string{"a", "b"} {
		for _, path := range []string{"/v2/chat/completions", "/v2/plugin/auth/token/refresh", "/v2/billing/meter/daily-checkin", "/v2/billing/meter/get-user-resource"} {
			found := false
			for _, visit := range visits {
				if visit == id+":"+path {
					found = true
				}
			}
			if !found {
				t.Errorf("missing proxied request %s:%s; got %v", id, path, visits)
			}
		}
	}
}

func TestBrokenAccountProxyNeverFallsBack(t *testing.T) {
	var direct atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1); w.WriteHeader(200) }))
	defer origin.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	proxyURL := broken.URL
	broken.Close()
	c := New()
	if err := c.SetAccountProxies(map[string]string{"a": proxyURL}); err != nil {
		t.Fatal(err)
	}
	var failed string
	c.ProxyFailure = func(uid string) { failed = uid }
	req, _ := http.NewRequestWithContext(context.Background(), "GET", origin.URL, nil)
	if _, err := c.do(req, &auth.Auth{UID: "a"}, c.HTTP); err == nil {
		t.Fatal("broken proxy succeeded")
	}
	if direct.Load() != 0 || failed != "a" {
		t.Fatalf("direct=%d failed=%s", direct.Load(), failed)
	}
	resp, err := c.do(req, &auth.Auth{UID: "unbound"}, c.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if direct.Load() != 1 {
		t.Fatal("unbound account should retain direct access")
	}
}

func TestAccountProxyHTTPSConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") }))
	defer origin.Close()
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Error("expected CONNECT")
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") == "" {
			t.Error("missing proxy authentication")
		}
		connects.Add(1)
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer target.Close(); defer conn.Close(); io.Copy(target, conn) }()
		go func() { defer target.Close(); defer conn.Close(); io.Copy(conn, target) }()
	}))
	defer proxy.Close()
	c := New()
	c.HTTP = origin.Client()
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("user", "password")
	if err := c.SetAccountProxies(map[string]string{"a": u.String()}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", origin.URL, nil)
	resp, err := c.do(req, &auth.Auth{UID: "a"}, c.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" || connects.Load() != 1 {
		t.Fatalf("body=%s connects=%d", body, connects.Load())
	}
}

func TestProxyValidationAndAtomicUpdates(t *testing.T) {
	c := New()
	if err := c.SetAccountProxies(map[string]string{"a": "http://user:password@127.0.0.1:3128"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ftp://host:1", "http://host", "http://host:0", "http://host:80/path"} {
		if err := c.SetAccountProxies(map[string]string{"a": "", "b": bad}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
		if c.proxyFor("a") == "" {
			t.Fatal("failed update erased existing binding")
		}
	}
	if err := c.SetAccountProxies(map[string]string{"b": c.proxyFor("a")}); err == nil {
		t.Fatal("duplicate proxy accepted")
	}
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		if _, err := NormalizeProxyURL(scheme + "://user:pass@localhost:1080"); err != nil {
			t.Fatal(err)
		}
	}
}
