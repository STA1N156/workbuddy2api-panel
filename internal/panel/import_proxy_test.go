package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestImportBindsProxyBeforeFirstRequest(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"code":0,"data":{"Response":{"Data":{"Accounts":[]}}}}`)
	}))
	defer proxy.Close()
	u := upstream.New()
	u.ChatBaseCN, u.BillingBaseCN = "http://upstream.invalid", "http://upstream.invalid"
	if err := u.LoadAccountProxies(filepath.Join(t.TempDir(), "proxies.json")); err != nil {
		t.Fatal(err)
	}
	p := New(Config{APIKey: "test-key", Pool: pool.New(""), Upstream: u, AuthDir: t.TempDir()})
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, _ := form.CreateFormFile("file", "accounts.json")
	json.NewEncoder(file).Encode([]map[string]any{{"uid": "test-account", "access_token": "at", "refresh_token": "rt", "domain": "codebuddy.cn", "proxy_url": proxy.URL}})
	form.Close()
	r := httptest.NewRequest("POST", "/panel/api/import/cockpit", &body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || calls.Load() < 2 || u.ProxyLabels()["test-account"] != proxy.URL {
		t.Fatalf("status=%d proxy requests=%d bindings=%v body=%s", w.Code, calls.Load(), u.ProxyLabels(), w.Body.String())
	}
}
