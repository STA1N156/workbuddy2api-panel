package panel

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestProxyBindingAPI(t *testing.T) {
	u := upstream.New()
	if err := u.LoadAccountProxies(filepath.Join(t.TempDir(), "proxies.json")); err != nil {
		t.Fatal(err)
	}
	accounts := pool.New("")
	accounts.Add(&auth.Auth{UID: "a", AccessToken: "at"})
	p := New(Config{APIKey: "test-key", Pool: accounts, Upstream: u})
	call := func(key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/panel/api/proxies", strings.NewReader(body))
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}
	body := `{"bindings":[{"uid":"a","proxy_url":"http://user:secret@localhost:1080"}]}`
	if w := call("", body); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("test-key", body); w.Code != 200 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("test-key", `{"bindings":[{"uid":"missing","proxy_url":"http://localhost:1081"}]}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
