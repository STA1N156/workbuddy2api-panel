package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestConversationHeaderWithUserIDSurvivesRotation(t *testing.T) {
	for _, fields := range []string{
		`"metadata":{"user_id":"private-user"}`,
		`"user_id":"private-user"`,
		`"metadata":{"user_id":"private-user","conversation_id":"explicit-conversation"}`,
	} {
		t.Run(fields, func(t *testing.T) {
			var ids []string
			up := &upstream.Client{ChatBaseCN: "https://fake.example", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				ids = append(ids, r.Header.Get("X-Conversation-ID"))
				status, body, ct := 200, sseOK, "text/event-stream"
				if len(ids) == 1 {
					status, body, ct = 401, `{"code":12153,"msg":"Offline user session not found"}`, "application/json"
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{ct}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "a", ExpiresAt: 9999999999}, &auth.Auth{UID: "u2", AccessToken: "b", ExpiresAt: 9999999999})
			h := NewHandler(Config{Pool: p, Upstream: up})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{`+fields+`,"model":"glm-5.2","messages":[{"role":"user","content":"hello"}]}`)))
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			if len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] {
				t.Fatalf("rotation IDs=%v", ids)
			}
			if strings.Contains(ids[0], "private-user") {
				t.Fatalf("user ID leaked: %q", ids[0])
			}
			if strings.Contains(fields, "conversation_id") && ids[0] != "explicit-conversation" {
				t.Fatalf("explicit ID lost: %v", ids)
			}
		})
	}
}

func TestRefreshCredentialFailureCoolsWithoutDisabling(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		cooldown   int64
	}{
		{"session-dead", `{"code":12153,"msg":"Offline user session not found"}`, 60},
		{"request-illegal", `{"code":11140,"msg":"request illegal"}`, 1800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			up := newFakeUpstream(t, func(string) (int, string, bool) { calls++; return 401, tc.body, false })
			p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "a", RefreshToken: "r", ExpiresAt: 1})
			h := NewHandler(Config{Pool: p, Upstream: up, MaxRotate: 3})
			for i := 0; i < 2; i++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","messages":[]}`)))
				if rec.Code != 503 {
					t.Fatalf("status=%d", rec.Code)
				}
			}
			st, _ := p.Status("u1")
			if calls != 1 || st.Disabled || !st.Cooling || st.CoolRemaining < tc.cooldown-1 || st.CoolRemaining > tc.cooldown {
				t.Fatalf("refresh calls=%d status=%+v", calls, st)
			}
		})
	}
}

func TestRequestIllegalPolicyDoesNotChangeOtherVariants(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		cooldown   int64
		disables   bool
	}{
		{"request-illegal", `{"code":11140,"msg":"request illegal"}`, 1800, true},
		{"model-rate-limit", `{"code":11140,"msg":"The model provider is rate-limiting requests."}`, 60, false},
		{"trial-not-activated", `{"code":14017,"msg":"trial not activated"}`, 60, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPoolWith(&auth.Auth{UID: "u1"})
			h := NewHandler(Config{Pool: p, SoftCooldown: time.Minute})
			kind := upstream.Classify(403, tc.body)
			for i := 0; i < 3; i++ {
				h.applyErrorPolicy("u1", kind, tc.body, "glm-5.2", nil)
				st, _ := p.Status("u1")
				if st.Disabled != (tc.disables && i == 2) {
					t.Fatalf("failure %d status=%+v", i+1, st)
				}
				if i == 0 && (!st.Cooling || st.CoolRemaining < tc.cooldown-1 || st.CoolRemaining > tc.cooldown) {
					t.Fatalf("cooldown=%+v", st)
				}
			}
			if tc.disables && p.Pick() != nil {
				t.Fatal("disabled account selected")
			}
		})
	}
}

func TestRefreshSuccessClearsCredentialFailures(t *testing.T) {
	for _, illegal := range []bool{false, true} {
		t.Run(map[bool]string{false: "session-dead", true: "request-illegal"}[illegal], func(t *testing.T) {
			p := testPoolWith(&auth.Auth{UID: "u1", AccessToken: "a", RefreshToken: "r", ExpiresAt: 1})
			note := p.NoteSessionDead
			if illegal {
				note = p.NoteRequestIllegal
			}
			note("u1")
			note("u1")
			p.Cooldown("u1", pool.CoolSoft, 0, "expired")
			up := newFakeUpstream(t, func(string) (int, string, bool) {
				return 200, `{"code":0,"data":{"accessToken":"new","expiresIn":3600}}`, false
			})
			// Chat fails after refresh; only refresh success can clear the counter.
			transport := up.HTTP.Transport
			up.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "/auth/token/refresh") {
					return transport.RoundTrip(r)
				}
				return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"msg":"unavailable"}`))}, nil
			})
			h := NewHandler(Config{Pool: p, Upstream: up})
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","messages":[]}`)))
			if note("u1") || note("u1") {
				t.Fatal("refresh success did not reset credential failures")
			}
		})
	}
}
