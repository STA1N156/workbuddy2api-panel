package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

func TestChatTargetUIDDoesNotRotate(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "upstream_rejection"}[rejected], func(t *testing.T) {
			calls := map[string]int{}
			up := newFakeUpstream(t, func(authz string) (int, string, bool) {
				calls[authz]++
				if rejected && authz == "Bearer at-target" {
					return 403, `{"code":11140,"msg":"request illegal"}`, false
				}
				return 200, sseOK, true
			})
			p := testPoolWith(
				&auth.Auth{UID: "other", AccessToken: "at-other", ExpiresAt: 9999999999},
				&auth.Auth{UID: "target", AccessToken: "at-target", ExpiresAt: 9999999999},
			)
			p.SetCredits("other", 2000, 0)
			h := NewHandler(Config{Pool: p, Upstream: up, APIKey: "test-key"})
			r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","messages":[{"role":"user","content":"Reply OK."}]}`))
			r.Header.Set("Authorization", "Bearer test-key")
			r.Header.Set("X-Account-UID", "target")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantStatus := http.StatusOK
			if rejected {
				wantStatus = http.StatusServiceUnavailable
			}
			if w.Code != wantStatus || w.Header().Get("X-Account-UID") != "target" {
				t.Fatalf("status=%d target=%q body=%s", w.Code, w.Header().Get("X-Account-UID"), w.Body)
			}
			if calls["Bearer at-target"] != 1 || calls["Bearer at-other"] != 0 {
				t.Fatalf("calls=%v; target must be the only attempted account", calls)
			}
		})
	}
}

func TestChatTargetUIDPreservesRestrictions(t *testing.T) {
	for _, state := range []string{"paused", "disabled", "cooling", "model_cooling", "unknown"} {
		t.Run(state, func(t *testing.T) {
			calls := 0
			up := newFakeUpstream(t, func(string) (int, string, bool) {
				calls++
				return 200, sseOK, true
			})
			p := testPoolWith(
				&auth.Auth{UID: "target", AccessToken: "at-target", ExpiresAt: 9999999999},
				&auth.Auth{UID: "other", AccessToken: "at-other", ExpiresAt: 9999999999},
			)
			uid := "target"
			switch state {
			case "paused":
				p.Pause(uid)
			case "disabled":
				p.Disable(uid, "test")
			case "cooling":
				p.Cooldown(uid, pool.CoolSoft, time.Hour, "429 rate limit")
			case "model_cooling":
				p.BlockModelBackoff(uid, "glm-5.2", "model rate limit")
			case "unknown":
				uid = "missing"
			}
			h := NewHandler(Config{Pool: p, Upstream: up})
			r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","messages":[]}`))
			r.Header.Set("X-Account-UID", uid)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "account_unavailable") || calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body)
			}
		})
	}
}
