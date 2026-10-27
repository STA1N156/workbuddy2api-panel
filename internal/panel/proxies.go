package panel

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func (p *Panel) accountProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Bindings []struct {
			UID string `json:"uid"`
			URL string `json:"proxy_url"`
		} `json:"bindings"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil || len(body.Bindings) == 0 {
		writeErr(w, 400, "请提供代理绑定列表")
		return
	}
	updates := make(map[string]string, len(body.Bindings))
	for _, b := range body.Bindings {
		if p.cfg.Pool.AuthByUID(b.UID) == nil {
			writeErr(w, 400, "账号不存在："+b.UID)
			return
		}
		if _, exists := updates[b.UID]; exists {
			writeErr(w, 400, "绑定列表包含重复账号")
			return
		}
		value, err := upstream.NormalizeProxyURL(b.URL)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		updates[b.UID] = value
	}
	if err := p.cfg.Upstream.SetAccountProxies(updates); err != nil {
		writeErr(w, 500, "代理配置保存失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "updated": len(updates), "proxies": p.cfg.Upstream.ProxyLabels()})
}

func (p *Panel) checkAccountProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UIDs []string `json:"uids"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil || len(body.UIDs) == 0 || len(body.UIDs) > 1000 {
		writeErr(w, 400, "请选择需要检测的账号")
		return
	}
	seen := map[string]bool{}
	for _, uid := range body.UIDs {
		if seen[uid] || p.cfg.Pool.AuthByUID(uid) == nil {
			writeErr(w, 400, "账号不存在或重复")
			return
		}
		seen[uid] = true
	}
	results := make([]upstream.ProxyCheck, len(body.UIDs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, uid := range body.UIDs {
		wg.Add(1)
		go func(i int, uid string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-r.Context().Done():
				return
			}
			results[i] = p.cfg.Upstream.CheckAccountProxy(r.Context(), uid)
		}(i, uid)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"results": results})
}
