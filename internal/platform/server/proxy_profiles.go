package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/traffic"
)

// 代理库：命名代理配置 + 每个用途一个手动选择。
//
// 存储不走新表，而是复用 settings：
//
//	proxy.profiles          JSON 数组 [{id,name,url,note}]
//	proxy.profile.<slot>    该用途选中的代理 ID（空=直连/自定义）
//
// 运行时仍使用既有 URL 设置（global_proxy / web_search_proxy /
// nuclei.proxy / update_proxy），选择代理时把解析后的 URL 写进去，
// 因此各模块不需要知道代理库的存在。
const (
	settingProxyProfiles    = "proxy.profiles"
	settingUpdateProxy      = "update_proxy"
	settingFingerprintProxy = "fingerprint_proxy"

	proxySlotGlobal      = "global"
	proxySlotWebSearch   = "web_search"
	proxySlotNuclei      = "nuclei"
	proxySlotFingerprint = "fingerprint"
	proxySlotUpdate      = "update"
)

var proxySlots = []string{proxySlotGlobal, proxySlotWebSearch, proxySlotNuclei, proxySlotFingerprint, proxySlotUpdate}

// ProxyProfile 是代理库中的一条命名代理。
type ProxyProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Note string `json:"note,omitempty"`
}

// ProxyGallery 是代理库 + 当前选择 + 各用途实际 URL 的聚合视图。
type ProxyGallery struct {
	Profiles   []ProxyProfile    `json:"profiles"`
	Selections map[string]string `json:"selections"`
	URLs       map[string]string `json:"urls"`
}

func proxySelectionKey(slot string) string { return "proxy.profile." + slot }

func validProxySlot(slot string) bool {
	for _, s := range proxySlots {
		if s == slot {
			return true
		}
	}
	return false
}

func loadProxyProfiles(pg interface {
	GetSetting(key string) (string, bool, error)
}) []ProxyProfile {
	stored, ok, err := pg.GetSetting(settingProxyProfiles)
	if err != nil || !ok || strings.TrimSpace(stored) == "" {
		return []ProxyProfile{}
	}
	var out []ProxyProfile
	if json.Unmarshal([]byte(stored), &out) != nil {
		return []ProxyProfile{}
	}
	return out
}

func (s *Server) saveProxyProfiles(profiles []ProxyProfile) error {
	b, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingProxyProfiles, string(b))
}

func findProxyProfile(profiles []ProxyProfile, id string) (ProxyProfile, bool) {
	id = strings.TrimSpace(id)
	for _, p := range profiles {
		if p.ID == id {
			return p, true
		}
	}
	return ProxyProfile{}, false
}

func proxyProfileURL(profiles []ProxyProfile, id string) string {
	if p, ok := findProxyProfile(profiles, id); ok {
		return p.URL
	}
	return ""
}

func (s *Server) proxyGallery() ProxyGallery {
	g := ProxyGallery{
		Profiles:   loadProxyProfiles(s.m.pg),
		Selections: map[string]string{},
		URLs:       map[string]string{},
	}
	if g.Profiles == nil {
		g.Profiles = []ProxyProfile{}
	}
	for _, slot := range proxySlots {
		id, _, _ := s.m.pg.GetSetting(proxySelectionKey(slot))
		g.Selections[slot] = strings.TrimSpace(id)
		switch slot {
		case proxySlotGlobal:
			g.URLs[slot] = s.m.GlobalProxy()
		case proxySlotWebSearch:
			_, _, _, _, proxy := s.m.WebSearch()
			g.URLs[slot] = proxy
		case proxySlotNuclei:
			g.URLs[slot] = s.nucleiManager().Proxy()
		case proxySlotFingerprint:
			g.URLs[slot] = s.m.FingerprintProxy()
		case proxySlotUpdate:
			g.URLs[slot] = s.m.UpdateProxy()
		}
	}
	return g
}

// applyProxySlot 把某个用途切换到指定代理 ID（空=直连），同时写入
// 运行时 URL 设置和选择键。
func (s *Server) applyProxySlot(slot, profileID string) error {
	if !validProxySlot(slot) {
		return fmt.Errorf("未知代理用途: %s", slot)
	}
	profileID = strings.TrimSpace(profileID)
	url := ""
	if profileID != "" {
		p, ok := findProxyProfile(loadProxyProfiles(s.m.pg), profileID)
		if !ok {
			return fmt.Errorf("代理配置不存在: %s", profileID)
		}
		url = p.URL
	}
	if err := s.setProxySlotURL(slot, url); err != nil {
		return err
	}
	return s.m.pg.SetSetting(proxySelectionKey(slot), profileID)
}

func (s *Server) setProxySlotURL(slot, raw string) error {
	raw = strings.TrimSpace(raw)
	switch slot {
	case proxySlotGlobal:
		return s.m.SetGlobalProxy(raw)
	case proxySlotWebSearch:
		return s.m.SetWebSearchProxy(raw)
	case proxySlotNuclei:
		s.nucleiManager().SetProxy(raw)
		return nil
	case proxySlotFingerprint:
		return s.m.SetFingerprintProxy(raw)
	case proxySlotUpdate:
		return s.m.SetUpdateProxy(raw)
	default:
		return fmt.Errorf("未知代理用途: %s", slot)
	}
}

// reconcileProxySelections 在启动时把已选代理的 URL 重新写回运行时设置，
// 避免代理库被外部修改后，存量 URL 与选择不一致。
func (s *Server) reconcileProxySelections() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	profiles := loadProxyProfiles(s.m.pg)
	for _, slot := range proxySlots {
		id, ok, _ := s.m.pg.GetSetting(proxySelectionKey(slot))
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			continue
		}
		url := proxyProfileURL(profiles, id)
		if url == "" {
			// 选中的配置被删了：清空选择，保持当前 URL 不变。
			_ = s.m.pg.SetSetting(proxySelectionKey(slot), "")
			continue
		}
		_ = s.setProxySlotURL(slot, url)
	}
}

// rebuildAgentsForProxyChange 让 global / web_search 的代理改动立即进入
// agent 的 bash 环境、WebFetch 与搜索工具。
func (s *Server) rebuildAgentsForProxyChange() error {
	s.cfgMu.Lock()
	cfg, on := s.llmCfg, s.llmOn
	s.cfgMu.Unlock()
	if !on {
		return nil
	}
	return s.applyLLM(cfg)
}

func proxySlotNeedsRebuild(slot string) bool {
	return slot == proxySlotGlobal || slot == proxySlotWebSearch
}

func validateProxyProfileInput(name, rawURL string) (string, string, error) {
	name = strings.TrimSpace(name)
	rawURL = strings.TrimSpace(rawURL)
	if name == "" {
		return "", "", fmt.Errorf("代理名称不能为空")
	}
	if len([]rune(name)) > 64 {
		return "", "", fmt.Errorf("代理名称最多 64 个字符")
	}
	if _, err := traffic.ValidateProxyURL(rawURL); err != nil {
		return "", "", err
	}
	return name, rawURL, nil
}

func newProxyProfileID() string {
	return "p-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// GET /api/proxy-profiles
func (s *Server) getProxyProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.proxyGallery())
}

// POST /api/proxy-profiles {name,url,note}
func (s *Server) createProxyProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name, rawURL, err := validateProxyProfileInput(body.Name, body.URL)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	profiles := loadProxyProfiles(s.m.pg)
	if len(profiles) >= 50 {
		writeErr(w, 400, "代理配置最多 50 条")
		return
	}
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) {
			writeErr(w, 400, "代理名称已存在: "+name)
			return
		}
	}
	p := ProxyProfile{ID: newProxyProfileID(), Name: name, URL: rawURL, Note: strings.TrimSpace(body.Note)}
	profiles = append(profiles, p)
	if err := s.saveProxyProfiles(profiles); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, p)
}

// PUT /api/proxy-profiles/{id} {name,url,note}
func (s *Server) updateProxyProfile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name, rawURL, err := validateProxyProfileInput(body.Name, body.URL)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	profiles := loadProxyProfiles(s.m.pg)
	idx := -1
	for i := range profiles {
		if profiles[i].ID == id {
			idx = i
			continue
		}
		if strings.EqualFold(profiles[i].Name, name) {
			writeErr(w, 400, "代理名称已存在: "+name)
			return
		}
	}
	if idx < 0 {
		writeErr(w, 404, "代理配置不存在")
		return
	}
	profiles[idx].Name = name
	profiles[idx].URL = rawURL
	profiles[idx].Note = strings.TrimSpace(body.Note)
	if err := s.saveProxyProfiles(profiles); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 若该配置被某个用途选中，同步更新运行时 URL。
	rebuild := false
	for _, slot := range proxySlots {
		if selected, _, _ := s.m.pg.GetSetting(proxySelectionKey(slot)); strings.TrimSpace(selected) == id {
			if err := s.setProxySlotURL(slot, rawURL); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			rebuild = rebuild || proxySlotNeedsRebuild(slot)
		}
	}
	if rebuild {
		if err := s.rebuildAgentsForProxyChange(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, profiles[idx])
}

// DELETE /api/proxy-profiles/{id}
func (s *Server) deleteProxyProfile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	profiles := loadProxyProfiles(s.m.pg)
	out := make([]ProxyProfile, 0, len(profiles))
	found := false
	for _, p := range profiles {
		if p.ID == id {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		writeErr(w, 404, "代理配置不存在")
		return
	}
	if err := s.saveProxyProfiles(out); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rebuild := false
	for _, slot := range proxySlots {
		if selected, _, _ := s.m.pg.GetSetting(proxySelectionKey(slot)); strings.TrimSpace(selected) == id {
			if err := s.applyProxySlot(slot, ""); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			rebuild = rebuild || proxySlotNeedsRebuild(slot)
		}
	}
	if rebuild {
		if err := s.rebuildAgentsForProxyChange(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// PUT /api/proxy-profiles/selection {slot, profile_id}
func (s *Server) selectProxyProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slot      string `json:"slot"`
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.applyProxySlot(strings.TrimSpace(body.Slot), strings.TrimSpace(body.ProfileID)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if proxySlotNeedsRebuild(strings.TrimSpace(body.Slot)) {
		if err := s.rebuildAgentsForProxyChange(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, s.proxyGallery())
}

// POST /api/proxy-profiles/test {url}
func (s *Server) testProxyProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, err := traffic.ValidateProxyURL(strings.TrimSpace(body.URL))
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
		},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/", nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "4zrec-proxy-test/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "elapsed_ms": elapsed})
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// 能拿到目标响应即说明代理链路是通的；407/5xx 才视为失败。
	ok := resp.StatusCode != http.StatusProxyAuthRequired && resp.StatusCode < 500
	out := map[string]any{"ok": ok, "status": resp.StatusCode, "elapsed_ms": elapsed}
	switch {
	case resp.StatusCode == http.StatusProxyAuthRequired:
		out["error"] = "代理认证失败（HTTP 407）"
	case resp.StatusCode >= 500:
		out["error"] = fmt.Sprintf("目标返回 HTTP %d", resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden:
		out["warning"] = "代理已连通，但目标返回 403（可能是节点 IP 被限流）"
	}
	writeJSON(w, 200, out)
}
