package datasource

import (
	"strings"
	"time"
)

// Session contains the encrypted provider configuration. Secret fields are never
// serialized by API handlers; use Metadata for externally visible data.
type Session struct {
	ID        string            `json:"id"`
	Owner     string            `json:"owner"`
	Project   string            `json:"project"`
	Provider  string            `json:"provider"`
	Config    map[string]string `json:"-"`
	Revision  int64             `json:"revision"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type Metadata struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	Project    string    `json:"project"`
	Provider   string    `json:"provider"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Configured bool      `json:"configured"`
}

func (s Session) Metadata() Metadata {
	return Metadata{ID: s.ID, Owner: s.Owner, Project: s.Project, Provider: s.Provider, Revision: s.Revision, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, Configured: len(s.Config) > 0}
}

type UpsertRequest struct {
	ID       string            `json:"id"`
	Owner    string            `json:"owner"`
	Project  string            `json:"project"`
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
}

type TestResult struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Supported  bool   `json:"supported"`
}

// SupportedProviders 平台支持的企业数据源 provider 全集（大小写不敏感比较）。
// capabilities 自检用它展示「已配置/未配置」全量清单，Test 用它判定 Supported。
var SupportedProviders = []string{"enscan_go", "aqc", "tyc", "qcc", "kuaicha", "xiaolanben", "fengniao"}

// IsSupportedProvider 大小写不敏感判定 provider 是否在支持清单内。
func IsSupportedProvider(provider string) bool {
	for _, p := range SupportedProviders {
		if strings.EqualFold(provider, p) {
			return true
		}
	}
	return false
}
