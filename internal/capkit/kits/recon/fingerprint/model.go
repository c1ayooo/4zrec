package fingerprint

// Pattern is one match primitive. Types:
//
//	body | header | cookie | url | title | script | meta | favicon
type Pattern struct {
	Type    string `json:"type" yaml:"type"`
	Part    string `json:"part,omitempty" yaml:"part,omitempty"` // header/cookie/meta key
	Value   string `json:"value" yaml:"value"`
	Regex   bool   `json:"regex,omitempty" yaml:"regex,omitempty"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// Rule identifies one technology.
type Rule struct {
	ID       string    `json:"id" yaml:"id"`
	Name     string    `json:"name" yaml:"name"`
	Product  string    `json:"product,omitempty" yaml:"product,omitempty"`
	Category string    `json:"category,omitempty" yaml:"category,omitempty"`
	Source   string    `json:"source,omitempty" yaml:"source,omitempty"`
	Patterns []Pattern `json:"patterns" yaml:"patterns"`
}

// Response is the input to the matcher. FaviconHash may be supplied by the
// caller (computed from Favicon); both are optional.
type Response struct {
	URL         string              `json:"url,omitempty"`
	Status      int                 `json:"status,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Body        []byte              `json:"body,omitempty"`
	Cookies     map[string]string   `json:"cookies,omitempty"`
	Favicon     []byte              `json:"favicon,omitempty"`
	FaviconHash string              `json:"favicon_hash,omitempty"`
}

// Tech is one detected technology. It is intentionally not an asset record;
// the host decides whether/how to persist it.
type Tech struct {
	Product    string `json:"product"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Source     string `json:"source,omitempty"`
	Confidence int    `json:"confidence"`
}
