package core

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// TargetKind is the shape of a target.
type TargetKind string

const (
	TargetURL    TargetKind = "url"
	TargetHost   TargetKind = "host"
	TargetDomain TargetKind = "domain"
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
)

// Target is a normalized, scope-checkable target. Every tool declares how to
// extract its targets; the runtime validates them before the kit runs.
type Target struct {
	ProjectID int64      `json:"project_id,omitempty"`
	Kind      TargetKind `json:"kind"`
	URL       string     `json:"url,omitempty"`
	Host      string     `json:"host,omitempty"`
	Port      int        `json:"port,omitempty"`
	IP        string     `json:"ip,omitempty"`
	CIDR      string     `json:"cidr,omitempty"`
}

// Key is the rate-limit / dedupe key. Hostnames and IPs are kept distinct.
func (t Target) Key() string {
	switch {
	case t.Host != "":
		return strings.ToLower(t.Host)
	case t.IP != "":
		return t.IP
	case t.CIDR != "":
		return t.CIDR
	case t.URL != "":
		if u, err := url.Parse(t.URL); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return "global"
}

// TargetFromURL normalizes an http(s) URL.
func TargetFromURL(projectID int64, raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return Target{}, fmt.Errorf("invalid http(s) URL: %q", raw)
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	return Target{
		ProjectID: projectID, Kind: TargetURL, URL: raw,
		Host: strings.ToLower(u.Hostname()), Port: port,
	}, nil
}

// TargetFromString normalizes a URL, IP, CIDR or hostname.
func TargetFromString(projectID int64, raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "://") {
		return TargetFromURL(projectID, raw)
	}
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		return Target{ProjectID: projectID, Kind: TargetCIDR, CIDR: ipnet.String()}, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return Target{ProjectID: projectID, Kind: TargetIP, IP: ip.String()}, nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		p, _ := strconv.Atoi(port)
		return Target{ProjectID: projectID, Kind: TargetHost, Host: strings.ToLower(host), Port: p}, nil
	}
	if strings.Contains(raw, "/") || strings.ContainsAny(raw, " \t") {
		return Target{}, fmt.Errorf("invalid target: %q", raw)
	}
	return Target{ProjectID: projectID, Kind: TargetDomain, Host: strings.ToLower(raw)}, nil
}

// TargetsFromStrings normalizes a slice; any invalid target fails the whole set.
func TargetsFromStrings(projectID int64, raws []string) ([]Target, error) {
	out := make([]Target, 0, len(raws))
	for _, raw := range raws {
		t, err := TargetFromString(projectID, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
