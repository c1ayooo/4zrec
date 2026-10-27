// Package reconkit is an engine-neutral reconnaissance pipeline. It composes
// host-provided providers (subdomain/DNS/ports/HTTP) and emits assets through
// an AssetSink; it never writes the host's asset graph directly.
package recon

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type AssetKind string

const (
	AssetDomain    AssetKind = "domain"
	AssetSubdomain AssetKind = "subdomain"
	AssetIP        AssetKind = "ip"
	AssetService   AssetKind = "service"
	AssetURL       AssetKind = "url"
)

type Asset struct {
	Kind   AssetKind         `json:"kind"`
	Value  string            `json:"value"`
	Parent string            `json:"parent,omitempty"`
	Meta   map[string]string `json:"meta,omitempty"`
}

type Resolution struct {
	Name  string   `json:"name"`
	IPs   []string `json:"ips"`
	CNAME string   `json:"cname,omitempty"`
}

type Port struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

type HTTPInfo struct {
	URL          string   `json:"url"`
	Status       int      `json:"status"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

type SubdomainProvider interface {
	Subdomains(ctx context.Context, domain string) ([]string, error)
}
type Resolver interface {
	Resolve(ctx context.Context, names []string) ([]Resolution, error)
}
type PortScanner interface {
	Scan(ctx context.Context, host string, ports []int) ([]Port, error)
}
type HTTPProber interface {
	Probe(ctx context.Context, url string) (*HTTPInfo, error)
}
type AssetSink interface {
	Emit(ctx context.Context, asset Asset) error
}

type Options struct {
	Domains         []string `json:"domains"`
	Ports           []int    `json:"ports"`
	EnableSubdomain bool     `json:"enable_subdomain"`
	EnableResolve   bool     `json:"enable_resolve"`
	EnablePorts     bool     `json:"enable_ports"`
	EnableHTTP      bool     `json:"enable_http"`
	MaxHosts        int      `json:"max_hosts"`
}

type Stats struct {
	Domains    int      `json:"domains"`
	Subdomains int      `json:"subdomains"`
	Resolved   int      `json:"resolved"`
	Hosts      int      `json:"hosts"`
	Ports      int      `json:"ports"`
	HTTP       int      `json:"http"`
	Assets     int      `json:"assets"`
	Errors     []string `json:"errors,omitempty"`
}

type Pipeline struct {
	Subs     SubdomainProvider
	Resolver Resolver
	Ports    PortScanner
	HTTP     HTTPProber
	Sink     AssetSink
	Scope    core.ScopeChecker
	Limiter  core.Limiter
	Evidence core.EvidenceSink
}

func (p *Pipeline) Run(ctx context.Context, opts Options) (Stats, error) {
	var stats Stats
	if p.Scope == nil {
		return stats, fmt.Errorf("reconkit: scope checker is required")
	}
	if !opts.EnableSubdomain && !opts.EnableResolve && !opts.EnablePorts && !opts.EnableHTTP {
		return stats, fmt.Errorf("reconkit: enable at least one stage")
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 5000
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = []int{80, 443, 8080, 8443}
	}

	emit := func(a Asset) {
		stats.Assets++
		if p.Sink != nil {
			if err := p.Sink.Emit(ctx, a); err != nil {
				stats.Errors = append(stats.Errors, "sink "+a.Value+": "+err.Error())
			}
		}
	}
	scope := func(t core.Target) bool {
		if err := p.Scope.Check(ctx, t); err != nil {
			stats.Errors = append(stats.Errors, "scope "+t.Key()+": "+err.Error())
			return false
		}
		return true
	}
	acquire := func(key string) func() {
		if p.Limiter == nil {
			return func() {}
		}
		release, err := p.Limiter.Acquire(ctx, key, core.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4})
		if err != nil {
			stats.Errors = append(stats.Errors, "limit "+key+": "+err.Error())
			return func() {}
		}
		return release
	}

	hosts := map[string]bool{}
	for _, domain := range dedupe(opts.Domains) {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		stats.Domains++
		dTarget := core.Target{Kind: core.TargetDomain, Host: domain}
		if !scope(dTarget) {
			continue
		}
		emit(Asset{Kind: AssetDomain, Value: domain})

		var names []string
		if opts.EnableSubdomain && p.Subs != nil {
			release := acquire(domain)
			subs, err := p.Subs.Subdomains(ctx, domain)
			release()
			if err != nil {
				stats.Errors = append(stats.Errors, "subdomain "+domain+": "+err.Error())
			}
			for _, sub := range dedupe(subs) {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if sub == "" {
					continue
				}
				if !scope(core.Target{Kind: core.TargetDomain, Host: sub}) {
					continue
				}
				stats.Subdomains++
				emit(Asset{Kind: AssetSubdomain, Value: sub, Parent: domain})
				names = append(names, sub)
				hosts[sub] = true
			}
		}
		names = append(names, domain)
		hosts[domain] = true
		if len(hosts) > opts.MaxHosts {
			stats.Errors = append(stats.Errors, fmt.Sprintf("max hosts %d exceeded", opts.MaxHosts))
			break
		}

		if opts.EnableResolve && p.Resolver != nil {
			release := acquire(domain)
			resolutions, err := p.Resolver.Resolve(ctx, dedupe(names))
			release()
			if err != nil {
				stats.Errors = append(stats.Errors, "resolve "+domain+": "+err.Error())
			}
			for _, r := range resolutions {
				stats.Resolved++
				for _, ip := range dedupe(r.IPs) {
					if net.ParseIP(ip) == nil {
						continue
					}
					if !scope(core.Target{Kind: core.TargetIP, IP: ip}) {
						continue
					}
					hosts[ip] = true
					emit(Asset{Kind: AssetIP, Value: ip, Parent: r.Name, Meta: map[string]string{"cname": r.CNAME}})
				}
			}
		}
	}

	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}
	if len(hostList) > opts.MaxHosts {
		hostList = hostList[:opts.MaxHosts]
	}
	stats.Hosts = len(hostList)

	if opts.EnablePorts && p.Ports != nil {
		for _, host := range hostList {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			t := targetForHost(host)
			if !scope(t) {
				continue
			}
			release := acquire(host)
			list, err := p.Ports.Scan(ctx, host, ports)
			release()
			if err != nil {
				stats.Errors = append(stats.Errors, "ports "+host+": "+err.Error())
				continue
			}
			for _, pt := range list {
				stats.Ports++
				emit(Asset{Kind: AssetService, Value: net.JoinHostPort(host, strconv.Itoa(pt.Port)), Parent: host,
					Meta: map[string]string{"port": strconv.Itoa(pt.Port), "service": pt.Service}})
				if opts.EnableHTTP && p.HTTP != nil && isHTTPPort(pt.Port, pt.Service) {
					probeHTTP(ctx, p, &stats, host, pt.Port, emit, scope, acquire)
				}
			}
		}
	} else if opts.EnableHTTP && p.HTTP != nil {
		for _, host := range hostList {
			probeHTTP(ctx, p, &stats, host, 0, emit, scope, acquire)
		}
	}

	if p.Evidence != nil {
		_, _ = p.Evidence.Record(ctx, core.Evidence{
			Kind: "recon", Title: "recon pipeline", CreatedAt: time.Now(),
			Metadata: map[string]string{
				"domains": fmt.Sprint(stats.Domains), "subdomains": fmt.Sprint(stats.Subdomains),
				"hosts": fmt.Sprint(stats.Hosts), "ports": fmt.Sprint(stats.Ports), "http": fmt.Sprint(stats.HTTP),
			},
		})
	}
	return stats, nil
}

func probeHTTP(ctx context.Context, p *Pipeline, stats *Stats, host string, port int, emit func(Asset), scope func(core.Target) bool, acquire func(string) func()) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := scheme + "://" + host
	if port > 0 && port != 80 && port != 443 {
		url = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	}
	if !scope(targetForHost(host)) {
		return
	}
	release := acquire(host)
	info, err := p.HTTP.Probe(ctx, url)
	release()
	if err != nil {
		stats.Errors = append(stats.Errors, "http "+url+": "+err.Error())
		return
	}
	stats.HTTP++
	meta := map[string]string{"status": strconv.Itoa(info.Status)}
	if info.Title != "" {
		meta["title"] = info.Title
	}
	if info.Server != "" {
		meta["server"] = info.Server
	}
	if len(info.Technologies) > 0 {
		meta["technologies"] = strings.Join(info.Technologies, ",")
	}
	emit(Asset{Kind: AssetURL, Value: url, Parent: host, Meta: meta})
}

func targetForHost(host string) core.Target {
	if net.ParseIP(host) != nil {
		return core.Target{Kind: core.TargetIP, IP: host}
	}
	return core.Target{Kind: core.TargetDomain, Host: host}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func isHTTPPort(port int, service string) bool {
	switch port {
	case 80, 443, 8000, 8080, 8081, 8443, 8888, 9000:
		return true
	}
	service = strings.ToLower(service)
	return strings.Contains(service, "http")
}
