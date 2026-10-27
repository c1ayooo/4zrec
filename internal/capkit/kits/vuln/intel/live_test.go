//go:build live

// Package vulnintelkit — live source verification.
//
// The unit tests feed canned bodies, which proves the parsers but says nothing
// about whether a page still has the shape a parser expects. Four of the nine
// sources are HTML scrapers, so a redesign upstream breaks them silently.
//
// Run:
//
//	go test -tags live -run TestLiveSources -v ./kits/vulnintelkit/
//
// Each source is reported independently. This is a diagnostic, not a CI gate:
// a source being down says nothing about the rest of the build, so the verdict
// is the table below rather than the exit status.
package intel

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
)

// liveRow is one source's verdict.
type liveRow struct {
	source   string
	items    int
	badKey   int
	badTitle int
	badSev   int
	err      error
}

// TestLiveSources fetches a small page from every source using the real
// httpx.Fetcher — the same transport a host uses, redirects and body limits
// included.
func TestLiveSources(t *testing.T) {
	fetcher := httpx.NewFetcher(gates.NewLimiter(), nil)
	fetcher.MaxBodyBytes = 8 << 20
	kit := New(core.Deps{Fetcher: fetcher})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := make([]liveRow, 0, len(kit.sources))
	for _, s := range kit.sources {
		items, err := s.Fetch(ctx, 10)
		r := liveRow{source: s.Info().Name, items: len(items), err: err}
		for _, it := range items {
			if it.UniqueKey == "" {
				r.badKey++
			}
			if it.Title == "" {
				r.badTitle++
			}
			if NormalizeSeverity(it.Severity) == SeverityUnknown {
				r.badSev++
			}
		}
		rows = append(rows, r)
		reportRow(os.Stdout, r)
	}

	usable, degraded, unusable := 0, 0, 0
	for _, r := range rows {
		switch {
		case r.err != nil || r.items == 0:
			unusable++
		case r.badKey > 0 || r.badTitle > 0:
			degraded++
		default:
			usable++
		}
	}
	fmt.Fprintf(os.Stdout, "\nsummary: %d usable, %d degraded, %d unusable (of %d sources)\n",
		usable, degraded, unusable, len(rows))
}

func reportRow(w *os.File, r liveRow) {
	switch {
	case r.err != nil:
		fmt.Fprintf(w, "%-14s ERROR    %v\n", r.source, r.err)
		return
	case r.items == 0:
		fmt.Fprintf(w, "%-14s EMPTY    解析到 0 条\n", r.source)
		return
	}
	verdict := "OK"
	if r.badKey > 0 || r.badTitle > 0 {
		verdict = "DEGRADED"
	}
	fmt.Fprintf(w, "%-14s %-8s %d 条", r.source, verdict, r.items)
	if r.badKey > 0 {
		fmt.Fprintf(w, " | 无 unique_key %d", r.badKey)
	}
	if r.badTitle > 0 {
		fmt.Fprintf(w, " | 无标题 %d", r.badTitle)
	}
	if r.badSev > 0 {
		fmt.Fprintf(w, " | 无严重度 %d", r.badSev)
	}
	fmt.Fprintln(w)
}
