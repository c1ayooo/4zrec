package delivery

import (
	"context"
	"errors"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/plan"
)

func capTargetForTest() core.Target {
	return core.Target{Kind: core.TargetURL, URL: "http://target/"}
}

type fakeSink struct {
	err error
}

func (f *fakeSink) Deliver(context.Context, plan.DeliveryPlan) (*plan.DeliveryResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &plan.DeliveryResult{OK: true, DroppedURL: "http://target/shell.php", EvidenceID: "ev-1"}, nil
}

type fakeVerifier struct {
	ok  bool
	out string
	err error
}

func (f *fakeVerifier) Verify(context.Context, plan.DeliveryPlan, plan.DeliveryResult) (*plan.VerifyResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &plan.VerifyResult{OK: f.ok, Output: f.out}, nil
}

type fakeCleanup struct{ called bool }

func (f *fakeCleanup) Cleanup(context.Context, plan.DeliveryPlan, plan.DeliveryResult) (string, error) {
	f.called = true
	return "cleaned", nil
}

func testRecord() *Record {
	return &Record{
		ProjectID: 7,
		State:     Pending,
		Plan: plan.DeliveryPlan{
			Target:    capTargetForTest(),
			UploadURL: "http://target/upload",
			Method:    "post",
			Payload:   plan.Payload{Filename: "w.php", Content: []byte("<?php ?>"), ShellType: "php", Protocol: "plain", Password: "p"},
		},
	}
}

func TestManagerFlow(t *testing.T) {
	store := NewMemoryStore()
	sink := &fakeSink{}
	verifier := &fakeVerifier{ok: true, out: "marker found"}
	cleanup := &fakeCleanup{}
	m := NewManager(store, sink)
	m.Verifier = verifier
	m.CleanupSink = cleanup
	ctx := context.Background()

	rec, err := m.Deliver(ctx, testRecord())
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != Delivered || rec.Result == nil || rec.Result.DroppedURL == "" {
		t.Fatalf("record = %+v", rec)
	}
	rec, err = m.Verify(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != Verified {
		t.Fatalf("state = %s", rec.State)
	}
	rec, err = m.MarkRegistered(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != Registered {
		t.Fatalf("state = %s", rec.State)
	}
	rec, err = m.Cleanup(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != Cleaned || !cleanup.called {
		t.Fatalf("state = %s cleanup=%v", rec.State, cleanup.called)
	}
}

func TestManagerDeliverFailure(t *testing.T) {
	store := NewMemoryStore()
	m := NewManager(store, &fakeSink{err: errors.New("upload blocked")})
	rec, err := m.Deliver(context.Background(), testRecord())
	if err == nil || rec.State != Failed {
		t.Fatalf("rec=%+v err=%v", rec, err)
	}
	if rec.Message == "" {
		t.Fatal("failure message empty")
	}
}

func TestManagerVerifyFailureStaysDelivered(t *testing.T) {
	store := NewMemoryStore()
	m := NewManager(store, &fakeSink{})
	m.Verifier = &fakeVerifier{ok: false, out: "marker missing"}
	rec, err := m.Deliver(context.Background(), testRecord())
	if err != nil {
		t.Fatal(err)
	}
	rec, err = m.Verify(context.Background(), rec.ID)
	if err == nil || rec.State != Delivered {
		t.Fatalf("rec=%+v err=%v", rec, err)
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	rec := testRecord()
	id, err := store.Create(context.Background(), rec)
	if err != nil || id == 0 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	got, err := store.Get(context.Background(), id)
	if err != nil || got.State != Pending || got.ProjectID != 7 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	// Mutating the returned copy must not mutate the store.
	got.Plan.Payload.Content[0] = 'x'
	again, _ := store.Get(context.Background(), id)
	if again.Plan.Payload.Content[0] == 'x' {
		t.Fatal("store returned an aliased payload")
	}
	list, err := store.List(context.Background(), 7, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}
