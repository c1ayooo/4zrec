package delivery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/plan"
)

// Manager is the host-agnostic delivery state machine. It requires a Store and
// a host-provided DeliverySink; it ships no uploader/executor.
type Manager struct {
	Store       Store
	Sink        plan.DeliverySink
	Verifier    plan.Verifier
	CleanupSink plan.CleanupSink
}

func NewManager(store Store, sink plan.DeliverySink) *Manager {
	return &Manager{Store: store, Sink: sink}
}

// Deliver creates a pending record, invokes the host sink, and advances to
// delivered/failed.
func (m *Manager) Deliver(ctx context.Context, rec *Record) (*Record, error) {
	if m.Store == nil || m.Sink == nil {
		return nil, errors.New("delivery: store and sink are required")
	}
	if rec == nil {
		return nil, errors.New("delivery: record is nil")
	}
	rec.State = Pending
	if _, err := m.Store.Create(ctx, rec); err != nil {
		return nil, err
	}
	res, err := m.Sink.Deliver(ctx, rec.Plan)
	if err != nil {
		rec.State = Failed
		rec.Error = err.Error()
		rec.Message = err.Error()
		_ = m.Store.Update(ctx, rec)
		return rec, err
	}
	if res == nil {
		rec.State = Failed
		rec.Error = "delivery sink returned nil result"
		rec.Message = rec.Error
		_ = m.Store.Update(ctx, rec)
		return rec, errors.New(rec.Error)
	}
	if rec.Result != nil && rec.Result.DroppedURL != "" && res.DroppedURL == "" {
		res.DroppedURL = rec.Result.DroppedURL
	}
	rec.Result = res
	rec.PayloadPath = res.PayloadPath
	rec.UploadTrafficID = res.EvidenceID
	rec.UploadTranscript = res.UploadTranscript
	if !res.OK {
		rec.State = Failed
		rec.Error = res.Message
		rec.Message = res.Message
		_ = m.Store.Update(ctx, rec)
		return rec, fmt.Errorf("delivery failed: %s", res.Message)
	}
	rec.State = Delivered
	if err := m.Store.Update(ctx, rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// Verify runs the host verifier and advances delivered -> verified.
func (m *Manager) Verify(ctx context.Context, id int64) (*Record, error) {
	rec, err := m.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := ValidateTransition(rec.State, Verified); err != nil {
		return rec, err
	}
	if m.Verifier == nil {
		return rec, errors.New("delivery: verifier is not configured")
	}
	if rec.Result == nil {
		return rec, errors.New("delivery: no delivery result to verify")
	}
	vr, err := m.Verifier.Verify(ctx, rec.Plan, *rec.Result)
	if err != nil {
		rec.State = Failed
		rec.Error = err.Error()
		rec.Message = err.Error()
		_ = m.Store.Update(ctx, rec)
		return rec, err
	}
	if vr == nil {
		rec.State = Failed
		rec.Error = "verifier returned nil result"
		rec.Message = rec.Error
		_ = m.Store.Update(ctx, rec)
		return rec, errors.New(rec.Error)
	}
	rec.VerifyOutput = vr.Output
	rec.VerifyTrafficID = vr.TrafficID
	if !vr.OK {
		_ = m.Store.Update(ctx, rec)
		return rec, fmt.Errorf("delivery: verification failed: %s", vr.Output)
	}
	rec.State = Verified
	rec.Message = vr.Output
	if err := m.Store.Update(ctx, rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// MarkRegistered advances verified -> registered (the host has created a
// session after verification).
func (m *Manager) MarkRegistered(ctx context.Context, id int64) (*Record, error) {
	rec, err := m.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := ValidateTransition(rec.State, Registered); err != nil {
		return rec, err
	}
	rec.State = Registered
	if err := m.Store.Update(ctx, rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// Cleanup invokes the host cleanup sink and advances registered -> cleaned.
func (m *Manager) Cleanup(ctx context.Context, id int64) (*Record, error) {
	rec, err := m.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := ValidateTransition(rec.State, Cleaned); err != nil {
		return rec, err
	}
	if m.CleanupSink != nil {
		res := plan.DeliveryResult{}
		if rec.Result != nil {
			res = *rec.Result
		}
		out, err := m.CleanupSink.Cleanup(ctx, rec.Plan, res)
		if err != nil {
			return rec, err
		}
		rec.VerifyOutput = out
	}
	rec.State = Cleaned
	now := time.Now()
	rec.CleanedAt = &now
	if err := m.Store.Update(ctx, rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// Fail marks a record failed.
func (m *Manager) Fail(ctx context.Context, id int64, msg string) (*Record, error) {
	rec, err := m.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := ValidateTransition(rec.State, Failed); err != nil {
		return rec, err
	}
	rec.State = Failed
	rec.Message = msg
	rec.Error = msg
	if err := m.Store.Update(ctx, rec); err != nil {
		return rec, err
	}
	return rec, nil
}
