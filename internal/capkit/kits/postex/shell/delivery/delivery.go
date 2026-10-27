// Package delivery contains the pure delivery state machine. It performs no
// I/O; the host supplies a plan.DeliverySink and persists records.
package delivery

import (
	"fmt"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/plan"
)

type State string

const (
	Pending    State = "pending"
	Delivered  State = "delivered"
	Verified   State = "verified"
	Registered State = "registered"
	Cleaned    State = "cleaned"
	Failed     State = "failed"
)

// CanTransition reports whether the state machine allows from -> to.
func CanTransition(from, to State) bool {
	switch from {
	case Pending:
		return to == Delivered || to == Failed
	case Delivered:
		return to == Verified || to == Failed
	case Verified:
		return to == Registered || to == Failed
	case Registered:
		return to == Cleaned || to == Failed
	case Failed:
		return to == Pending // retry
	case Cleaned:
		return false
	default:
		return false
	}
}

func ValidateTransition(from, to State) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("invalid delivery transition %s -> %s", from, to)
	}
	return nil
}

// Record is a host-persisted delivery record. The host owns storage; this
// struct is only the shared shape.
type Record struct {
	ID        int64
	ProjectID int64
	TaskID    string
	State     State
	Plan      plan.DeliveryPlan
	Result    *plan.DeliveryResult
	Message   string

	// Host metadata (mapped by the host Store).
	PayloadPath      string
	UploadTranscript string
	UploadTrafficID  string
	VerifyOutput     string
	VerifyTrafficID  string
	Error            string
	CreatedBy        string
	Remark           string
	Variant          string
	ConnectionID     *int64
	CleanedAt        *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}
