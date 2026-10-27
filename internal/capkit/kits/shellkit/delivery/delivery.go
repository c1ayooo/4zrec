// Deprecated: 迁移到 kits/postex/shell/delivery，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package delivery

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/delivery"

type (
	Manager     = delivery.Manager
	MemoryStore = delivery.MemoryStore
	Record      = delivery.Record
	State       = delivery.State
	Store       = delivery.Store
)

const (
	Cleaned    = delivery.Cleaned
	Delivered  = delivery.Delivered
	Failed     = delivery.Failed
	Pending    = delivery.Pending
	Registered = delivery.Registered
	Verified   = delivery.Verified
)

var (
	ErrNotFound        = delivery.ErrNotFound
	CanTransition      = delivery.CanTransition
	NewManager         = delivery.NewManager
	NewMemoryStore     = delivery.NewMemoryStore
	ValidateTransition = delivery.ValidateTransition
)
