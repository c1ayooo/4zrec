// Deprecated: 迁移到 kits/postex/shell/plan，本包仅作兼容，M3 后移除。
// shellkit 子包路径的过渡 shim：只做类型别名与函数变量转发。
package plan

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/plan"

type (
	CleanupSink    = plan.CleanupSink
	DeliveryPlan   = plan.DeliveryPlan
	DeliveryResult = plan.DeliveryResult
	DeliverySink   = plan.DeliverySink
	Payload        = plan.Payload
	Verifier       = plan.Verifier
	VerifyResult   = plan.VerifyResult
)
