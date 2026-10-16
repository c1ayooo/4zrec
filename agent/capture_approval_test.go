package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zrec/askernel"
	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/guard"
	"github.com/c1ayooo/4zrec/intercept"
	actool "github.com/c1ayooo/4zrec/tools"
	"github.com/cloudwego/eino/schema"
)

// The approval-flow gold standard, run through the FULL kernel: model tool call
// → guard hook (intercept review) → execution (or denial) → result. No real
// model or command is used; the probe tool only returns a fixed string.
func TestCaptureApprovalLifecycle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	priorConfig := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools); _ = ic.SetJudgeConfig(priorConfig) })
	if err := ic.SetEnabledTools([]string{"ApprovalAuditProbe"}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true, AskTimeoutSeconds: 1, AskTimeoutAction: "allow"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, action, status, execution string
		manual, approve, toolError      bool
	}{
		{"model_fallback", "invalid", "allowed", "succeeded", false, false, false},
		{"model_allow", "allow", "allowed", "succeeded", false, false, false},
		{"model_deny", "deny", "denied", "not_executed", false, false, false},
		{"human_allow_tool_error", "ask", "allowed", "failed", true, true, true},
		{"human_deny", "ask", "denied", "not_executed", true, false, false},
		{"timeout_allow", "ask", "timeout", "succeeded", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ic.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
				return intercept.Decision{Action: tc.action, Message: "probe review", ProfileID: 7}, nil
			})
			g := guard.NewWithInterceptor(ic)
			taskID := "approval-lifecycle-" + tc.name
			t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID) })
			ctx := intercept.WithTaskContext(t.Context(), taskID, "test-agent", func(a db.Activity) {
				if a.Kind != "intercept_request" || !tc.manual {
					return
				}
				var detail struct {
					ID int64 `json:"pending_id"`
				}
				if err := json.Unmarshal([]byte(a.Detail), &detail); err != nil {
					t.Error(err)
					return
				}
				if err := ic.Decide(detail.ID, tc.approve); err != nil {
					t.Error(err)
				}
			})
			// Turn 1 asks for the probe tool; turn 2 answers with text. The
			// intercept "ask" verdict blocks inside the PreToolUse hook until the
			// manual decision above lands (or the ask timeout fires).
			m := &fakeChatModel{}
			m.script(
				schema.AssistantMessage("", []schema.ToolCall{
					{ID: "probe-call", Function: schema.FunctionCall{Name: "ApprovalAuditProbe", Arguments: `{}`}},
				}),
				schema.AssistantMessage("done", nil),
			)
			executions := 0
			probe := actool.Build(actool.Spec{Name: "ApprovalAuditProbe", Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
					executions++
					if tc.toolError {
						return actool.Errorf("probe failed"), nil
					}
					return actool.Text("probe succeeded"), nil
				},
			})
			_, _, err := captureRun(ctx, askernel.Options{Model: m, Tools: []actool.CoreTool{probe}, Hooks: g.Hooks(),
				PermissionMode: actool.ModeBypass, WorkingDir: t.TempDir(), MaxTurns: 2}, "record this review", nil)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := d.ListTaskIntercepts(taskID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%d err=%v", len(rows), err)
			}
			detail, err := d.GetInterceptDetail(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			a := detail.Audit
			initialAction := tc.action
			if tc.action == "invalid" {
				initialAction = "allow"
			}
			wantUserMessage := "record this review"
			if initialAction == "allow" {
				// Routine automatic allows keep decision/execution metadata but
				// intentionally omit the bulky replay context from the audit row.
				wantUserMessage = ""
			}
			if detail.Status != tc.status || detail.DecisionSource != "model" || a == nil || a.ExecutionStatus != tc.execution || a.ToolUseID != "probe-call" || a.UserMessage != wantUserMessage || a.InitialAction != initialAction || a.ModelFallback != (tc.action == "invalid") || a.ProfileID != 7 {
				t.Fatalf("unexpected review: row=%+v audit=%+v", detail.InterceptApprovalRow, a)
			}
			if initialAction == "allow" && (len(a.Context) != 0 || a.UserTruncated || a.ContextTruncated) {
				t.Fatalf("routine allow retained replay context: %+v", a)
			}
			wantCalls := 1
			if tc.execution == "not_executed" {
				wantCalls = 0
			}
			if executions != wantCalls {
				t.Fatalf("tool ran %d times, wanted %d", executions, wantCalls)
			}
		})
	}
}
