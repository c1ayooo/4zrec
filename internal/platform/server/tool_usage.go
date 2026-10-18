package server

import (
	"context"
	"encoding/json"
	"log"
	"time"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
)

type toolUsageRecorder interface {
	InsertToolUsage(*db.ToolUsage) error
}

// meteredTool records one row immediately before a catalog tool is invoked. It
// embeds the resolved tool so schema overrides, defaults and permission behavior
// remain unchanged. For the three feature tools it also writes a richer
// feature_call_log row after the call so their pages can show an invocation
// history with inputs, result summary and duration.
type meteredTool struct {
	actool.CoreTool
	recorder        toolUsageRecorder
	featureRecorder featureCallRecorder
	feature         *featureToolSpec
	toolKey         string
	agentKey        string
	ri              agent.RunInfo
}

func meterTool(t actool.CoreTool, recorder toolUsageRecorder, toolKey, agentKey string, ri agent.RunInfo) actool.CoreTool {
	if recorder == nil {
		return t
	}
	m := &meteredTool{CoreTool: t, recorder: recorder, toolKey: toolKey, agentKey: agentKey, ri: ri}
	if fr, ok := recorder.(featureCallRecorder); ok {
		m.featureRecorder = fr
		m.feature = featureToolSpecFor(toolKey)
	}
	return m
}

func (m *meteredTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if err := m.recorder.InsertToolUsage(&db.ToolUsage{
		ToolKey:       m.toolKey,
		AgentKey:      m.agentKey,
		TaskID:        m.ri.TaskID,
		ExplorationID: m.ri.ExplorationID,
		IntentID:      m.ri.IntentID,
		SessionID:     m.ri.SessionID,
	}); err != nil {
		log.Printf("[toolusage] insert %s: %v", m.toolKey, err)
	}
	start := time.Now()
	res, err := m.CoreTool.Call(ctx, input, tc)
	if m.feature != nil {
		recordMeteredFeatureCall(m.featureRecorder, m.feature, m.agentKey, m.ri, input, res, err, time.Since(start))
	}
	return res, err
}
