package agent

import (
	"testing"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
)

func TestWorkerSessionIDIsStablePerIntent(t *testing.T) {
	if got := WorkerSessionID(12, 34); got != "exp12-worker-i34" {
		t.Fatalf("session id = %q, want exp12-worker-i34", got)
	}
}

func TestWorkerChatMarkerOnlyMatchesItsNormalUserTurn(t *testing.T) {
	requestID := "worker-message-123"
	messages := []acllm.Message{
		{Role: acllm.RoleAssistant, Content: []acllm.ContentBlock{acllm.TextBlock(workerChatMarker(requestID))}},
		acllm.UserText(workerChatMarker("worker-message-other") + "\nother"),
		acllm.UserText(workerChatMarker(requestID) + "\nnew intent"),
	}
	if !hasWorkerChatMessage(messages, requestID) {
		t.Fatal("expected the matching user turn to be detected")
	}
	if hasWorkerChatMessage(messages, "worker-message-missing") {
		t.Fatal("unrelated request id matched a Worker user turn")
	}
}
