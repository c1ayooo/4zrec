// Package noa is the ARTEX port of the norma noa compaction-takeover
// subsystem (norma v0.4.3 noaadapter + the pure noa engine it wraps).
//
// The package has two layers:
//
//   - The pure engine (copied from norma's noa package, stdlib-only): a
//     model-driven context-compression core. The model writes the summaries;
//     noa decides WHEN to compress, WHICH range, tracks state, applies the
//     decision, and prunes. It never calls a model.
//
//   - The adapter (ported from norma's noaadapter): projects acllm.Message
//     into the engine's flat representation and back, persists state and
//     archives, and exposes the Compress tool. Where norma's adapter wired
//     into agentcore via harness.Compactor/harness.ContextView, this port
//     implements the askernel seam: askernel.NoaTakeover (ExtraTools +
//     SystemPromptSegments) plus askernel.NoaView, whose View replaces
//     acllm.MessagesForAPI as the request projection — exactly the role
//     norma's ContextView takeover played against llm.MessagesForAPI.
//
// The entry point is Enable, mirroring norma noaadapter.Enable's all-or-nothing
// wiring: it fills askernel.Options.Noa with the takeover in one call. NewTakeover
// builds the takeover alone.
package noa
