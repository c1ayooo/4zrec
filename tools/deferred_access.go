package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// NewSearchExtraTools builds the always-loaded discovery tool. deferred is the set
// of tool names whose schemas are withheld; the tool searches those names in reg
// and returns each match's name + description + params schema.
func NewSearchExtraTools(reg *Registry, deferred []string) CoreTool {
	deferredSet := make(map[string]bool, len(deferred))
	for _, n := range deferred {
		deferredSet[n] = true
	}
	ordered := append([]string(nil), deferred...)
	sort.Strings(ordered)
	return Build(Spec{
		Name: SearchExtraToolsName,
		Description: "Discover deferred tools (not in your tool list) and get their schemas, then invoke via " +
			ExecuteExtraToolName + ". Query forms: \"select:Name\" exact, \"select:A,B\" multiple, or free keywords to match name/description.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "\"select:<name>\" exact (comma-separated for multiple), or keywords.",
				},
			},
			"required": []any{"query"},
		},
		ReadOnly: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, Context) Decision {
			return Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *ToolContext) (Result, error) {
			var args struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(in, &args)
			q := strings.TrimSpace(args.Query)
			if q == "" {
				return Errorf("Error: query is required"), nil
			}
			var matches []CoreTool
			seen := map[string]bool{}
			addByFullName := func(name string) {
				if seen[name] || !deferredSet[name] {
					return
				}
				if t, ok := reg.Get(name); ok {
					seen[name] = true
					matches = append(matches, t)
				}
			}
			// addByQuery resolves one query token: exact full-name first, then
			// case-insensitive suffix match against each deferred tool name so that
			// short MCP tool names like "list_projects" also find
			// "mcp__4zrecon__list_projects".
			addByQuery := func(token string) {
				token = strings.TrimSpace(token)
				if token == "" {
					return
				}
				// 1. exact match
				addByFullName(token)
				if seen[token] {
					return
				}
				// 2. suffix / substring match (case-insensitive) for short names
				lower := strings.ToLower(token)
				for _, name := range ordered {
					lname := strings.ToLower(name)
					// match if full name equals, ends with __token, or contains token
					if lname == lower ||
						strings.HasSuffix(lname, "__"+lower) ||
						strings.Contains(lname, lower) {
						addByFullName(name)
					}
				}
			}
			if strings.HasPrefix(q, "select:") {
				for _, part := range strings.Split(strings.TrimPrefix(q, "select:"), ",") {
					addByQuery(part)
				}
			} else {
				// Multi-token keyword search: every space-separated token must appear
				// in the canonicalised haystack (__ replaced by space for MCP tool names).
				tokens := strings.Fields(strings.ToLower(q))
				for _, name := range ordered {
					t, ok := reg.Get(name)
					if !ok {
						continue
					}
					// canonicalise __ → space so "4zrecon list_projects" finds
					// "mcp__4zrecon__list_projects".
					haystack := strings.ReplaceAll(
						strings.ToLower(t.Name()+" "+t.Description()), "__", " ")
					allMatch := true
					for _, tok := range tokens {
						if !strings.Contains(haystack, tok) {
							allMatch = false
							break
						}
					}
					if allMatch {
						addByFullName(name)
					}
				}
			}
			if len(matches) == 0 {
				return Text("No matching deferred tools for query: " + q), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Found %d deferred tool(s). Invoke with %s({\"tool_name\":\"<name>\",\"params\":{...}}):\n",
				len(matches), ExecuteExtraToolName)
			for _, t := range matches {
				schemaJSON, _ := json.Marshal(t.InputSchema())
				fmt.Fprintf(&b, "\n## %s\n%s\nparams schema: %s\n", t.Name(), t.Description(), string(schemaJSON))
			}
			return Text(b.String()), nil
		},
	})
}

// NewExecuteExtraTool builds the always-loaded invoker for deferred tools. It runs
// the named tool from reg, but only if it is currently in the unlock set. Schema is
// validated before the call. unlock may be nil (then every registry tool is
// callable — no gating).
func NewExecuteExtraTool(reg *Registry, unlock *UnlockSet) CoreTool {
	return Build(Spec{
		Name: ExecuteExtraToolName,
		Description: "Invoke a deferred tool discovered via " + SearchExtraToolsName +
			". tool_name is the deferred tool's exact name; params must match its schema.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tool_name": map[string]any{
					"type":        "string",
					"description": "Exact name of the deferred tool (from " + SearchExtraToolsName + " / <available-deferred-tools>).",
				},
				"params": map[string]any{
					"type":        "object",
					"description": "Parameters for the tool, matching its schema.",
				},
			},
			"required": []any{"tool_name"},
		},
		Permissions: func(context.Context, json.RawMessage, Context) Decision {
			return Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *ToolContext) (Result, error) {
			var args struct {
				ToolName string          `json:"tool_name"`
				Params   json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return Errorf("Error: " + err.Error()), nil
			}
			if args.ToolName == "" {
				return Errorf("Error: tool_name is required"), nil
			}
			t, ok := reg.Get(args.ToolName)
			if !ok {
				return Errorf("Error: unknown tool " + args.ToolName), nil
			}
			if unlock != nil && !unlock.Has(args.ToolName) {
				return Errorf("Error: tool " + args.ToolName +
					" is not unlocked in this session — load the skill that provides it first."), nil
			}
			params := args.Params
			if len(params) == 0 {
				params = json.RawMessage("{}")
			}
			if err := ValidateInput(t.InputSchema(), params); err != nil {
				return Errorf("Error: invalid params for " + args.ToolName + ": " + err.Error()), nil
			}
			return t.Call(ctx, params, tc)
		},
	})
}
